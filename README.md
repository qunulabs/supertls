# supertls

One TLS session carried inside another, for programs that must keep a strict
end-to-end TLS session working on networks that terminate and re-sign TLS for
inspection.

The client dials its server directly. When that fails and the peer is not provably
the server it meant to reach, it opens an ordinary gRPC call to the same host over a
deliberately permissive outer TLS connection, and runs the unchanged strict session
inside that call as the bytes of a stream. A proxy that inspects the outer connection
sees only a pipe; the inner session, with the caller's own credentials, runs end to
end through it.

```go
import (
    "github.com/qunulabs/supertls"
    "github.com/qunulabs/supertls/server"
)
```

Dependencies: gRPC and protobuf (and what they require). Go 1.25+. Apache-2.0.

## What it owns, and what it does not

**supertls owns** the outer connection, the detection of a middlebox that breaks the
inner session, the cache of which mode each host needs, the adapter that makes a gRPC
stream look like a `net.Conn`, the tunnel service a server registers to accept inner
connections, and the limits that bound all of it.

**supertls owns none of** the inner TLS configuration, any certificate, any
authentication or authorisation decision, any RPC carried through it, or any retry
policy above a single dial. The caller supplies the inner credentials and decides who
may connect. supertls moves bytes and reports how the path behaved.

| Package | What it is |
|---|---|
| `supertls` | The client: `Dialer`, `Dial`, `Trust`, the probe, the mode cache. |
| `supertls/server` | The tunnel service, its limits, the inner and outer server options, the stop order. |
| `supertls/conn` | The `net.Conn` adapter over a frame stream, and a channel-fed `net.Listener`. |
| `supertls/tunnelpb` | Generated code for the `supertls.v1.TunnelService/Open` stream of `Frame`. |

## How detection behaves

A host is dialled directly first. Only when that dial fails does the library probe: a
maximally permissive TLS handshake (classical groups only, so a large hybrid hello
cannot itself trip the middlebox) whose purpose is to look at the certificate the peer
actually presents. The probe dials the way gRPC dials, through `HTTP_PROXY` and
`HTTPS_PROXY` with `CONNECT` when the environment says so.

| What the probe observes | Verdict | What `Dial` does |
|---|---|---|
| TCP, DNS or `CONNECT` failure, or the probe ran out of time | inconclusive | tunnel |
| TCP connected but even the permissive handshake failed | intercepted | tunnel |
| Handshake completed and the chain is recognised by the `Trust` | genuine | return the direct error, never tunnel |
| Handshake completed and the chain is not recognised | intercepted | tunnel |

A genuine peer is never tunnelled. The tunnel dials the same host through the same
network, so it would fail identically, and tunnelling would hide a real fault (an
expired server certificate, drifted SANs) behind a silent fallback.

When the tunnel is tried and fails, `Dial` returns a `*DialError`. Its `Direct` field
is always the original direct-path error, never the tunnel's, and `errors.Is` matches
both the direct and the tunnel error.

The mode is cached per host in the `Dialer`. A tunnel decision expires after one hour
(`WithTunnelModeTTL`), so a machine that leaves the intercepting network stops paying
for the tunnel; a direct decision never expires. A failed tunnel leaves the cache
unchanged. The first switch to the tunnel for a host writes one `Warn` log line, once
per host for the life of the `Dialer`; because two nested TLS layers defeat packet
capture, that line is the only local evidence the mode changed. `WithOnModeChange`
installs a hook that runs on every transition, including the first direct success. The
hook runs on the dialling goroutine and must not block.

**The cost of an unreachable host.** A host that cannot be reached at all is
inconclusive, so it is tunnelled, and the tunnel fails too. A dial then takes up to the
direct budget, plus the probe timeout, plus the tunnel budget to fail: 5s + 10s + 20s
by default. Tune them with `WithDirectDialBudget`, `WithProbeTimeout` and
`WithTunnelDialBudget`.

## Client

```go
d, err := supertls.NewDialer(supertls.TrustPool(pool), supertls.WithLogger(l))
if err != nil {
    return err
}

c, err := d.Dial(ctx, "licensing.example.com:443", credentials.NewTLS(cfg),
    grpc.WithUnaryInterceptor(myInterceptor))
if err != nil {
    return err
}
defer c.Close()

client := pb.NewMyServiceClient(c.ClientConn())
```

`Dial` returns once the connection is ready. `c.ClientConn()` is the connection to
make calls on; for a tunnel it is the inner connection, verified by your credentials.
`c.Mode()` says which path it took. `Close` is idempotent and closes the outer
connection of a tunnel too. A host may be `host` or `host:port`, without a scheme; no
port means 443, as it does to gRPC.

The credentials you pass are used unchanged on both paths. `NewDialer` refuses a zero
or invalid `Trust`, and `Dial` refuses nil credentials, gRPC's insecure and local
credentials, an empty host and a host containing `://`, all with `ErrInvalidOption`. It
cannot see TLS credentials built with
`InsecureSkipVerify`: those would leave no verification anywhere on a tunnelled
connection, and avoiding them is the caller's responsibility.

**Never pass `grpc.WithTransportCredentials` or `grpc.WithContextDialer` in `extra`.**
The library applies the inner credentials and the tunnel dialler last, so neither can
replace them, but passing them is a bug in the caller. A dialler in `extra` applies to
the direct path only. To change how the tunnel reaches the network, use
`WithOuterDialOptions`, and never put per-RPC credentials there: the outer connection
reports `PrivacyAndIntegrity` to gRPC while verifying nothing, so gRPC would hand a
token to whoever terminates it. Per-RPC credentials belong in `extra`, on the inner
connection.

## Server

```go
svc, err := server.New(server.WithListenerAddr(lis.Addr()))
if err != nil {
    return err
}

// The outer server listens on the real socket and carries the tunnel service.
outer := grpc.NewServer(append(myOpts, svc.OuterServerOptions()...)...)
pb.RegisterMyServiceServer(outer, impl)
svc.Register(outer)

// The inner server has no socket: it serves the tunnel listener.
inner := grpc.NewServer(append(myOpts, svc.InnerServerOptions()...)...)
pb.RegisterMyServiceServer(inner, impl) // the SAME services
go inner.Serve(svc.Listener())

go outer.Serve(lis)

// ... on shutdown:
svc.GracefulStop(inner, outer, 30*time.Second)
```

Build the credentials in `myOpts` for both servers from the same `tls.Config` value, so
the inner session is byte for byte the one a direct client would run. The outer server
must not require a client certificate: the client's outer connection presents none.
Verify client certificates on the inner session, where the identity lives.

Five rules, each of which fails silently when broken:

1. Register the tunnel service on the outer server only (`svc.Register`).
2. Give `InnerServerOptions` to the inner server only. They set `MaxConnectionIdle`,
   which would close direct clients of the outer server that are idle between calls.
3. Use the same `tls.Config` for both servers.
4. Stop the inner server first. `GracefulStop` does, and splits its budget between the
   two. Stopping the outer server first waits on tunnel handlers that wait on the inner
   server nobody asked to stop.
5. Register the same services on both servers. A handler cannot tell whether a call came
   through a tunnel.

## Trust

The `Trust` answers one question for the probe: is the peer at this address the server I
meant to reach? It does not decide whether the connection is trusted; that stays with
your inner credentials.

| Constructor | Recognises a peer whose chain... |
|---|---|
| `TrustPool(pool)` | leads to a root in `pool`. The hostname is ignored and validity is pinned to the latest `NotBefore` in the chain plus one second, so a genuine server with an expired leaf or drifted SANs is still genuine. |
| `TrustPoolWithHostname(pool)` | the same, and the leaf also covers the dialled host. |
| `TrustSystemRoots()` | leads to a root in the operating system store, and the leaf covers the dialled host. For a server on the public web PKI. |

A nil pool yields the invalid zero `Trust`, which `NewDialer` refuses.

**With `TrustSystemRoots`, a corporate inspection CA installed in the operating system
store makes interception look genuine.** The probe then sees a chain it recognises,
calls the peer genuine, and the client never tunnels. Prefer `TrustPool` with the
roots of your own server wherever you can. A long-expired public certificate can also
read as genuine under the pinned-time rule; the only effect of that is that no tunnel
is attempted.

## Flow control

Both nested connections have pinned HTTP/2 windows. The defaults are the values proven
in the transport this library was extracted from.

| Window | Client default | Constant |
|---|---|---|
| Outer stream | 1 MiB | `DefaultOuterStreamWindow` |
| Outer connection | 2 MiB | `DefaultOuterConnWindow` |
| Inner stream | 512 KiB | `DefaultInnerStreamWindow` |
| Inner connection | 1 MiB | `DefaultInnerConnWindow` |
| Outer read and write buffer | 64 KiB | `DefaultBufferSize` |

The smallest window gRPC honours is `MinWindow` (64 KiB). The invariant is **outer
stream window >= inner connection window**; `WithWindows` refuses a violation with
`ErrWindowInvariant`, and so does `server.WithWindows`.

The windows are pinned rather than left to gRPC's bandwidth-delay estimator because of
head-of-line blocking, not throughput. All inner traffic shares one outer stream, so a
small RPC can queue behind bulk bytes for roughly the outer window divided by the
bandwidth. At 1 MiB on a 1 Mbit/s link that is about eight seconds, inside a typical
30-second deadline. Left to auto-tune, the estimator grows the window toward 16 MiB and
the same arithmetic gives over two minutes. Setting any initial window turns the
estimator off, which is the point. Measured over a 60 ms round-trip shaped link, tunnel
throughput is within about 6% of a direct connection with the same pinned windows; the
test's shaper, not the windows, is the ceiling there.

Server windows (`server.WithWindows`) are unset by default, which leaves gRPC's
estimator on. When set, `OuterServerOptions` applies them to every connection of the
outer server, so they apply to direct clients too.

## Limits

The tunnel call is unauthenticated by construction, so what it exposes is resource, not
identity. `server.Limits` bounds it; start from `server.DefaultLimits()` and change what
you mean to change, since `server.WithLimits` replaces all of them.

| Limit | Default | What it bounds |
|---|---|---|
| `MaxConcurrent` | 1024 | Open tunnels in the process (about 134 KiB and 11 goroutines each). |
| `MaxPerAddress` | 256 | Open tunnels from one client address. |
| `OpenBurst` | 512 | Token bucket depth for opens per address. |
| `OpenRefillPerSecond` | 17 | Sustained opens per address. |
| `BucketSweep` | 5 min | How often idle full buckets are forgotten. |
| `AcceptTimeout` | 5 s | How long a handler waits for the inner server to accept. |
| `InnerHandshakeTimeout` | 20 s | A peer that opens a tunnel and never speaks. |
| `InnerMaxConnectionIdle` | 5 min | Reclaims a tunnel that handshakes and then issues nothing. |
| `MaxLifetime` | 4 h | Absolute backstop on one tunnel. |

There is deliberately no global open-rate limit: it cannot be sized from anything the
process knows, and one set too low turns a mass reconnect into an outage that prevents
its own recovery. A refused open is `ResourceExhausted`; a tunnel opened while the server
drains is `Unavailable`.

Client timing defaults: direct dial budget 5 s (`DefaultDirectDialBudget`), probe 10 s
(`DefaultProbeTimeout`), tunnel dial budget 20 s (`DefaultTunnelDialBudget`), tunnel
decision TTL 1 h (`DefaultTunnelModeTTL`). Reconnect backoff: inner 0.5 s base, 1.6x,
0.2 jitter, 15 s cap (`DefaultInnerBackoff()`, `WithInnerBackoff`); outer 1 s base, 1.6x,
0.2 jitter, 60 s cap (`DefaultOuterBackoff()`, `WithOuterBackoff`). Outer keepalive: a
ping every 30 s, stream or no stream, 20 s to answer (`DefaultOuterKeepalive()`,
`WithOuterKeepalive`). The defaults are functions returning a fresh copy, and each
`Dialer` keeps its own settings from construction, so nothing one caller changes reaches
another `Dialer`.

## Known gaps

- **A layer-7 proxy in front of the server needs streaming timeouts disabled.** One
  `Open` stream carries the whole tunnel, so a per-request or idle-stream timeout kills
  it. Envoy's default route timeout is 15 seconds. Envoy's `stream_idle_timeout` (5
  minutes by default) for an idle tunnel is untested.
- The real-proxy test (`make l7`) has passed in an adapted run but is still owed a run
  in its committed form on native Docker or CI.

## Running the tests

```
make test        # everything, including the slow tests
make test-race   # -short -race
make check       # vet, tests, cross-compile
make l7          # a real Envoy in front of the server
```

All default tests use loopback only. `make l7` needs a native Docker Engine on Linux (the
container uses host networking, which Docker Desktop cannot provide) and pulls
`envoyproxy/envoy:v1.32-latest`. It is not in CI.

See [SECURITY.md](SECURITY.md) for what the library does and does not verify,
[CHANGELOG.md](CHANGELOG.md) for releases, and
[docs/sentinel-migration.md](docs/sentinel-migration.md) for moving Sentinel's copies
onto this library.

## License

Apache-2.0. See [LICENSE](LICENSE).
