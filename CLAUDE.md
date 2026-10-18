# supertls - Claude Context

**Project**: `github.com/qunulabs/supertls`. An Apache-2.0 Go library that carries a
strict, caller-owned TLS session inside a permissive outer TLS connection, opened only
when the direct path fails and the peer is not provably the caller's own server. It is
an extraction of Sentinel DRM's transport, kept close to the original so Sentinel can
delete its three copies and import this.

Read [README.md](README.md) first for the public API and how a consumer wires it up.
This file is about the invariants: the reasons the code is shaped the way it is, and the
things that look like tidying opportunities but are not.

---

## Scope

**supertls owns** the outer connection, interception detection, the per-host mode cache,
the `net.Conn` adapter over a gRPC stream, the tunnel service and its limits, and the
inner/outer server option helpers and stop order.

**supertls owns none of** the inner TLS configuration, any certificate, authentication,
authorisation, any RPC carried, or any retry policy above one dial. The caller supplies
the inner credentials and the library never changes them.

---

## Layout

```
doc.go, options.go, windows.go      package doc, client options, flow-control windows
dial.go                             Dialer, Dial, Conn, the direct path, waitForReady
tunnel.go                           the tunnelled dial: outer connection, inner connection
probe.go, proxy.go, trust.go        the interception probe, the CONNECT dialler, Trust
permissive.go, record.go            outer credentials, the handshake-error recorder
mode.go, errors.go                  the per-host mode cache with TTL, DialError
conn/                               net.Conn over a frame stream, channel-fed Listener
server/                             tunnel service, limiter, Limits, server options, stop order
tunnelpb/, proto/                   generated code and the neutral tunnel.proto
internal/testpki/                   test certificates
*_test.go                           unit, integration, proxy-env, throughput, l7proxy tests
module_test.go                      guards: dependency allowlist, gRPC floor, Go directive, dashes
```

---

## Rules and traps

Each one is here because getting it wrong breaks the security argument or fails in
silence.

1. **Never weaken or modify the caller's inner credentials or `tls.Config`.** The library
   adds no transport option after the caller's, except through `extra`, which must never
   carry credentials or a dialler. The inner session being byte for byte the caller's own
   is the whole argument that the fallback is not a downgrade.
2. **`permissiveCreds.Info().ServerName` stays empty.** gRPC derives the channel's
   authority from it, and a value there would redirect the inner hostname check.
3. **The inner target is `passthrough:///host`.** A synthetic target disables SAN
   checking, and a resolver would be pointless since the dialler ignores the address.
4. **The outer connection never uses `credentials.NewTLS`.** Since gRPC 1.67 it enforces
   ALPN, which an inspecting proxy may not echo, and it cannot drop the hybrid key
   exchange group, whose large hello is a middlebox tripwire.
5. **The probe dials the way gRPC dials** (`http.ProxyFromEnvironment`, then `CONNECT`).
   On a network where a proxy is mandatory, a direct dial reports the opposite of the
   truth.
6. **`TrustPool` ignores the hostname and pins time to the latest `NotBefore` + 1s.** The
   question is "is this our server", not "is this certificate usable". A genuine server
   with an expired leaf must read as genuine, because genuine never tunnels and the
   tunnel would fail identically.
7. **Adapter (`conn`).** `Write` never re-checks closed after its final frame. `Read`
   pre-checks closed and the deadline. Writes go through the writer goroutine so a
   deadline can interrupt them. `frames` and `sends` are unbuffered. Deadlines are
   revivable. The frame cap is enforced on receive. Addresses are never nil. A divergence
   here shows up as a hang, not a compile error.
8. **The tunnel service is registered on the outer server only.** On the inner server it
   would let a tunnel nest inside a tunnel.
9. **`InnerServerOptions` (`ConnectionTimeout`, `MaxConnectionIdle`) go on the inner
   server only.** A caller `KeepaliveParams` appended after them silently replaces
   `MaxConnectionIdle`.
10. **Stop the inner server first.** Every tunnel handler waits on the inner server;
    `TestOuterFirstStopBlocksOnLiveTunnel` demonstrates the hang.
11. **`KeepaliveMinTime` stays below gRPC's 10s client ping floor.** A threshold above it
    strikes a client configured at the floor, which gRPC silently clamps to.
12. **Outer stream window >= inner connection window**, or the outer stream silently
    becomes the binding constraint. `WithInitialWindowSize` disabling BDP is intended: the
    estimator would grow the window and break head-of-line bounds.
13. **The limiter's rate check comes after both concurrency checks**, so an address that
    is merely at its cap is not also charged a token for being told so.
14. **`http.ProxyFromEnvironment` caches for the process and never proxies loopback.**
    Proxy-environment tests run in a child process.
15. **The gRPC floor is pinned at v1.81.1 by a test.** `go get` and `go mod tidy` can move
    dependencies further than asked, and can raise the `go` directive; read the `go.mod`
    diff. The allowed module set is pinned by `module_test.go`.
16. **Envoy's default route timeout (15s) kills a tunnel.** Any layer-7 proxy in front of
    the server needs streaming timeouts disabled.
17. **Regenerate protos only with the pinned toolchain** (`make proto`). A different
    protoc rewrites hundreds of lines and hides the one that matters on the wire.

Behaviours that were decided and must not be "fixed back" to Sentinel's: an inconclusive
probe tunnels; a failed tunnel leaves the mode cache unchanged; the switch is logged once
per host; `Dial` refuses nil, insecure and local inner credentials up front.

---

## Writing rules

No em dash (U+2014) or en dash (U+2013), nor their HTML entity or `\u` spellings, anywhere:
code, comments, docs, commit messages. `TestNoDashes` enforces it. No AI attribution in
commits.
