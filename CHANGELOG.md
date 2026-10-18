# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). While the
major version is 0, the public API may change between minor releases.

## [Unreleased]

## [0.1.0] - Unreleased

The first release: an extraction of Sentinel DRM's TLS-in-TLS transport into a generic
library. The date is set when the version is tagged.

### Added

Every exported identifier, by package (`go doc -all` is the source this list was
checked against).

- `supertls`: `Dialer`, `NewDialer`, `Dialer.Dial`, `Dialer.Mode`, `Conn`,
  `Conn.ClientConn`, `Conn.Mode`, `Conn.Close`, `Mode` (`ModeUnknown`, `ModeDirect`,
  `ModeTunnel`) and `Mode.String`, `ModeChange`, `DialError` with `Error` and `Unwrap`,
  and the sentinel errors `ErrInvalidOption`, `ErrNotReady`, `ErrProxyConnect`,
  `ErrForeignCertificate` and `ErrWindowInvariant`.
- `Trust`, `TrustPool`, `TrustPoolWithHostname` and `TrustSystemRoots`: the trust is a
  parameter, and the caller supplies the inner credentials, which the library never
  modifies. All three require server authentication (`ExtKeyUsageServerAuth`) along the
  chain.
- `Probe` and `Verdict` (`VerdictInconclusive`, `VerdictGenuine`, `VerdictIntercepted`)
  with `Verdict.String`: the interception probe, which dials the way gRPC dials
  (`HTTP_PROXY`, `CONNECT`).
- Options (`Option`): `WithLogger`, `WithOnModeChange`, `WithServiceName`,
  `WithDirectDialOptions`, `WithOuterDialOptions`, `WithInnerBackoff`, `WithOuterBackoff`,
  `WithOuterKeepalive`, `WithWindows`, `WithDirectDialBudget`, `WithTunnelDialBudget`,
  `WithProbeTimeout` and `WithTunnelModeTTL`. A backoff is refused unless
  `BaseDelay >= 0`, `MaxDelay > 0`, `Multiplier >= 1` and `Jitter` is in [0, 1]; a
  keepalive needs a positive `Time` and `Timeout`.
- Defaults: the constants `DefaultDirectDialBudget`, `DefaultTunnelDialBudget`,
  `DefaultProbeTimeout`, `DefaultTunnelModeTTL`, `DefaultServiceName` and
  `DefaultOuterMinConnectTimeout`, and the functions `DefaultInnerBackoff()`,
  `DefaultOuterBackoff()` and `DefaultOuterKeepalive()`, which return a fresh copy so the
  package holds no mutable state. Each `Dialer` keeps its own settings from construction.
- `Windows`, `DefaultWindows`, `Windows.Validate`, `MinWindow` and the constants
  `DefaultOuterStreamWindow`, `DefaultOuterConnWindow`, `DefaultInnerStreamWindow`,
  `DefaultInnerConnWindow` and `DefaultBufferSize`: configurable flow-control windows
  with Sentinel's values as defaults. An outer stream window smaller than the inner
  connection window is refused at construction.
- `server`: `Service`, `New`, `Service.Register`, `Service.Listener`,
  `Service.OuterServerOptions`, `Service.InnerServerOptions`, `Service.GracefulStop`
  (inner server first), `Service.OpenTunnels` (held slots, including tunnels not yet
  accepted), `Service.Open`, `KeepalivePolicy`, `KeepaliveMinTime`, `DefaultServiceName`,
  `Option`, `WithLimits`, `WithListenerAddr`, `WithLogger`, `WithServiceName`,
  `WithWindows`, the server-side `Windows` and `Windows.Validate`, `ErrInvalidOption`
  and `ErrWindowInvariant`.
- `server` limits: `Limits`, `DefaultLimits`, `Limits.Validate` and the constants
  `DefaultMaxConcurrent`, `DefaultMaxPerAddress`, `DefaultOpenBurst`,
  `DefaultOpenRefillPerSecond`, `DefaultBucketSweep`, `DefaultAcceptTimeout`,
  `DefaultInnerHandshakeTimeout`, `DefaultInnerMaxConnectionIdle` and
  `DefaultMaxLifetime`.
- `conn`: `Conn` (a `net.Conn` over a frame stream, with `Read`, `Write`, `Close`,
  `Done`, `LocalAddr`, `RemoteAddr`, `SetDeadline`, `SetReadDeadline` and
  `SetWriteDeadline`), `NewConn`, `Options`, `Stream`, `Listener` (`Accept`, `Addr`,
  `Close`, `Deliver`), `NewListener`, `MaxFrameBytes`, `DefaultAcceptTimeout`,
  `ErrFrameTooLarge` and `ErrDeliverTimeout`.
- `tunnelpb`: generated code for the neutral `supertls.v1.TunnelService/Open`: `Frame`,
  `TunnelServiceClient`, `NewTunnelServiceClient`, `TunnelServiceServer`,
  `RegisterTunnelServiceServer`, `UnimplementedTunnelServiceServer`,
  `UnsafeTunnelServiceServer`, `TunnelService_ServiceDesc`, `TunnelService_Open_FullMethodName`,
  `File_supertls_v1_tunnel_proto` and the stream aliases `TunnelService_OpenClient` and
  `TunnelService_OpenServer`.
- `WithServiceName` on both client and server, so a deployment can keep an existing
  service name on the wire (Sentinel keeps `sentinel.tunnel.v1.TunnelService`). Both
  sides apply one rule: a dotted sequence of identifiers such as `pkg.v1.Service`.
- Tests: the library-relevant Sentinel tests, ported, plus the real-proxy tests (an in-process intercepting
  proxy, an explicit proxy, and an Envoy test behind the `l7proxy` build tag), a
  throughput test against a direct connection, and guards pinning the dependency
  allowlist, the gRPC floor, the Go directive and the absence of em and en dashes.

### Changed from Sentinel

These are deliberate differences from the code this was extracted from.

- **An inconclusive probe tunnels.** Sentinel stays on the direct path. A host that
  cannot be reached now takes up to direct budget + probe timeout + tunnel budget to
  fail (5s + 10s + 20s by default).
- **The switch is logged once per host**, not once per client.
- **A failed tunnel leaves the mode cache unchanged.** After a probe-then-tunnel failure
  the next dial tries direct first. A host already cached as tunnel is different: its
  failure is a plain wrapped error and the host keeps tunnelling until the decision's
  TTL expires.
- **The `CONNECT` reply honours the context.** Dialling through an HTTP proxy no longer
  waits on a silent proxy past the probe timeout.
- **`conn.Conn.Write` returns the stream's terminal status** when the server ended the
  stream, rather than a bare `io.EOF`, and returns `io.EOF` without blocking when an
  unread frame is pending. A `Close` while `Write` waits for that status always yields
  `net.ErrClosed`.
- **Unsafe arguments are refused up front**, with `ErrInvalidOption`. `NewDialer`
  refuses a zero or invalid `Trust`; `Dial` refuses nil inner credentials, gRPC insecure
  or local inner credentials, an empty host and a host containing `://`. Inner credentials and the tunnel dialler are applied after
  every caller option, so `extra` and the direct options cannot replace them.
- `DialError.Direct` is always the original direct error; `errors.Is` matches it and the
  tunnel error.
