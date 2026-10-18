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

- `supertls`: `Dialer`, `NewDialer`, `Dialer.Dial`, `Dialer.Mode`, `Conn`, `Mode`,
  `ModeChange`, `DialError` and the sentinel errors `ErrInvalidOption`, `ErrNotReady`,
  `ErrProxyConnect`, `ErrForeignCertificate` and `ErrWindowInvariant`.
- `Trust`, `TrustPool`, `TrustPoolWithHostname` and `TrustSystemRoots`: the trust is a
  parameter, and the caller supplies the inner credentials, which the library never
  modifies.
- `Probe` and `Verdict` (`VerdictInconclusive`, `VerdictGenuine`, `VerdictIntercepted`):
  the interception probe, which dials the way gRPC dials (`HTTP_PROXY`, `CONNECT`).
- Options: `WithLogger`, `WithOnModeChange`, `WithServiceName`, `WithDirectDialOptions`,
  `WithOuterDialOptions`, `WithInnerBackoff`, `WithWindows`, `WithDirectDialBudget`,
  `WithTunnelDialBudget`, `WithProbeTimeout` and `WithTunnelModeTTL`, with their
  `Default...` values.
- `Windows`, `DefaultWindows` and `Windows.Validate`: configurable flow-control windows
  with Sentinel's values as defaults. An outer stream window smaller than the inner
  connection window is refused at construction.
- `server`: `Service`, `New`, `Register`, `Listener`, `OuterServerOptions`,
  `InnerServerOptions`, `GracefulStop` (inner server first), `OpenTunnels`,
  `KeepalivePolicy`, `Limits`, `DefaultLimits`, `WithLimits`, `WithListenerAddr`,
  `WithLogger`, `WithServiceName`, `WithWindows` and the server-side `Windows`.
- `conn`: `Conn` (a `net.Conn` over a frame stream), `NewConn`, `Listener`, `NewListener`,
  `Stream`, `Options`, `MaxFrameBytes` and `DefaultAcceptTimeout`.
- `tunnelpb`: generated code for the neutral `supertls.v1.TunnelService/Open`.
- `WithServiceName` on both client and server, so a deployment can keep an existing
  service name on the wire (Sentinel keeps `sentinel.tunnel.v1.TunnelService`).
- Tests: the Sentinel tests, ported, plus the real-proxy tests (an in-process intercepting
  proxy, an explicit proxy, and an Envoy test behind the `l7proxy` build tag), a
  throughput test against a direct connection, and guards pinning the dependency
  allowlist, the gRPC floor, the Go directive and the absence of em and en dashes.

### Changed from Sentinel

These are deliberate differences from the code this was extracted from.

- **An inconclusive probe tunnels.** Sentinel stays on the direct path. A host that
  cannot be reached now takes up to direct budget + probe timeout + tunnel budget to
  fail (5s + 10s + 20s by default).
- **The switch is logged once per host**, not once per client.
- **A failed tunnel leaves the mode cache unchanged.** The next dial tries direct first.
- **The `CONNECT` reply honours the context.** Dialling through an HTTP proxy no longer
  waits on a silent proxy past the probe timeout.
- **`conn.Conn.Write` returns the stream's terminal status** when the server ended the
  stream, rather than a bare `io.EOF`, and returns `io.EOF` without blocking when an
  unread frame is pending.
- **`Dial` refuses unsafe arguments up front**, with `ErrInvalidOption`: a zero or
  invalid `Trust`, nil inner credentials, gRPC insecure or local inner credentials, and a
  host containing `://`. Inner credentials and the tunnel dialler are applied after
  every caller option, so `extra` and the direct options cannot replace them.
- `DialError.Direct` is always the original direct error; `errors.Is` matches it and the
  tunnel error.
