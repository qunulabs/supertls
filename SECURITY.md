# Security

## What supertls verifies, and what it does not

supertls carries a TLS session inside another. It is precise about which of the two
sessions it has any say over: the outer one verifies nothing, by design, and the inner
one is entirely the caller's.

**supertls verifies exactly one thing, and only on the probe:** whether the chain the
peer presents reaches the configured `Trust` (and, for `TrustPoolWithHostname` and
`TrustSystemRoots`, whether the leaf covers the dialled host). That answer decides
**routing**, whether a failed direct dial is worth tunnelling. It does not decide
trust. A peer the probe calls genuine is still verified again, by your credentials, on
the dial itself.

**supertls does not:**

- verify the outer connection. It is a pipe that a proxy may open and terminate, so its
  credentials accept any certificate and present none
- configure, change or weaken the inner session. The inner credentials and `tls.Config`
  are the caller's and are used unchanged on both paths
- authenticate whoever opens a tunnel. The tunnel service is unauthenticated, exactly
  like a server's other pre-authentication calls. The exposure it adds is resource, not
  identity, and `server.Limits` bounds it
- authorise any call carried through it. Authentication of clients belongs on the inner
  session, where the identity lives
- promise confidentiality beyond what the caller's inner TLS gives
- detect TLS credentials built with `InsecureSkipVerify`. `Dial` refuses nil credentials
  and gRPC's insecure and local credentials, but a `tls.Config` that skips verification
  cannot be seen from outside, and over a tunnel it would leave no verification
  anywhere. That is the caller's responsibility

## Why the fallback is not a downgrade

The inner handshake is identical on the direct path and the tunnelled path: the same
credentials, the same roots, the same identity. Falling back to the tunnel changes only
the pipe the bytes travel in. A network that inspects TLS can still read the outer
session, which carries the inner session as opaque bytes, but it cannot read or alter
the inner session without failing its verification.

## Things worth knowing

**The library makes traffic uninspectable by a corporate proxy.** That is its purpose,
and also a thing a customer's security team is entitled to know. A deployment should
tell them. The one `Warn` log line per host, written on the first switch to the tunnel,
is the only local evidence: two nested TLS layers make packet capture useless for
diagnosis.

**Never put per-RPC credentials on the outer connection.** `WithOuterDialOptions` must
not carry `grpc.WithPerRPCCredentials`, or an interceptor that attaches a token. The
outer connection reports `PrivacyAndIntegrity` to gRPC while verifying nothing, so gRPC
would hand the token to whoever terminates it, an inspecting proxy included. Per-RPC
credentials belong on the inner connection, through `extra` in `Dial`.

**`TrustSystemRoots` and inspection CAs.** A corporate inspection CA installed in the
operating system store makes interception look genuine: the probe recognises the chain,
calls the peer genuine, and the client never tunnels. Prefer `TrustPool` with the roots
of your own server. A long-expired public certificate can read as genuine under the
pinned-time rule; the only effect is that no tunnel is attempted.

**The outer server must not require a client certificate**, and a deployment that wants
client authentication verifies it on the inner session (for example
`tls.VerifyClientCertIfGiven` plus a per-call check).

**Resource exposure.** An unauthenticated peer can open tunnels up to the configured
limits and no further: a global cap, a per-address cap, a per-address open rate, a
handshake timeout, an idle bound and an absolute lifetime. Raising them raises the
memory an attacker can pin (about 134 KiB and eleven goroutines per tunnel).

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue.

Open a [draft security advisory](https://github.com/qunulabs/supertls/security/advisories/new)
on this repository. If that is not available to you, contact the maintainers through the
repository's listed contact address.

Please include the version or commit, the platform, and enough detail to reproduce.
We aim to acknowledge within a week.

## Supported versions

supertls is pre-1.0. Fixes land on the latest minor release only.
