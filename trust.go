package supertls

import (
	"crypto/x509"
	"time"
)

// Trust says which certificates identify the caller's own server. The probe
// uses it to answer "is the peer at this address ours?", which decides whether
// a failed direct dial is worth tunnelling.
//
// The zero value is invalid: it trusts nothing. Build one with TrustPool,
// TrustPoolWithHostname or TrustSystemRoots.
type Trust struct {
	roots         *x509.CertPool
	system        bool
	checkHostname bool
}

// TrustPool recognises a server whose presented chain leads to a root in pool
// and is valid for server authentication: x509.ExtKeyUsageServerAuth is
// required, so a certificate in the chain that lists extended key usages must
// include it. The hostname is not checked and validity dates are neutralised,
// so a genuine server with an expired leaf or drifted SANs is still recognised
// as genuine. A nil pool yields the invalid zero Trust.
func TrustPool(pool *x509.CertPool) Trust {
	if pool == nil {
		return Trust{}
	}
	return Trust{roots: pool}
}

// TrustPoolWithHostname is TrustPool that also requires the leaf to cover the
// dialled host name. A nil pool yields the invalid zero Trust.
//
// The host checked is the one passed to Dial, not a server name the inner
// credentials override it with: dialling an IP address while the inner
// credentials verify a DNS name makes a genuine server fail the check, so it is
// ruled intercepted and tunnelled. That is safe (the inner session still
// verifies the server) but costs a tunnel; use TrustPool for that setup.
func TrustPoolWithHostname(pool *x509.CertPool) Trust {
	if pool == nil {
		return Trust{}
	}
	return Trust{roots: pool, checkHostname: true}
}

// TrustSystemRoots recognises a server whose presented chain leads to a root in
// the operating system's trust store, is valid for server authentication
// (x509.ExtKeyUsageServerAuth), and whose leaf covers the dialled host name. Use it
// for a server that presents a certificate from the public web PKI.
func TrustSystemRoots() Trust {
	return Trust{system: true, checkHostname: true}
}

// valid reports whether t was built by one of the constructors. The check
// matters: a nil Roots in x509.VerifyOptions means the system roots, so an
// unchecked zero Trust would silently trust the whole web PKI.
func (t Trust) valid() bool {
	return t.roots != nil || t.system
}

// recognises answers "is this our server?", NOT "is this certificate usable?".
//
// Validity dates are neutralised on purpose, and the hostname is ignored unless
// the Trust asks for it. A genuine-but-expired leaf, or one whose SANs have
// drifted from the configured hosts, is the server operator's bug: tunnelling
// would fail on it identically, and treating it as interception would hide a
// real outage behind a silent fallback.
func (t Trust) recognises(der [][]byte, serverName string) bool {
	if !t.valid() {
		return false
	}
	if len(der) == 0 {
		return false
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		return false
	}
	// The pin must be a moment when EVERY certificate in the path was valid, not
	// merely the leaf: Go checks the validity of each one it walks through. The
	// latest NotBefore in the chain is that moment.
	verifyAt := leaf.NotBefore
	intermediates := x509.NewCertPool()
	for _, d := range der[1:] {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			continue
		}
		intermediates.AddCert(c)
		if c.NotBefore.After(verifyAt) {
			verifyAt = c.NotBefore
		}
	}

	opts := x509.VerifyOptions{
		// nil when t.system, which x509 reads as the system roots.
		Roots:         t.roots,
		Intermediates: intermediates,
		CurrentTime:   verifyAt.Add(time.Second),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if t.checkHostname {
		// VerifyHostname accepts an IP literal here as well as a DNS name.
		opts.DNSName = serverName
	}
	_, err = leaf.Verify(opts)
	return err == nil
}
