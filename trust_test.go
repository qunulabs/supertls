package supertls

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/qunulabs/supertls/internal/testpki"
)

// The pin is the latest NotBefore in the chain, not the leaf's: an intermediate
// issued after the leaf's NotBefore was not valid at that moment, and Go checks
// every certificate it walks through.
func TestTrustPinsTimeToLatestNotBefore(t *testing.T) {
	t.Parallel()
	now := time.Now()
	root := testpki.NewRoot(t, "root", now.Add(-72*time.Hour), now.Add(24*time.Hour))
	inter := root.Intermediate(t, "late intermediate", now.Add(-time.Hour), now.Add(24*time.Hour))
	leaf := inter.ServerCert(t, now.Add(-48*time.Hour), now.Add(time.Hour), "localhost")

	if !TrustPool(root.Pool).recognises(leaf.Certificate, "localhost") {
		t.Fatal("a chain valid at its latest NotBefore was not recognised")
	}
}

func TestTrustRequiresServerAuthEKU(t *testing.T) {
	t.Parallel()
	p := testpki.Standard(t)
	now := time.Now()
	leaf := p.Issuing.LeafWithEKU(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		now.Add(-time.Hour), now.Add(time.Hour), "localhost")

	if TrustPool(p.Root.Pool).recognises(leaf.Certificate, "localhost") {
		t.Fatal("a leaf without ExtKeyUsageServerAuth was recognised")
	}
	if !TrustPool(p.Root.Pool).recognises(p.Server.Certificate, "localhost") {
		t.Fatal("control: the standard server leaf was not recognised")
	}
}

// A zero Trust has a nil pool, which x509 would read as the system roots. It
// must recognise nothing rather than everything the web PKI signs.
func TestTrustZeroValueIsInvalid(t *testing.T) {
	t.Parallel()
	var zero Trust
	if zero.valid() {
		t.Fatal("zero Trust reports valid")
	}
	p := testpki.Standard(t)
	if zero.recognises(p.Server.Certificate, "localhost") {
		t.Fatal("zero Trust recognised a certificate")
	}
}

func TestTrustPoolNilIsInvalid(t *testing.T) {
	t.Parallel()
	if TrustPool(nil).valid() {
		t.Fatal("TrustPool(nil) reports valid")
	}
	if TrustPoolWithHostname(nil).valid() {
		t.Fatal("TrustPoolWithHostname(nil) reports valid")
	}
}

func TestTrustSystemRootsIsValid(t *testing.T) {
	t.Parallel()
	tr := TrustSystemRoots()
	if !tr.valid() {
		t.Fatal("TrustSystemRoots reports invalid")
	}
	if !tr.checkHostname {
		t.Fatal("TrustSystemRoots does not check the hostname")
	}
	// A private hierarchy is not in the system store.
	p := testpki.Standard(t)
	if tr.recognises(p.Server.Certificate, "localhost") {
		t.Fatal("system roots recognised a private test chain")
	}
}

func TestTrustRejectsEmptyAndGarbageChains(t *testing.T) {
	t.Parallel()
	p := testpki.Standard(t)
	for _, tr := range []Trust{TrustPool(p.Root.Pool), TrustPoolWithHostname(p.Root.Pool), TrustSystemRoots()} {
		if tr.recognises(nil, "localhost") {
			t.Fatal("an empty chain was recognised")
		}
		if tr.recognises([][]byte{{0x01}}, "localhost") {
			t.Fatal("a garbage chain was recognised")
		}
	}
}

func TestTrustHostnameIsCheckedOnlyWhenAsked(t *testing.T) {
	t.Parallel()
	p := testpki.Standard(t)
	if !TrustPool(p.Root.Pool).recognises(p.Server.Certificate, "elsewhere.example") {
		t.Fatal("TrustPool checked the hostname")
	}
	if TrustPoolWithHostname(p.Root.Pool).recognises(p.Server.Certificate, "elsewhere.example") {
		t.Fatal("TrustPoolWithHostname ignored a hostname mismatch")
	}
	if !TrustPoolWithHostname(p.Root.Pool).recognises(p.Server.Certificate, "origin.supertls.test") {
		t.Fatal("TrustPoolWithHostname refused a covered hostname")
	}
}
