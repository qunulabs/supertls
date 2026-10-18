// Package testpki builds throwaway ECDSA P-256 certificate hierarchies for
// tests. It lives under internal/ and is never part of the public API.
//
// Everything here takes a testing.TB and fails the test on any error, so a
// caller never handles one.
package testpki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"
)

// CA is one certificate authority: a root, or an intermediate beneath one.
type CA struct {
	Cert *x509.Certificate
	DER  []byte
	Key  crypto.Signer
	// Pool trusts the ROOT of this hierarchy, whichever CA in it this is.
	Pool *x509.CertPool
	// chain holds the DERs of this CA's issuers below the root, appended to
	// every leaf this CA issues so a verifier that trusts only the root can
	// still build a path.
	chain [][]byte
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("testpki: generate key: %v", err)
	}
	return k
}

func newSerial(t testing.TB) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	if err != nil {
		t.Fatalf("testpki: serial: %v", err)
	}
	return n
}

func parse(t testing.TB, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("testpki: parse certificate: %v", err)
	}
	return c
}

// NewRoot returns a self-signed root CA.
func NewRoot(t testing.TB, cn string, notBefore, notAfter time.Time) *CA {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          newSerial(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("testpki: create root %q: %v", cn, err)
	}
	cert := parse(t, der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &CA{Cert: cert, DER: der, Key: key, Pool: pool}
}

// Intermediate returns a CA issued by ca. Its Pool is the ROOT's pool.
func (ca *CA) Intermediate(t testing.TB, cn string, notBefore, notAfter time.Time) *CA {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          newSerial(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatalf("testpki: create intermediate %q: %v", cn, err)
	}
	// This CA's own certificate is below the root unless this CA is the root.
	below := ca.chainBelowRoot()
	return &CA{Cert: parse(t, der), DER: der, Key: key, Pool: ca.Pool, chain: below}
}

// chainBelowRoot returns ca's own DER followed by its issuers' up to but not
// including the root, which a verifier holds already. A root yields nothing.
func (ca *CA) chainBelowRoot() [][]byte {
	if ca.Cert.CheckSignatureFrom(ca.Cert) == nil {
		return nil
	}
	return append([][]byte{ca.DER}, ca.chain...)
}

// issue signs a leaf for pub and returns the DER.
func (ca *CA) issue(t testing.TB, tmpl *x509.Certificate, pub crypto.PublicKey) []byte {
	t.Helper()
	tmpl.SerialNumber = newSerial(t)
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	tmpl.BasicConstraintsValid = true
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
	if err != nil {
		t.Fatalf("testpki: create leaf: %v", err)
	}
	return der
}

// leaf wraps a leaf DER and key as a tls.Certificate carrying ca's chain.
func (ca *CA) leaf(der []byte, key crypto.Signer) tls.Certificate {
	chain := append([][]byte{der}, ca.chainBelowRoot()...)
	return tls.Certificate{Certificate: chain, PrivateKey: key}
}

// ServerCert issues a server leaf with ExtKeyUsageServerAuth and the given DNS
// names. The certificate carries no IP addresses.
func (ca *CA) ServerCert(t testing.TB, notBefore, notAfter time.Time, dnsNames ...string) tls.Certificate {
	t.Helper()
	return ca.LeafWithEKU(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, notBefore, notAfter, dnsNames...)
}

// LeafWithEKU issues a leaf with exactly the given extended key usages.
func (ca *CA) LeafWithEKU(t testing.TB, eku []x509.ExtKeyUsage, notBefore, notAfter time.Time, dnsNames ...string) tls.Certificate {
	t.Helper()
	key := newKey(t)
	cn := "supertls test leaf"
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	}
	der := ca.issue(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: cn},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		ExtKeyUsage: eku,
		DNSNames:    dnsNames,
	}, &key.PublicKey)
	return ca.leaf(der, key)
}

// ClientCert issues a client leaf with ExtKeyUsageClientAuth, the given common
// name and, when uri is not nil, that URI SAN.
func (ca *CA) ClientCert(t testing.TB, cn string, uri *url.URL, notAfter time.Time) tls.Certificate {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: cn},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if uri != nil {
		tmpl.URIs = []*url.URL{uri}
	}
	return ca.leaf(ca.issue(t, tmpl, &key.PublicKey), key)
}

// PKI is the standard fixture: a real hierarchy, a foreign root standing in for
// a TLS-inspecting proxy, and the leaves the tests need.
type PKI struct {
	Root, Issuing, Foreign *CA
	Server, Client, Proxy  tls.Certificate
	ClientURI              *url.URL
}

// Standard builds the standard fixture.
//
// Server carries DNS SANs only and deliberately no IP SAN, so a test that dials
// 127.0.0.1 and verifies the hostname fails verification.
func Standard(t testing.TB) *PKI {
	t.Helper()
	now := time.Now()
	root := NewRoot(t, "supertls test root", now.Add(-time.Hour), now.Add(24*time.Hour))
	issuing := root.Intermediate(t, "supertls test issuing", now.Add(-time.Hour), now.Add(24*time.Hour))
	foreign := NewRoot(t, "corporate inspection CA", now.Add(-time.Hour), now.Add(24*time.Hour))
	uri := &url.URL{Scheme: "spiffe", Host: "supertls.test", Path: "/client-1"}
	return &PKI{
		Root:      root,
		Issuing:   issuing,
		Foreign:   foreign,
		Server:    issuing.ServerCert(t, now.Add(-time.Hour), now.Add(24*time.Hour), "localhost", "origin.supertls.test"),
		Client:    issuing.ClientCert(t, "client-1", uri, now.Add(24*time.Hour)),
		Proxy:     foreign.ServerCert(t, now.Add(-time.Hour), now.Add(24*time.Hour), "localhost", "origin.supertls.test"),
		ClientURI: uri,
	}
}

// StrictServerTLS is the strict server configuration: pinned client CA, TLS 1.3
// floor, hybrid post-quantum group preferred, and a client certificate verified
// whenever one is presented.
func StrictServerTLS(p *PKI) *tls.Config {
	return &tls.Config{
		Certificates:     []tls.Certificate{p.Server},
		ClientAuth:       tls.VerifyClientCertIfGiven,
		ClientCAs:        p.Root.Pool,
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	}
}

// StrictClientTLS is the strict client configuration: pinned root, TLS 1.3
// floor, the same groups, and the fixture's client certificate. It sets no
// ServerName; the caller names the server.
func StrictClientTLS(p *PKI) *tls.Config {
	return &tls.Config{
		RootCAs:          p.Root.Pool,
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &p.Client, nil
		},
	}
}
