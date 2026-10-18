//go:build l7proxy

package supertls_test

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/qunulabs/supertls"
	"github.com/qunulabs/supertls/internal/testpki"
)

// envoyImage is the proxy under test. A real L7 HTTP/2 proxy is the case the
// in-process proxies cannot stand in for: it terminates the outer connection,
// re-originates it as its own HTTP/2 connection, and enforces its own timeouts
// on streams.
const envoyImage = "envoyproxy/envoy:v1.32-latest"

// The container uses host networking, so this needs a Docker Engine on Linux.
// Docker Desktop runs containers in a VM whose "host" network is not this
// machine's loopback: Envoy starts, but nothing it listens on is reachable.
//
// envoyConfig is a minimal terminating HTTP/2 proxy. The route timeout and idle
// timeout are DISABLED on purpose: Envoy's default route timeout is 15 seconds,
// which would end the one long-lived Open stream that carries the whole tunnel.
// A deployment behind such a proxy should disable it too; the test pins that
// the library works once it has. (Envoy starts that timer only when the
// downstream request ends, which a never-ending tunnel stream does not, so the
// default may not bite today; disabling it removes the dependence on that.)
//
// The upstream context pins TLS 1.3 because Envoy's client default tops out at
// TLS 1.2, which the strict backend refuses.
const envoyConfig = `static_resources:
  listeners:
  - name: ingress
    address:
      socket_address: { address: 127.0.0.1, port_value: %d }
    filter_chains:
    - transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          common_tls_context:
            alpn_protocols: ["h2"]
            tls_certificates:
            - certificate_chain: { filename: /cfg/proxy.pem }
              private_key: { filename: /cfg/proxy.key }
      filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress
          codec_type: AUTO
          route_config:
            name: local
            virtual_hosts:
            - name: all
              domains: ["*"]
              routes:
              - match: { prefix: "/" }
                route:
                  cluster: backend
                  timeout: 0s
                  idle_timeout: 0s
          http_filters:
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
  - name: backend
    type: STATIC
    connect_timeout: 5s
    load_assignment:
      cluster_name: backend
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address: { address: 127.0.0.1, port_value: %d }
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        explicit_http_config:
          http2_protocol_options: {}
    transport_socket:
      name: envoy.transport_sockets.tls
      typed_config:
        "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
        sni: localhost
        common_tls_context:
          tls_params:
            tls_minimum_protocol_version: TLSv1_3
            tls_maximum_protocol_version: TLSv1_3
`

func TestL7HTTP2ProxyCarriesTunnel(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the Envoy container runs with host networking, which only Linux provides")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("docker is not on PATH, and the l7proxy tag was asked for explicitly: %v", err)
	}

	p := testpki.Standard(t)
	backend, svc := startBackend(t, p)

	dir := t.TempDir()
	envoyPort := freePort(t)
	writeProxyFiles(t, dir, p, envoyPort, portOf(t, backend))

	name := "supertls-l7-" + randomSuffix(t)
	out, err := exec.Command("docker", "run", "--rm", "-d", "--name", name,
		"--network", "host", "-v", dir+":/cfg:ro",
		envoyImage, "-c", "/cfg/envoy.yaml").CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	envoyAddr := net.JoinHostPort("127.0.0.1", fmt.Sprint(envoyPort))
	deadline := time.Now().Add(30 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", envoyAddr, time.Second)
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
			t.Fatalf("envoy did not listen on %s within 30s (Docker Desktop cannot run this test, see the top of the file): %v\n%s", envoyAddr, err, logs)
		}
		time.Sleep(200 * time.Millisecond)
	}

	d := newDialer(t, p, nil, supertls.WithTunnelDialBudget(10*time.Second))
	c, err := d.Dial(dialCtx(t), "localhost:"+fmt.Sprint(envoyPort), innerCreds(p))
	if err != nil {
		logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
		t.Fatalf("Dial through envoy: %v\nenvoy logs:\n%s", err, logs)
	}
	t.Cleanup(func() { _ = c.Close() })

	if c.Mode() != supertls.ModeTunnel {
		t.Fatalf("Mode() = %s, want tunnel", c.Mode())
	}
	healthCheck(t, c.ClientConn())
	if n := svc.OpenTunnels(); n != 1 {
		t.Fatalf("OpenTunnels() = %d, want 1", n)
	}

	// Envoy's default route timeout is 15 seconds. The configuration disables
	// it; this proves the SAME tunnel outlives it.
	time.Sleep(20 * time.Second)
	healthCheck(t, c.ClientConn())
	if n := svc.OpenTunnels(); n != 1 {
		t.Fatalf("after 20s OpenTunnels() = %d, want 1 (the same tunnel)", n)
	}
}

// writeProxyFiles writes the proxy's certificate and key (signed by the foreign
// root, as a TLS-inspecting proxy's would be) and its configuration into dir.
// The directory and files are world-readable because the container's envoy user
// is not the test's user.
func writeProxyFiles(t *testing.T, dir string, p *testpki.PKI, envoyPort int, backendPort string) {
	t.Helper()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	var certPEM []byte
	for _, der := range p.Proxy.Certificate {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(p.Proxy.PrivateKey)
	if err != nil {
		t.Fatalf("marshal proxy key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	var bp int
	if _, err := fmt.Sscan(backendPort, &bp); err != nil {
		t.Fatalf("backend port %q: %v", backendPort, err)
	}
	files := map[string][]byte{
		"proxy.pem":  certPEM,
		"proxy.key":  keyPEM,
		"envoy.yaml": []byte(fmt.Sprintf(envoyConfig, envoyPort, bp)),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
}

// freePort asks the kernel for an unused loopback port. The port is released
// before it is used, which is a race another process could win; on a test
// machine that is accepted.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("random: %v", err)
	}
	return hex.EncodeToString(b)
}
