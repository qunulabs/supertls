package supertls_test

import (
	"crypto/x509"
	"errors"
	"testing"

	"github.com/qunulabs/supertls"
	"github.com/qunulabs/supertls/internal/servicename"
	"github.com/qunulabs/supertls/server"
)

// The client and the server must accept exactly the same service names: a
// name one side accepts and the other refuses is a deployment that can be
// configured on one end only. Both refuse every name on the shared list, and
// both accept the default and Sentinel's name.
func TestClientAndServerRefuseTheSameServiceNames(t *testing.T) {
	t.Parallel()
	trust := supertls.TrustPool(x509.NewCertPool())
	for _, name := range servicename.InvalidExamples() {
		_, cerr := supertls.NewDialer(trust, supertls.WithServiceName(name))
		_, serr := server.New(server.WithServiceName(name))
		if !errors.Is(cerr, supertls.ErrInvalidOption) || !errors.Is(serr, server.ErrInvalidOption) {
			t.Errorf("name %q: client err = %v, server err = %v; both must refuse", name, cerr, serr)
		}
	}
	for _, name := range []string{supertls.DefaultServiceName, "sentinel.tunnel.v1.TunnelService"} {
		_, cerr := supertls.NewDialer(trust, supertls.WithServiceName(name))
		_, serr := server.New(server.WithServiceName(name))
		if cerr != nil || serr != nil {
			t.Errorf("name %q: client err = %v, server err = %v; both must accept", name, cerr, serr)
		}
	}
}
