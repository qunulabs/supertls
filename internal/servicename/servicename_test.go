package servicename

import "testing"

func TestValid(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"Single", "_x", "supertls.v1.TunnelService", "sentinel.tunnel.v1.TunnelService", "a.b_c.D9",
	} {
		if !Valid(name) {
			t.Errorf("Valid(%q) = false, want true", name)
		}
	}
	for _, name := range InvalidExamples() {
		if Valid(name) {
			t.Errorf("Valid(%q) = true, want false", name)
		}
	}
}
