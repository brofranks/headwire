package engine

import (
	"net/netip"
	"strings"
	"testing"

	"brof.dev/headwire/internal/config"
)

func TestWindowsHostDNS(t *testing.T) {
	cfg := &config.Config{
		Interface: config.Interface{
			DNS: []netip.Addr{netip.MustParseAddr("192.0.2.53")},
		},
	}
	if err := checkKernelConfig(cfg); err == nil || !strings.Contains(err.Error(), "DNS nameservers") {
		t.Fatalf("host DNS rejection: %v", err)
	}
}

func TestWindowsHostDefaultRoute(t *testing.T) {
	for _, prefix := range []string{"0.0.0.0/0", "::/0"} {
		route := netip.MustParsePrefix(prefix)
		for _, cfg := range []*config.Config{
			{Interface: config.Interface{Addresses: []netip.Prefix{route}}},
			{Peers: []config.Peer{{AllowedIPs: []netip.Prefix{route}}}},
		} {
			if err := checkKernelConfig(cfg); err == nil || !strings.Contains(err.Error(), "default routes") {
				t.Fatalf("derived route %s rejection: %v", route, err)
			}
		}
	}
}
