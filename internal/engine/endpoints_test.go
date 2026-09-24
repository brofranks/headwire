package engine

import (
	"net"
	"slices"
	"testing"

	"tailscale.com/net/netmon"
)

// TestTunnelIsNotAnInterface checks that an interface hidden from netmon
// stays out of every list magicsock builds its local endpoints from. Start
// explains why the tunnel must be.
func TestTunnelIsNotAnInterface(t *testing.T) {
	ifs, err := net.Interfaces()
	if err != nil || len(ifs) == 0 {
		t.Skip("no interfaces:", err)
	}
	netmon.RegisterInterfaceGetter(interfacesExcept(ifs[0].Name))
	t.Cleanup(func() { netmon.RegisterInterfaceGetter(nil) })

	got, err := netmon.GetInterfaceList()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(ifs)-1 || slices.ContainsFunc(got, func(i netmon.Interface) bool { return i.Name == ifs[0].Name }) {
		t.Fatalf("interfaces = %v, want all but %s", got, ifs[0].Name)
	}
}
