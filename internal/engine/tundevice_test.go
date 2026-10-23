package engine

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"tailscale.com/tstest"

	"brof.dev/headwire/internal/config"
	"github.com/tailscale/wireguard-go/tun"
	"github.com/tailscale/wireguard-go/tun/tuntest"
	"tailscale.com/net/netmon"
	"tailscale.com/types/key"
)

// defaultRouteAddr is the address the peer endpoint has to use: an injected
// device leaves netns enabled, which binds the underlay sockets to the default
// interface, so loopback endpoints never connect. Production wants exactly
// that, because the underlay must not be routed back into the tunnel.
func defaultRouteAddr(t *testing.T) netip.Addr {
	t.Helper()
	c, err := net.Dial("udp4", "192.0.2.1:9")
	if err != nil {
		t.Skipf("no IPv4 default route: %v", err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Addr()
}

// startInjected runs an engine on a packet device the caller owns. No root and
// no OS router are involved.
func startInjected(t *testing.T, cfg *config.Config) (*Engine, *tuntest.ChannelTUN) {
	t.Helper()
	ch := tuntest.NewChannelTUN()
	e, err := Start(cfg, tstest.WhileTestRunningLogger(t), Options{Tun: ch.TUN()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e, ch
}

type unnamedTun struct{ tun.Device }

func (unnamedTun) Name() (string, error) { return "", errors.New("no name") }

func TestInjectedTunWithoutName(t *testing.T) {
	a := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), 0}
	if _, err := Start(a.parse(t, "", ""), tstest.WhileTestRunningLogger(t), Options{Tun: unnamedTun{tuntest.NewChannelTUN().TUN()}}); err == nil {
		t.Fatal("started on a device without a name")
	}
}

// TestInjectedTunRoundTrip sends a packet into one engine's injected device and
// reads it out of the other's, so the whole data plane runs on devices the
// engine did not create.
func TestInjectedTunRoundTrip(t *testing.T) {
	a := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), freePort(t)}
	b := node{key.NewNode(), netip.MustParsePrefix("100.64.0.2/32"), freePort(t)}
	eb, chb := startInjected(t, b.config(t, "", a, "")) // passive
	ea, cha := startInjected(t, a.config(t, "", b, fmt.Sprintf("Endpoint = %s:%d", defaultRouteAddr(t), b.port)))
	warm(t, ea, eb)

	if ea.tunName != "loopbackTun1" {
		t.Errorf("tunName = %q, want the injected device's name", ea.tunName)
	}

	ping := tuntest.Ping(b.addr.Addr(), a.addr.Addr())
	deadline := time.After(30 * time.Second)
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		cha.Outbound <- ping
		select {
		case got := <-chb.Inbound:
			if string(got) != string(ping) {
				t.Fatalf("got %x, want %x", got, ping)
			}
			return
		case <-tick.C:
		case <-deadline:
			t.Fatal("no packet arrived on the peer's injected device")
		}
	}
}

type namedTun struct{ tun.Device }

func (namedTun) Name() (string, error) { return "hwtest0", nil }

// TestTunnelIsNotAnEndpoint checks that the tunnel's address, outside
// Tailscale's ranges, stays out of the endpoints advertised to peers. Start
// explains why it must.
func TestTunnelIsNotAnEndpoint(t *testing.T) {
	up := net.FlagUp | net.FlagRunning
	netmon.RegisterInterfaceGetter(func() ([]netmon.Interface, error) {
		return []netmon.Interface{
			{
				Interface: &net.Interface{Index: 1001, MTU: 1500, Name: "eth0", Flags: up},
				AltAddrs:  []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.10"), Mask: net.CIDRMask(24, 32)}},
			},
			{
				Interface: &net.Interface{Index: 1002, MTU: 1280, Name: "hwtest0", Flags: up},
				AltAddrs:  []net.Addr{&net.IPNet{IP: net.ParseIP("10.99.0.1"), Mask: net.CIDRMask(24, 32)}},
			},
		}, nil
	})
	t.Cleanup(func() {
		netmon.RegisterInterfaceGetter(nil)
		netmon.SetTailscaleInterfaceProps("", 0)
	})

	a := node{key.NewNode(), netip.MustParsePrefix("10.99.0.1/24"), 0}
	e, err := Start(a.parse(t, "", ""), tstest.WhileTestRunningLogger(t), Options{Tun: namedTun{tuntest.NewChannelTUN().TUN()}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)

	tunnel, lan := a.addr.Addr(), netip.MustParseAddr("192.0.2.10")
	deadline := time.Now().Add(30 * time.Second)
	for {
		e.mu.Lock()
		eps := e.eps
		e.mu.Unlock()
		if slices.ContainsFunc(eps, func(ep netip.AddrPort) bool { return ep.Addr() == tunnel }) {
			t.Fatalf("endpoints %v include the tunnel's address", eps)
		}
		if slices.ContainsFunc(eps, func(ep netip.AddrPort) bool { return ep.Addr() == lan }) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("endpoints %v never included 192.0.2.10", eps)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
