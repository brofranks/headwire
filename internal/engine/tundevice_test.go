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

type countingTun struct {
	tun.Device
	closes int
}

func (d *countingTun) Close() error {
	d.closes++
	return d.Device.Close()
}

func TestInjectedTunWithoutName(t *testing.T) {
	a := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), 0}
	dev := &countingTun{Device: unnamedTun{tuntest.NewChannelTUN().TUN()}}
	if _, err := Start(a.parse(t, "", ""), tstest.WhileTestRunningLogger(t), Options{Tun: dev}); err == nil {
		t.Fatal("started on a device without a name")
	}
	if dev.closes != 1 {
		t.Fatalf("device closed %d times, want 1", dev.closes)
	}
}

// TestInjectedTunRoundTrip sends a packet into one engine's injected device and
// reads it out of the other's, so the whole data plane runs on devices the
// engine did not create.
func TestInjectedTunRoundTrip(t *testing.T) {
	a := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), freePort(t)}
	b := node{key.NewNode(), netip.MustParsePrefix("100.64.0.2/32"), freePort(t)}
	eb, chb := startInjected(t, b.config(t, "", a, "")) // passive
	ea, cha := startInjected(t, a.config(t, "", b, fmt.Sprintf("Endpoint = 127.0.0.1:%d", b.port)))
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

// fakeInterfaces makes netmon see eth0 with IPv4 192.0.2.10/24 and the
// tunnel hwtest0 with the given address. It starts with no tunnel registered,
// so only Start can register hwtest0.
func fakeInterfaces(t *testing.T, tunnel *net.IPNet) {
	t.Helper()
	netmon.SetTailscaleInterfaceProps("", 0)
	up := net.FlagUp | net.FlagRunning
	netmon.RegisterInterfaceGetter(func() ([]netmon.Interface, error) {
		return []netmon.Interface{
			{
				Interface: &net.Interface{
					Index: 1001,
					MTU:   1500,
					Name:  "eth0",
					Flags: up,
				},
				AltAddrs: []net.Addr{&net.IPNet{
					IP:   net.ParseIP("192.0.2.10"),
					Mask: net.CIDRMask(24, 32),
				}},
			},
			{
				Interface: &net.Interface{
					Index: 1002,
					MTU:   1280,
					Name:  "hwtest0",
					Flags: up,
				},
				AltAddrs: []net.Addr{tunnel},
			},
		}, nil
	})
	t.Cleanup(func() {
		netmon.RegisterInterfaceGetter(nil)
		netmon.SetTailscaleInterfaceProps("", 0)
	})
}

// TestTunnelIsNotAnEndpoint checks that the tunnel's address, outside
// Tailscale's ranges, stays out of the endpoints advertised to peers, which
// would otherwise offer them a direct path through the tunnel itself.
func TestTunnelIsNotAnEndpoint(t *testing.T) {
	fakeInterfaces(t, &net.IPNet{
		IP:   net.ParseIP("10.99.0.1"),
		Mask: net.CIDRMask(24, 32),
	})

	a := node{
		key.NewNode(),
		netip.MustParsePrefix("10.99.0.1/24"),
		0,
	}
	e, err := Start(a.parse(t, "", ""), tstest.WhileTestRunningLogger(t), Options{Tun: namedTun{tuntest.NewChannelTUN().TUN()}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)

	tunnel, lan := a.addr.Addr(), netip.MustParseAddr("192.0.2.10")
	deadline := time.Now().Add(30 * time.Second)
	for {
		eps := e.endpoints()
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

// TestTunnelFamilyIsNotUnderlay checks that an ordinary peer's endpoint is
// chosen at startup by the underlay's address families, not the tunnel's: an
// IPv6 tunnel on an IPv4-only host must not select the peer's IPv6 address.
func TestTunnelFamilyIsNotUnderlay(t *testing.T) {
	fakeInterfaces(t, &net.IPNet{
		IP:   net.ParseIP("2001:db8::1"),
		Mask: net.CIDRMask(64, 128),
	})
	a := node{
		key.NewNode(),
		netip.MustParsePrefix("100.64.0.1/32"),
		0,
	}
	peer := key.NewNode().Public()
	cfg := a.parse(t, "", fmt.Sprintf(
		"[Peer]\nPublicKey = %s\nAllowedIPs = 100.64.0.2/32\nEndpoint = 192.0.2.20:51820\n",
		//lint:ignore SA1019 raw keys; see config.EncodeKey.
		config.EncodeKey(peer.Raw32()),
	))
	v4 := netip.MustParseAddrPort("192.0.2.20:51820")
	cfg.Peers[0].Addrs = []netip.AddrPort{
		netip.MustParseAddrPort("[2001:db8::20]:51820"),
		v4,
	}
	e, err := Start(cfg, tstest.WhileTestRunningLogger(t), Options{
		Tun: namedTun{tuntest.NewChannelTUN().TUN()},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	got := e.state.Load().nodes[peer].Endpoints().AsSlice()
	if !slices.Equal(got, []netip.AddrPort{v4}) {
		t.Fatalf("endpoints = %v, want [%v]", got, v4)
	}
}
