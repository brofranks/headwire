package engine

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"tailscale.com/tstest"

	"brof.dev/headwire/internal/config"
	"brof.dev/headwire/internal/discokey"
	"github.com/tailscale/wireguard-go/conn"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun/tuntest"
	"tailscale.com/net/packet"
	"tailscale.com/net/tstun"
	"tailscale.com/types/key"
)

func TestListenPortsAndEquivalentMTU(t *testing.T) {
	a := node{priv: key.NewNode(), addr: netip.MustParsePrefix("100.64.0.1/32")}
	for _, explicit := range []bool{false, true} {
		src := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\n", config.EncodeKey(a.priv.Raw32()), a.addr)
		if explicit {
			src += "ListenPort = 0\n"
		}
		cfg, err := config.Parse([]byte(src))
		if err != nil {
			t.Fatal(err)
		}
		e := startEcho(t, cfg)
		if port, _ := e.Status("listen-port"); port == "0\n" {
			t.Fatal("random port not bound")
		}
		next := *cfg
		next.Interface.MTU = int(tstun.DefaultTUNMTU())
		if err := e.Reload(&next); err != nil {
			t.Fatalf("equivalent MTU: %v", err)
		}
	}
	hold, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	cfg := a.parse(t, "", "")
	cfg.Interface.ListenPort = uint16(hold.LocalAddr().(*net.UDPAddr).Port)
	if e, err := Start(cfg, tstest.WhileTestRunningLogger(t), Options{Netstack: true}); err == nil {
		e.Close()
		t.Fatal("accepted unavailable explicit port")
	}
}

func TestOrdinaryWireGuardTraffic(t *testing.T) {
	for _, underlay := range []string{"127.0.0.1", "::1"} {
		t.Run(underlay, func(t *testing.T) { ordinaryWireGuardTraffic(t, underlay) })
	}
}

func ordinaryWireGuardTraffic(t *testing.T, underlay string) {
	t.Helper()
	// This device uses the pinned wireguard-go fork's ordinary UDP bind and
	// UAPI, with no magicsock, disco, netmap or lazy peer callbacks.
	a := node{priv: key.NewNode(), addr: netip.MustParsePrefix("100.64.0.1/32")}
	b := node{priv: key.NewNode(), addr: netip.MustParsePrefix("100.64.0.2/32")}
	other := node{priv: key.NewNode(), addr: netip.MustParsePrefix("100.64.0.3/32")}
	// LocalPort is IPv4-only (see Start), and this UAPI device needs a named
	// return endpoint, so IPv6 uses an explicit port.
	if underlay == "::1" {
		a.port = freePort(t)
	}
	ch := tuntest.NewChannelTUN()
	wg := device.NewDevice(ch.TUN(), conn.NewDefaultBind(), &device.Logger{Errorf: t.Logf, Verbosef: t.Logf})
	defer wg.Close()
	psk := [32]byte{1, 2, 3}
	//lint:ignore SA1019 raw keys; see config.EncodeKey.
	if err := wg.IpcSet(fmt.Sprintf("private_key=%x\nlisten_port=0\npublic_key=%x\npreshared_key=%x\nallowed_ip=100.64.0.1/32\nallowed_ip=fd00::1/128\n", b.priv.Raw32(), a.priv.Public().Raw32(), psk)); err != nil {
		t.Fatal(err)
	}
	if err := wg.Up(); err != nil {
		t.Fatal(err)
	}
	status, err := wg.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(status, "\n") {
		if port, ok := strings.CutPrefix(line, "listen_port="); ok {
			n, err := strconv.ParseUint(port, 10, 16)
			if err != nil {
				t.Fatal(err)
			}
			b.port = uint16(n)
		}
	}
	if b.port == 0 {
		t.Fatal("plain device did not bind a port")
	}
	//lint:ignore SA1019 raw keys; see config.EncodeKey.
	plain := fmt.Sprintf("[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = 100.64.0.0/24, fd00::/64\nPresharedKey = %s\n", config.EncodeKey(b.priv.Public().Raw32()), net.JoinHostPort(underlay, fmt.Sprint(b.port)), config.EncodeKey(psk))
	cfg := a.parse(t, "Address = fd00::1/128", plain+other.peerSection(""))
	cfg.Peers[1].AllowedIPs = append(cfg.Peers[1].AllowedIPs, netip.MustParsePrefix("fd00::3/128"))
	e := startEcho(t, cfg)
	if !e.state.Load().nm.Peers[0].IsWireGuardOnly() || e.state.Load().nm.Peers[1].IsWireGuardOnly() {
		t.Fatal("mixed peer classification")
	}
	if payload := e.mc.PriorityMessageForPeer(b.priv.Public()); len(payload) != 0 {
		t.Fatal("ordinary peer received a TSMP advertisement")
	}
	//lint:ignore SA1019 raw keys; see config.EncodeKey.
	if err := wg.IpcSet(fmt.Sprintf("public_key=%x\nendpoint=%s\n", a.priv.Public().Raw32(), net.JoinHostPort(underlay, fmt.Sprint(e.mc.LocalPort())))); err != nil {
		t.Fatal(err)
	}
	for _, addrs := range [][2]string{{"100.64.0.1", "100.64.0.2"}, {"fd00::1", "fd00::2"}} {
		t.Run(addrs[0], func(t *testing.T) {
			src, dst := netip.MustParseAddr(addrs[0]), netip.MustParseAddr(addrs[1])
			forward := compatibilityPacket(src, dst, []byte("to ordinary peer"))
			if err := e.tun.InjectOutbound(forward); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			select {
			case got := <-ch.Inbound:
				if !bytes.Equal(got, forward) {
					t.Fatalf("ordinary peer got %x, want %x", got, forward)
				}
			case <-ctx.Done():
				t.Fatal("ordinary peer received no packet")
			}
			network := "udp4"
			if src.Is6() {
				network = "udp6"
			}
			listener, err := e.ns.ListenPacket(network, net.JoinHostPort(src.String(), "12345"))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			deadline, _ := ctx.Deadline()
			listener.SetReadDeadline(deadline)
			// A narrower discovery peer owns .3 / ::3, so a packet from
			// the ordinary peer with that source is dropped. Follow it
			// with a valid one.
			mismatched := other.addr.Addr()
			if src.Is6() {
				mismatched = netip.MustParseAddr("fd00::3")
			}
			select {
			case ch.Outbound <- compatibilityPacket(mismatched, src, []byte("mismatched")):
			case <-ctx.Done():
				t.Fatal("send mismatched source timed out")
			}
			select {
			case ch.Outbound <- compatibilityPacket(dst, src, []byte("from ordinary peer")):
			case <-ctx.Done():
				t.Fatal("send timed out")
			}
			buf := make([]byte, 128)
			n, _, err := listener.ReadFrom(buf)
			if err != nil {
				t.Fatal(err)
			}
			if string(buf[:n]) != "from ordinary peer" {
				t.Fatalf("received %q", buf[:n])
			}
		})
	}
}

func compatibilityPacket(src, dst netip.Addr, payload []byte) []byte {
	if src.Is4() {
		return packet.Generate(packet.UDP4Header{
			Src:     src,
			Dst:     dst,
			SrcPort: 12346,
			DstPort: 12345,
		}, payload)
	}
	return packet.Generate(packet.UDP6Header{
		Src:     src,
		Dst:     dst,
		SrcPort: 12346,
		DstPort: 12345,
	}, payload)
}

func TestOrdinaryPeerAdmission(t *testing.T) {
	for _, mode := range []string{"wrong-psk", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			a := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), freePort(t)}
			b := node{key.NewNode(), netip.MustParsePrefix("100.64.0.2/32"), freePort(t)}
			ac, bc := a.config(t, "", b, fmt.Sprintf("Endpoint = 127.0.0.1:%d", b.port)), b.config(t, "", a, fmt.Sprintf("Endpoint = 127.0.0.1:%d", a.port))
			for _, cfg := range []*config.Config{ac, bc} {
				cfg.Peers[0].DiscoKey = key.DiscoPublic{}
				cfg.Peers[0].PresharedKey[0] = 1
			}
			startEcho(t, bc)
			// This exact path must work before authentication changes, and the
			// sender is recreated so established sessions cannot mask denial.
			sender := func() *Engine {
				e, err := Start(ac, tstest.WhileTestRunningLogger(t), Options{Netstack: true})
				if err != nil {
					t.Fatal(err)
				}
				return e
			}
			target := netip.AddrPortFrom(b.addr.Addr(), testEchoPort)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			first := sender()
			err := dialRoundTripUntil(ctx, first, target)
			first.Close()
			if err != nil {
				t.Fatal("ordinary peer unavailable before admission test:", err)
			}
			if mode == "unknown" {
				ac.Interface.PrivateKey = key.NewNode()
			} else {
				ac.Peers[0].PresharedKey[0] = 2
			}
			second := sender()
			defer second.Close()
			denied(t, second, target, "unauthorized ordinary peer admitted")
		})
	}
}

func TestStagedOrdinaryPeer(t *testing.T) {
	a := node{priv: key.NewNode(), addr: netip.MustParsePrefix("100.64.0.1/32")}
	b := node{priv: key.NewNode(), addr: netip.MustParsePrefix("100.64.0.2/32")}
	//lint:ignore SA1019 raw keys; see config.EncodeKey.
	cfg := a.parse(t, "", fmt.Sprintf("[Peer]\nPublicKey = %s\nEndpoint = 127.0.0.1:12345\n", config.EncodeKey(b.priv.Public().Raw32())))
	e := startEcho(t, cfg)
	if peer, ok := e.peerConfig(b.priv.Public()); !ok || len(peer.AllowedIPs) != 0 {
		t.Fatalf("staged permissions: %+v, %v", peer, ok)
	}
	if _, ok := e.peerByIP(b.addr.Addr()); ok {
		t.Fatal("staged peer acquired a route")
	}
	//lint:ignore SA1019 raw keys; see config.EncodeKey.
	if got, err := e.Status("allowed-ips"); err != nil || got != config.EncodeKey(b.priv.Public().Raw32())+"\t(none)\n" {
		t.Fatalf("staged status: %q, %v", got, err)
	}
}

func TestReloadTransportMode(t *testing.T) {
	a := node{priv: key.NewNode(), addr: netip.MustParsePrefix("100.64.0.1/32")}
	b := node{priv: key.NewNode(), addr: netip.MustParsePrefix("100.64.0.2/32")}
	for _, plain := range []bool{false, true} {
		cfg := a.config(t, "", b, "Endpoint = 127.0.0.1:12345")
		if plain {
			cfg.Peers[0].DiscoKey = key.DiscoPublic{}
		}
		e := startEcho(t, cfg)
		old := e.state.Load()
		next := *cfg
		next.Peers = slices.Clone(cfg.Peers)
		if plain {
			next.Peers[0].DiscoKey = discokey.PublicForNode(b.priv)
		} else {
			next.Peers[0].DiscoKey = key.DiscoPublic{}
		}
		if err := e.Reload(&next); err == nil || !strings.Contains(err.Error(), "restart") {
			t.Fatalf("mode change: %v", err)
		}
		if e.state.Load() != old {
			t.Fatal("rejected mode change published state")
		}
	}
}
