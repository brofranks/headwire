package engine

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"brof.dev/headwire/internal/config"
	"brof.dev/headwire/internal/discokey"
	"tailscale.com/net/packet"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/wgcfg"
)

func TestSourceOwnership(t *testing.T) {
	a, b, c := key.NewNode().Public(), key.NewNode().Public(), key.NewNode().Public()
	peers := []config.Peer{
		{PublicKey: a, AllowedIPs: []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
			netip.MustParsePrefix("10.0.0.7/32"),
		}},
		{PublicKey: b, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("10.0.0.128/25")}},
		{PublicKey: c, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.128/25")}},
	}
	e := &Engine{}
	st, err := newState(&config.Config{
		Interface: config.Interface{
			PrivateKey: key.NewNode(),
			Addresses:  []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
		},
		Peers: peers,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.state.Store(st)
	for i := range 256 {
		ip := netip.AddrFrom4([4]byte{10, 0, 0, byte(i)})
		want := b
		if i == 7 {
			want = a
		} else if i >= 128 {
			want = c
		}
		for k, allowed := range st.allowed {
			if got := allowed.Contains(ip); got != (k == want) {
				t.Fatalf("source %s: peer %v allowed=%v", ip, k, got)
			}
		}
		if got, ok := e.peerByIP(ip); !ok || got != want {
			t.Fatalf("route %s: %v, %v; want %v", ip, got, ok, want)
		}
		if got, ok := e.peerForIP(ip); !ok || got.Node.Key() != want {
			t.Fatalf("node %s: %v, %v", ip, got, ok)
		}
	}
	if !st.allowed[a].Contains(netip.MustParseAddr("203.0.113.1")) {
		t.Fatal("default route lost addresses outside the narrower prefixes")
	}
	if got, ok := e.peerByIP(netip.MustParseAddr("fe80::1%eth0")); ok {
		t.Fatalf("zoned destination routed to %v", got)
	}
	if len(peers[0].AllowedIPs) != 3 || peers[0].AllowedIPs[0].Bits() != 0 {
		t.Fatal("configured prefixes were modified")
	}
}

func TestSourceOwnershipNestedPrefixes(t *testing.T) {
	a, b := key.NewNode().Public(), key.NewNode().Public()
	c, shadowed := key.NewNode().Public(), key.NewNode().Public()
	cfg := &config.Config{
		Interface: config.Interface{Addresses: []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("255.255.255.255/32"),
			netip.MustParsePrefix("::/0"),
			netip.MustParsePrefix("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"),
			netip.MustParsePrefix("192.0.2.65/24"),
			netip.MustParsePrefix("2001:db8::41/64"),
		}},
		Peers: []config.Peer{
			{PublicKey: a, AllowedIPs: []netip.Prefix{
				netip.MustParsePrefix("0.0.0.0/0"),
				netip.MustParsePrefix("::/0"),
				netip.MustParsePrefix("192.0.2.64/26"),
				netip.MustParsePrefix("2001:db8::40/122"),
				netip.MustParsePrefix("192.0.2.65/32"),
				netip.MustParsePrefix("2001:db8::41/128"),
			}},
			{PublicKey: b, AllowedIPs: []netip.Prefix{
				netip.MustParsePrefix("192.0.2.0/24"),
				netip.MustParsePrefix("2001:db8::/120"),
			}},
			{PublicKey: shadowed, AllowedIPs: []netip.Prefix{
				netip.MustParsePrefix("192.0.2.128/25"),
				netip.MustParsePrefix("2001:db8::80/121"),
			}},
			{PublicKey: c, AllowedIPs: []netip.Prefix{
				netip.MustParsePrefix("192.0.2.129/25"),
				netip.MustParsePrefix("2001:db8::81/121"),
			}},
		},
	}
	sets, err := sourcePermissions(cfg)
	if err != nil {
		t.Fatal(err)
	}
	check := func(ip netip.Addr, want key.NodePublic) {
		t.Helper()
		for k, set := range sets {
			if set.Contains(ip) != (k == want) {
				t.Fatalf("incorrect owner for %s: peer %s", ip, k.ShortString())
			}
		}
	}
	ipv6 := netip.MustParseAddr("2001:db8::").As16()
	for i := range 256 {
		want := b
		if i == 65 {
			want = key.NodePublic{}
		} else if i >= 128 {
			want = c
		} else if i >= 64 {
			want = a
		}
		check(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), want)
		ipv6[15] = byte(i)
		check(netip.AddrFrom16(ipv6), want)
	}
	for _, address := range []string{
		"0.0.0.1", "255.255.255.254", "::1",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe",
	} {
		check(netip.MustParseAddr(address), a)
	}
	for _, prefix := range cfg.Interface.Addresses {
		check(prefix.Addr(), key.NodePublic{})
	}
	if set := sets[shadowed]; set == nil || len(set.Ranges()) != 0 {
		t.Fatal("fully shadowed peer did not retain an empty source set")
	}
	withoutSelf := *cfg
	withoutSelf.Interface.Addresses = nil
	sets, err = sourcePermissions(&withoutSelf)
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range cfg.Interface.Addresses {
		check(prefix.Addr(), a)
	}
}

func sparseOwnershipConfig(tb testing.TB, n int) *config.Config {
	tb.Helper()
	cfg := &config.Config{Peers: []config.Peer{{PublicKey: key.NewNode().Public()}}}
	for i := range n {
		cfg.Peers[0].AllowedIPs = append(cfg.Peers[0].AllowedIPs,
			netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}), 32))
	}
	return cfg
}

func TestSourceOwnershipSparsePrefixes(t *testing.T) {
	cfg := sparseOwnershipConfig(t, 4096)
	sets, err := sourcePermissions(cfg)
	if err != nil {
		t.Fatal(err)
	}
	set := sets[cfg.Peers[0].PublicKey]
	if got := len(set.Ranges()); got != len(cfg.Peers[0].AllowedIPs) {
		t.Fatalf("got %d source ranges, want %d", got, len(cfg.Peers[0].AllowedIPs))
	}
	for _, prefix := range cfg.Peers[0].AllowedIPs {
		ip := prefix.Addr()
		if !set.Contains(ip) || set.Contains(ip.Prev()) || set.Contains(ip.Next()) {
			t.Fatalf("incorrect sparse source range for %s", ip)
		}
	}
}

func BenchmarkSourceOwnershipSparse(b *testing.B) {
	for _, n := range []int{128, 1024, 4096} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			cfg := sparseOwnershipConfig(b, n)
			b.ReportAllocs()
			for b.Loop() {
				if _, err := sourcePermissions(cfg); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestPeerForIPConcurrentSnapshots(t *testing.T) {
	e := &Engine{}
	self := node{priv: key.NewNode(), addr: netip.MustParsePrefix("100.64.0.1/32"), port: 51820}
	peer := node{priv: key.NewNode(), addr: netip.MustParsePrefix("100.64.0.2/32")}
	var states []*state
	for range 2 {
		st, err := newState(self.config(t, "", peer, ""), nil)
		if err != nil {
			t.Fatal(err)
		}
		states = append(states, st)
		peer.priv = key.NewNode()
	}
	empty, err := newState(self.parse(t, "", ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	states = append(states, empty)
	e.state.Store(states[0])
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
				e.state.Store(states[i%len(states)])
			}
		}
	})
	defer func() { close(done); wg.Wait() }()
	for range 10000 {
		if got, ok := e.peerForIP(peer.addr.Addr()); ok && !got.Node.Valid() {
			t.Fatal("lookup returned an invalid peer")
		}
		if got, ok := e.peerForIP(self.addr.Addr()); !ok || !got.IsSelf {
			t.Fatal("self lookup failed")
		}
		if _, ok := e.peerForIP(netip.MustParseAddr("192.0.2.1")); ok {
			t.Fatal("unknown address matched")
		}
	}
}

func TestReloadSourceOwnership(t *testing.T) {
	r := node{priv: key.NewNode(), addr: netip.MustParsePrefix("100.64.0.1/32"), port: 51820}
	a := node{priv: key.NewNode(), addr: netip.MustParsePrefix("100.64.0.0/24")}
	b := node{priv: key.NewNode(), addr: netip.MustParsePrefix("100.64.0.2/32")}
	for _, tc := range []struct {
		name, before, after string
		reject              bool
	}{
		{"removal", a.peerSection(""), "", true},
		{"reduction", a.peerSection(""), strings.ReplaceAll(a.peerSection(""), "/24", "/25"), true},
		{"more specific owner", a.peerSection(""), a.peerSection("") + b.peerSection(""), true},
		{"owner removed", a.peerSection("") + b.peerSection(""), a.peerSection(""), true},
		{"equal prefix transfer", a.peerSection(""), a.peerSection("") + strings.ReplaceAll(b.peerSection(""), b.addr.String(), a.addr.String()), true},
		{"expansion", a.peerSection(""), strings.ReplaceAll(a.peerSection(""), "/24", "/23"), true},
		{"redundant prefix", a.peerSection(""), strings.ReplaceAll(a.peerSection(""), a.addr.String(), a.addr.String()+", 100.64.0.2/32"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &Engine{}
			before, err := newState(r.parse(t, "", tc.before), nil)
			if err != nil {
				t.Fatal(err)
			}
			e.state.Store(before)
			cfg := r.parse(t, "", tc.after)
			after, err := newState(cfg, before.ids)
			if err != nil {
				t.Fatal(err)
			}
			err = before.checkSourceOwnership(after)
			if (err != nil) != tc.reject {
				t.Fatalf("ownership check: %v", err)
			}
			if tc.reject {
				// No engine is installed: refusal must precede all
				// engine mutations.
				if err := e.Reload(cfg); err == nil || !strings.Contains(err.Error(), "restart") {
					t.Fatalf("Reload: %v", err)
				}
				if e.state.Load() != before {
					t.Fatal("rejected reload changed live state")
				}
			}
		})
	}
}

// sourceProbe listens for UDP inside dst's stack. The returned send
// injects a packet from src into sender's TUN carrying src as its payload,
// and received reports the first source that reached the stack.
func sourceProbe(
	ctx context.Context,
	t *testing.T,
	target, sender *testNode,
	dst netip.Addr,
) (send func(netip.Addr), received func() string) {
	t.Helper()
	listener := target.stack.listenUDP(t, netip.AddrPortFrom(dst, 12345))
	deadline, _ := ctx.Deadline()
	if err := listener.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	return func(src netip.Addr) {
			t.Helper()
			pkt := packet.Generate(packet.UDP4Header{
				Src: src, Dst: dst, SrcPort: 12346, DstPort: 12345,
			}, []byte(src.String()))
			if err := sender.tun.InjectOutbound(pkt); err != nil {
				t.Fatal(err)
			}
		}, func() string {
			t.Helper()
			buf := make([]byte, 128)
			n, _, err := listener.ReadFrom(buf)
			if err != nil {
				t.Fatal(err)
			}
			return string(buf[:n])
		}
}

func TestOverlappingAllowedIPsSourceMatch(t *testing.T) {
	r := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), freePort(t)}
	other := node{key.NewNode(), netip.MustParsePrefix("100.64.0.2/32"), freePort(t)}
	sender := node{key.NewNode(), netip.MustParsePrefix("100.64.0.3/32"), freePort(t)}
	cfg := r.parse(t, "", other.peerSection("")+sender.peerSection(""))
	// A default route covers the other peer and this node's own address alike.
	cfg.Peers[1].AllowedIPs = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	er := startEcho(t, cfg)
	ea := startEcho(t, sender.config(t, "", r, fmt.Sprintf("Endpoint = 127.0.0.1:%d", r.port)))
	warm(t, ea.Engine, er.Engine)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := dialRoundTripUntil(ctx, ea, netip.AddrPortFrom(r.addr.Addr(), testEchoPort)); err != nil {
		t.Fatal(err)
	}
	send, received := sourceProbe(ctx, t, er, ea, r.addr.Addr())
	for _, src := range []netip.Addr{other.addr.Addr(), r.addr.Addr(), sender.addr.Addr()} {
		send(src)
	}
	if got := received(); got != sender.addr.Addr().String() {
		t.Fatalf("unexpected source reached receiving stack: %s", got)
	}
}

func TestReloadRejectsRevocationDuringPeerCreation(t *testing.T) {
	r := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), freePort(t)}
	other := node{key.NewNode(), netip.MustParsePrefix("100.64.0.2/32"), freePort(t)}
	sender := node{key.NewNode(), netip.MustParsePrefix("100.64.0.3/32"), freePort(t)}
	cfg := r.config(t, "", sender, "")
	cfg.Peers[0].AllowedIPs = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/24")}
	er := startEcho(t, cfg)
	captured, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	notify := sync.OnceFunc(func() { close(captured) })
	er.eng.SetPeerConfigFunc(func(k key.NodePublic) (wgcfg.PeerConfig, bool) {
		conf, ok := er.peerConfig(k)
		if k == sender.priv.Public() && slices.ContainsFunc(conf.AllowedIPs, func(p netip.Prefix) bool { return p.Contains(other.addr.Addr()) }) {
			notify()
			<-release // model preemption after the old config was captured
		}
		return conf, ok
	})
	ea := startEcho(t, sender.config(t, "", r, fmt.Sprintf("Endpoint = 127.0.0.1:%d", r.port)))
	warm(t, ea.Engine, er.Engine)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	send, received := sourceProbe(ctx, t, er, ea, r.addr.Addr())
	send(other.addr.Addr())
	select {
	case <-captured:
	case <-ctx.Done():
		t.Fatal("lazy peer creation did not start:", ctx.Err())
	}
	next := *cfg
	next.Peers = append([]config.Peer{}, cfg.Peers...)
	next.Peers = append(next.Peers, config.Peer{
		PublicKey:  other.priv.Public(),
		DiscoKey:   discokey.PublicForNode(other.priv),
		AllowedIPs: []netip.Prefix{other.addr},
	})
	before := er.state.Load()
	if err := er.Reload(&next); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("Reload: %v", err)
	}
	if er.state.Load() != before {
		t.Fatal("rejected reload changed live state")
	}
	unblock()
	send(sender.addr.Addr())
	// The rejected transfer leaves the original /24 owner authorized.
	if got := received(); got != other.addr.Addr().String() {
		t.Fatalf("original permissions changed: %s", got)
	}
}

func TestIPv6SourceOwnership(t *testing.T) {
	a, b, c := key.NewNode().Public(), key.NewNode().Public(), key.NewNode().Public()
	peers := []config.Peer{
		{PublicKey: a, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("::/0"), netip.MustParsePrefix("0.0.0.0/0")}},
		{PublicKey: b, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("fd00::/64")}},
		{PublicKey: c, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("fd00::7/128"), netip.MustParsePrefix("fd00::/64")}},
	}
	// This node's own addresses belong to no peer, whatever covers them.
	self := config.Interface{Addresses: []netip.Prefix{
		netip.MustParsePrefix("192.0.2.9/24"),
		netip.MustParsePrefix("fd00::9/64"),
	}}
	sets, err := sourcePermissions(&config.Config{Interface: self, Peers: peers})
	if err != nil {
		t.Fatal(err)
	}
	for address, want := range map[string]key.NodePublic{"fd00::7": c, "fd00::8": c, "2001:db8::1": a, "192.0.2.1": a, "192.0.2.9": {}, "fd00::9": {}} {
		for k, set := range sets {
			if set.Contains(netip.MustParseAddr(address)) != (k == want) {
				t.Fatalf("incorrect owner for %s", address)
			}
		}
	}
	st := &state{cfg: &config.Config{Peers: peers}, allowed: sets}
	reduced := append([]config.Peer(nil), peers...)
	reduced[2].AllowedIPs = []netip.Prefix{netip.MustParsePrefix("fd00::7/128")}
	after, err := sourcePermissions(&config.Config{Interface: self, Peers: reduced})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.checkSourceOwnership(&state{allowed: after}); err == nil {
		t.Fatal("allowed IPv6 revocation")
	}
}

func TestReloadPresharedKeyRequiresRestart(t *testing.T) {
	self := node{priv: key.NewNode(), addr: netip.MustParsePrefix("100.64.0.1/32")}
	peer := node{priv: key.NewNode(), addr: netip.MustParsePrefix("100.64.0.2/32")}
	before, err := newState(self.config(t, "", peer, ""), nil)
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{}
	e.state.Store(before)
	next := self.config(t, "", peer, "")
	next.Peers[0].PresharedKey[0] = 1
	if err := e.Reload(next); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("PresharedKey change: %v", err)
	}
	if e.state.Load() != before {
		t.Fatal("rejected reload changed state")
	}
}
