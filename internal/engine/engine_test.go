package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"brof.dev/headwire/internal/config"
	"brof.dev/headwire/internal/discokey"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"
)

// node is one side of a two-node test: its key material and a config
// builder that names the other side as its single peer.
type node struct {
	priv key.NodePrivate
	addr netip.Prefix
	port uint16
}

func (n node) peerSection(mode string) string {
	return fmt.Sprintf("[Peer]\nPublicKey = %s\nDiscoKey = %s\nAllowedIPs = %s\n%s\n",
		//lint:ignore SA1019 raw keys; see config.EncodeKey.
		config.EncodeKey(n.priv.Public().Raw32()),
		//lint:ignore SA1019 raw keys; see config.EncodeKey.
		config.EncodeKey(discokey.PublicForNode(n.priv).Raw32()),
		n.addr, mode)
}

func (n node) config(
	t *testing.T,
	interfaceExtra string,
	peer node,
	peerMode string,
) *config.Config {
	t.Helper()
	return n.parse(t, interfaceExtra, peer.peerSection(peerMode))
}

func (n node) parse(t *testing.T, interfaceExtra, peers string) *config.Config {
	t.Helper()
	src := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\nListenPort = %d\n%s\n%s",
		config.EncodeKey(n.priv.Raw32()), n.addr, n.port, interfaceExtra, peers)
	cfg, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse:\n%s\n%v", src, err)
	}
	return cfg
}

// lastPort is the port freePort handed out most recently. Every test in this
// package runs in the same process and none calls t.Parallel, so a plain
// counter is enough.
var lastPort uint16 = 20000

// freePort returns a free UDP port below the range the kernel allocates
// ephemeral ports from, so that nothing the kernel assigns on its own can take
// the port between this probe and the engine's bind. It probes the wildcard
// address, which is the one magicsock binds.
func freePort(t *testing.T) uint16 {
	t.Helper()
	for range 1000 {
		lastPort++
		c, err := net.ListenPacket("udp4", fmt.Sprintf(":%d", lastPort))
		if err != nil {
			continue
		}
		c.Close()
		return lastPort
	}
	t.Fatal("no free UDP port below the ephemeral range")
	return 0
}

// dualStack gives both nodes an IPv6 overlay address and routes it to the
// other.
func dualStack(ac, bc *config.Config) {
	ac.Interface.Addresses = append(ac.Interface.Addresses, netip.MustParsePrefix("fd00::1/128"))
	bc.Interface.Addresses = append(bc.Interface.Addresses, netip.MustParsePrefix("fd00::2/128"))
	ac.Peers[0].AllowedIPs = append(ac.Peers[0].AllowedIPs, bc.Interface.Addresses[1])
	bc.Peers[0].AllowedIPs = append(bc.Peers[0].AllowedIPs, ac.Interface.Addresses[1])
}

func TestFixedAndPassiveRoundTrip(t *testing.T) {
	a := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), freePort(t)}
	b := node{key.NewNode(), netip.MustParsePrefix("100.64.0.2/32"), freePort(t)}
	// DNS is configured but, without a kernel TUN, applied nowhere.
	ac := a.config(t, "DNS = 100.64.0.53, corp.example", b, fmt.Sprintf("Endpoint = 127.0.0.1:%d", b.port))
	bc := b.config(t, "", a, "") // passive
	dualStack(ac, bc)
	startEcho(t, bc)
	ea := startEcho(t, ac)
	// No warm: this is the one round trip that proves a cold path converges.

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, address := range bc.Interface.Addresses {
		if err := dialRoundTripUntil(ctx, ea, netip.AddrPortFrom(address.Addr(), testEchoPort)); err != nil {
			t.Fatal(err)
		}
	}
	st := ea.peerStatus(b.priv.Public())
	if st == nil || st.CurAddr == "" {
		t.Fatalf("no direct path to passive peer: %+v", st)
	}
	t.Logf("direct path %s", st.CurAddr)

	pong, err := ea.Status("ping " + b.addr.Addr().String())
	if err != nil || !strings.HasPrefix(pong, fmt.Sprintf("pong from %s via 127.0.0.1:%d in ", b.addr.Addr(), b.port)) {
		t.Fatalf("ping = %q, %v", pong, err)
	}
	for ip, want := range map[string]string{"100.64.0.1": "local address", "100.64.0.9": "AllowedIPs", "bogus": "unable to parse"} {
		if _, err := ea.Status("ping " + ip); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ping %s: err = %v, want %q", ip, err, want)
		}
	}
}

// TestMasqueradeAddress gives A an exit peer B that knows A only by a
// masquerade address and a mesh peer C that knows A's interface address. Each
// drops the other source, and A's stack accepts replies only to its own
// address, so the round trips establish both rewrites and that B's default
// route does not masquerade traffic to C. The field is installed at startup
// or arrives by reload, with either or both overlay address families.
// Reciprocal ordinary WireGuard endpoints isolate translation from discovery.
func TestMasqueradeAddress(t *testing.T) {
	for _, tc := range []struct {
		name, a, b, c, masq, defaults string
	}{
		{"ipv4", "10.77.0.1/32", "100.64.0.2/32", "10.77.0.3/32", "10.69.0.5", "0.0.0.0/0"},
		{"ipv6", "fd77::1/128", "fd64::2/128", "fd77::3/128", "fd69::5", "::/0"},
		{"dual", "10.77.0.1/32, fd77::1/128", "100.64.0.2/32, fd64::2/128", "10.77.0.3/32, fd77::3/128", "10.69.0.5, fd69::5", "0.0.0.0/0, ::/0"},
	} {
		for _, install := range []string{"startup", "reload"} {
			t.Run(tc.name+"/"+install, func(t *testing.T) {
				a, b, c := key.NewNode(), key.NewNode(), key.NewNode()
				aPort := freePort(t)
				parse := func(priv key.NodePrivate, addresses string, port uint16, peers string) *config.Config {
					t.Helper()
					cfg, err := config.Parse(fmt.Appendf(nil, "[Interface]\nPrivateKey = %s\nAddress = %s\nListenPort = %d\n%s",
						config.EncodeKey(priv.Raw32()), addresses, port, peers))
					if err != nil {
						t.Fatal(err)
					}
					return cfg
				}
				peer := func(priv key.NodePrivate, allowed, extra string) string {
					return fmt.Sprintf("[Peer]\nPublicKey = %s\nAllowedIPs = %s\n%s\n",
						//lint:ignore SA1019 raw keys; see config.EncodeKey.
						config.EncodeKey(priv.Public().Raw32()), allowed, extra)
				}
				var translated []string
				for addr := range strings.SplitSeq(tc.masq, ", ") {
					ip := netip.MustParseAddr(addr)
					translated = append(translated, netip.PrefixFrom(ip, ip.BitLen()).String())
				}
				eb := startEcho(t, parse(b, tc.b, 0, peer(a, strings.Join(translated, ", "), fmt.Sprintf("Endpoint = 127.0.0.1:%d", aPort))))
				ec := startEcho(t, parse(c, tc.c, 0, peer(a, tc.a, fmt.Sprintf("Endpoint = 127.0.0.1:%d", aPort))))
				peers := func(masq string) string {
					return peer(b, tc.defaults, fmt.Sprintf("Endpoint = 127.0.0.1:%d\n%s", eb.mc.LocalPort(), masq)) +
						peer(c, tc.c, fmt.Sprintf("Endpoint = 127.0.0.1:%d", ec.mc.LocalPort()))
				}
				cfg := parse(a, tc.a, aPort, peers("MasqueradeAddress = "+tc.masq))
				initial := cfg
				if install == "reload" {
					initial = parse(a, tc.a, aPort, peers(""))
				}
				ea := startEcho(t, initial)
				if install == "reload" {
					if err := ea.Reload(cfg); err != nil {
						t.Fatal(err)
					}
				}
				for target := range strings.SplitSeq(tc.b+", "+tc.c, ", ") {
					t.Run(target, func(t *testing.T) {
						ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
						defer cancel()
						if err := dialRoundTripUntil(ctx, ea, netip.AddrPortFrom(netip.MustParsePrefix(target).Addr(), testEchoPort)); err != nil {
							t.Fatal(err)
						}
					})
				}
			})
		}
	}
}

// TestReloadAddsPeer starts A with no peers, reloads B in, round-trips,
// then checks that removing B requires restart and leaves B live.
func TestReloadAddsPeer(t *testing.T) {
	a := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), freePort(t)}
	b := node{key.NewNode(), netip.MustParsePrefix("100.64.0.2/32"), freePort(t)}
	eb := startEcho(t, b.config(t, "", a, "")) // passive
	ea := startEcho(t, a.parse(t, "", ""))
	if _, ok := ea.peerConfig(b.priv.Public()); ok {
		t.Fatal("peer present before reload")
	}

	if err := ea.Reload(a.config(t, "", b, fmt.Sprintf("Endpoint = 127.0.0.1:%d", b.port))); err != nil {
		t.Fatal(err)
	}
	warm(t, ea.Engine, eb.Engine)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := dialRoundTripUntil(ctx, ea, netip.AddrPortFrom(b.addr.Addr(), testEchoPort)); err != nil {
		t.Fatal(err)
	}
	text, _ := ea.Status("")
	if !strings.HasPrefix(text, "interface: hwtest\n") {
		t.Fatalf("status did not use the engine's interface name:\n%s", text)
	}
	//lint:ignore SA1019 raw keys; see config.EncodeKey.
	if !strings.Contains(text, "peer: "+config.EncodeKey(b.priv.Public().Raw32())) || !strings.Contains(text, "allowed ips: "+b.addr.String()) {
		t.Fatalf("status text lacks peer:\n%s", text)
	}
	dump, _ := ea.Status("dump")
	if lines := strings.Split(strings.TrimSpace(dump), "\n"); len(lines) != 2 || strings.Count(lines[1], "\t") != 7 {
		t.Fatalf("bad dump:\n%s", dump)
	}
	if ips, _ := ea.Status("allowed-ips"); !strings.HasSuffix(strings.TrimSpace(ips), "\t"+b.addr.String()) {
		t.Fatalf("bad allowed-ips: %q", ips)
	}
	if _, err := ea.Status("nope"); err == nil {
		t.Fatal("Status accepted an unknown field")
	}

	if err := ea.Reload(a.parse(t, "", "")); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("peer removal should require restart: %v", err)
	}
	if _, ok := ea.peerConfig(b.priv.Public()); !ok {
		t.Fatal("rejected reload removed the peer")
	}
	if err := dialRoundTripUntil(ctx, ea, netip.AddrPortFrom(b.addr.Addr(), testEchoPort)); err != nil {
		t.Fatalf("rejected reload broke traffic: %v", err)
	}
	if err := ea.Reload(a.parse(t, "HomeDERP = 1\n[DERPRegion]\nID = 1\nNodes = derp1.example.com\n", "")); err == nil {
		t.Fatal("reload accepted an [Interface]/[DERPRegion] change")
	}

	// A changed DiscoKey is the peer restarting under a new identity, and a
	// peer that owns no addresses is the one removal that revokes nothing.
	cfg := a.config(t, "", b, fmt.Sprintf("Endpoint = 127.0.0.1:%d", b.port))
	cfg.Peers[0].DiscoKey = discokey.PublicForNode(key.NewNode())
	cfg.Peers = append(cfg.Peers, config.Peer{PublicKey: key.NewNode().Public(), Endpoint: "127.0.0.1:1"})
	if err := ea.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	if err := ea.Reload(a.config(t, "", b, fmt.Sprintf("Endpoint = 127.0.0.1:%d", b.port))); err != nil {
		t.Fatalf("removing a peer without AllowedIPs: %v", err)
	}
	if len(ea.state.Load().peers) != 1 {
		t.Fatal("peer without AllowedIPs not removed")
	}
}

func TestReloadDERPConfiguration(t *testing.T) {
	a := node{priv: key.NewNode(), addr: netip.MustParsePrefix("100.64.0.1/32")}
	region := "HomeDERP = 1\n[DERPRegion]\nID = 1\nNodes = first.example\n"
	// Exercise region comparison without selecting a home relay or
	// contacting it. Rejection must precede engine mutations, so no running
	// engine is needed.
	e := &Engine{netMon: netmon.NewStatic()}
	e.state.Store(&state{cfg: a.parse(t, region, "")})
	before := e.state.Load()
	if err := e.Reload(a.parse(t, strings.ReplaceAll(region, "first.example", "second.example"), "")); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("region change should require restart: %v", err)
	}
	if e.state.Load() != before {
		t.Fatal("rejected region change published state")
	}
}

func TestPingTimeout(t *testing.T) {
	a := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), freePort(t)}
	b := node{key.NewNode(), netip.MustParsePrefix("100.64.0.2/32"), 0}
	// Keep the endpoint bound but unanswered for a deterministic probe timeout.
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ea := startEcho(t, a.config(t, "", b, "Endpoint = "+conn.LocalAddr().String()))
	reply, err := ea.Status("ping 100.64.0.2")
	if err != nil || reply != "ping 100.64.0.2 timed out\n" {
		t.Fatalf("timeout = %q, %v", reply, err)
	}
}

// pingEngine answers every disco ping with one prepared result.
type pingEngine struct {
	wgengine.Engine
	res *ipnstate.PingResult
}

func (e pingEngine) Ping(
	ip netip.Addr,
	pingType tailcfg.PingType,
	size int,
	cb func(*ipnstate.PingResult),
) {
	cb(e.res)
}

func TestPingResults(t *testing.T) {
	a := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), 0}
	b := node{key.NewNode(), netip.MustParsePrefix("100.64.0.2/32"), 0}
	c := node{key.NewNode(), netip.MustParsePrefix("100.64.0.3/32"), 0}
	cfg := a.parse(t, "", b.peerSection("")+fmt.Sprintf("[Peer]\nPublicKey = %s\nAllowedIPs = %s\nEndpoint = 127.0.0.1:1\n",
		//lint:ignore SA1019 raw keys; see config.EncodeKey.
		config.EncodeKey(c.priv.Public().Raw32()), c.addr))
	st, err := newState(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{}
	e.state.Store(st)
	for _, tc := range []struct {
		ip   string
		res  *ipnstate.PingResult
		want string
	}{
		{"100.64.0.9", nil, "no peer's AllowedIPs contain 100.64.0.9"},
		{"100.64.0.1", nil, "100.64.0.1 is a local address"},
		{"100.64.0.3", nil, "peer has no DiscoKey, use ping(8)"},
		{"100.64.0.2", &ipnstate.PingResult{Err: "no path"}, "no path"},
		{"100.64.0.2", &ipnstate.PingResult{DERPRegionID: 1, LatencySeconds: 0.0104}, "pong from 100.64.0.2 via relay:1 in 10ms\n"},
		{"100.64.0.2", &ipnstate.PingResult{Endpoint: "127.0.0.1:2", LatencySeconds: 0.001}, "pong from 100.64.0.2 via 127.0.0.1:2 in 1ms\n"},
	} {
		e.eng = pingEngine{res: tc.res}
		reply, err := e.Ping(netip.MustParseAddr(tc.ip))
		if err != nil {
			reply = err.Error()
		}
		if reply != tc.want {
			t.Errorf("ping %s = %q, want %q", tc.ip, reply, tc.want)
		}
	}
	// An empty status records no endpoints.
	e.onStatus(&wgengine.Status{}, nil)
	if len(e.eps) != 0 {
		t.Fatal("empty status recorded endpoints")
	}
}

// peerStatus returns one peer's status. CurAddr is an observed direct path.
// Relay names the configured DERP region, not proof of relay activity, which
// `show` infers from a live session with no direct path.
func (e *Engine) peerStatus(pub key.NodePublic) *ipnstate.PeerStatus {
	return e.status().Peer[pub]
}

// TestInterfaceSubnetRoutedNotLocal pins the split between the addresses the
// node owns and the subnets the host routes into the tunnel: a configured
// prefix must not make every address inside it look like this node's own, or
// darwin loops peer traffic back into the host.
func TestInterfaceSubnetRoutedNotLocal(t *testing.T) {
	self, peer := key.NewNode(), key.NewNode()
	src := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.99.0.1/24, fd00::1/128

[Peer]
PublicKey = %s
AllowedIPs = 10.99.0.2/32
Endpoint = 192.0.2.1:51820
`,
		config.EncodeKey(self.Raw32()),
		//lint:ignore SA1019 raw keys; see config.EncodeKey.
		config.EncodeKey(peer.Public().Raw32()))
	cfg, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse:\n%s\n%v", src, err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("10.99.0.1/32"), netip.MustParsePrefix("fd00::1/128")}
	if got := hostAddrs(cfg.Interface.Addresses); !slices.Equal(got, want) {
		t.Errorf("hostAddrs = %v, want %v", got, want)
	}
	wantRoutes := []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24"), netip.MustParsePrefix("10.99.0.2/32")}
	if got := Routes(cfg); !slices.Equal(got, wantRoutes) {
		t.Errorf("Routes = %v, want %v", got, wantRoutes)
	}
}

type failedRouterEngine struct{ wgengine.Engine }

func (e failedRouterEngine) Reconfig(*wgcfg.Config, *router.Config, *dns.Config) error {
	return errors.New("injected route application failure")
}

func TestReloadApplyFailure(t *testing.T) {
	a := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), freePort(t)}
	b := node{key.NewNode(), netip.MustParsePrefix("100.64.0.2/32"), freePort(t)}
	e := startEcho(t, a.parse(t, "", ""))
	e.eng = failedRouterEngine{e.eng}
	err := e.Reload(a.config(t, "", b, ""))
	if _, ok := errors.AsType[*ReloadApplyError](err); !ok {
		t.Fatalf("apply failure must require teardown: %v", err)
	}
	if _, ok := e.peerConfig(b.priv.Public()); !ok {
		t.Fatal("test did not exercise failure after publication")
	}
}

func TestAddsTunnelIPv6(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interface.Addresses = []netip.Prefix{netip.MustParsePrefix("fd42::1/64")}
	if !addsTunnelIPv6(nil, cfg) {
		t.Fatal("startup needs IPv6 for the interface address")
	}
	next := &config.Config{
		Interface: cfg.Interface,
		Peers: []config.Peer{{
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("fd42::/64")},
		}},
	}
	if addsTunnelIPv6(cfg, next) {
		t.Fatal("the peer's IPv6 route is already installed for the interface")
	}
	next.Peers[0].AllowedIPs = append(next.Peers[0].AllowedIPs, netip.MustParsePrefix("fd42::2/128"))
	if !addsTunnelIPv6(cfg, next) {
		t.Fatal("a more specific IPv6 route still requires installation")
	}
}

func TestIPv4OnlyRouteComparisonAllocations(t *testing.T) {
	cfg := &config.Config{Peers: []config.Peer{{
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}}}
	allocs := testing.AllocsPerRun(10, func() {
		if addsTunnelIPv6(cfg, cfg) {
			t.Fatal("IPv4-only reload reported a new IPv6 route")
		}
	})
	if allocs != 0 {
		t.Fatalf("IPv4-only route comparison allocated %v times, want 0", allocs)
	}
}

func TestReloadPreservesSession(t *testing.T) {
	r := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), freePort(t)}
	a := node{key.NewNode(), netip.MustParsePrefix("100.64.0.2/32"), freePort(t)}
	b := node{key.NewNode(), netip.MustParsePrefix("100.64.0.3/32"), freePort(t)}
	er := startEcho(t, r.config(t, "", a, fmt.Sprintf("Endpoint = 127.0.0.1:%d", a.port)))
	ea := startEcho(t, a.config(t, "", r, fmt.Sprintf("Endpoint = 127.0.0.1:%d", r.port)))
	warm(t, ea.Engine, er.Engine)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := ea.stack.dialTCP(ctx, netip.AddrPortFrom(r.addr.Addr(), testEchoPort))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	deadline, _ := ctx.Deadline()
	if err := c.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	exchange := func(s string) {
		t.Helper()
		if _, err := c.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, len(s))
		if _, err := io.ReadFull(c, b); err != nil || string(b) != s {
			t.Fatalf("persistent stream: %q, %v", b, err)
		}
	}
	exchange("before")
	handshake := ea.peerStatus(r.priv.Public()).LastHandshake
	if err := er.Reload(r.parse(t, "", a.peerSection(fmt.Sprintf("Endpoint = 127.0.0.1:%d", a.port))+b.peerSection(""))); err != nil {
		t.Fatal(err)
	}
	exchange("after")
	if got := ea.peerStatus(r.priv.Public()).LastHandshake; !got.Equal(handshake) {
		t.Fatal("additive reload replaced the established session")
	}
}

// TestPresetAddrs checks that a peer's preset Addrs reach its node without a
// lookup, which name.invalid would fail, and that the state keeps them.
func TestPresetAddrs(t *testing.T) {
	k := key.NewNode()
	addrs := []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.1:51820"),
		netip.MustParseAddrPort("[2001:db8::1]:51820"),
	}
	cfg := &config.Config{
		Interface: config.Interface{PrivateKey: key.NewNode()},
		Peers: []config.Peer{{
			PublicKey: k.Public(),
			DiscoKey:  discokey.PublicForNode(k),
			Endpoint:  "name.invalid:51820",
			Addrs:     addrs,
		}},
	}
	st, err := newState(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.nodes[k.Public()].Endpoints().AsSlice(); !slices.Equal(got, addrs) {
		t.Fatalf("endpoints = %v, want %v", got, addrs)
	}
	if got := st.cfg.Peers[0].Addrs; !slices.Equal(got, addrs) {
		t.Fatalf("state addrs = %v, want %v", got, addrs)
	}
}

func TestEndpoints(t *testing.T) {
	k := key.NewNode()
	v4 := netip.MustParseAddrPort("192.0.2.1:7")
	v6 := netip.MustParseAddrPort("[2001:db8::1]:7")
	both := []netip.AddrPort{v6, v4}
	discovery := config.Peer{PublicKey: k.Public(), DiscoKey: discokey.PublicForNode(k), Addrs: both}
	for _, tt := range []struct {
		peer config.Peer
		ifs  *netmon.State
		want []netip.AddrPort
	}{
		{config.Peer{Addrs: both}, nil, both[:1]},
		{config.Peer{Addrs: both}, &netmon.State{}, both[:1]},
		{config.Peer{Addrs: both}, &netmon.State{HaveV4: true, HaveV6: true}, both[:1]},
		{config.Peer{Addrs: both}, &netmon.State{HaveV4: true}, []netip.AddrPort{v4}},
		{config.Peer{Addrs: both}, &netmon.State{HaveV6: true}, []netip.AddrPort{v6}},
		{config.Peer{Addrs: []netip.AddrPort{v6}}, &netmon.State{HaveV4: true}, []netip.AddrPort{v6}},
		{config.Peer{}, &netmon.State{HaveV4: true}, nil},
		{discovery, &netmon.State{HaveV4: true}, both},
	} {
		if got := endpoints(tt.peer, tt.ifs); !slices.Equal(got, tt.want) {
			t.Errorf("endpoints(%v, %v) = %v, want %v", tt.peer.Addrs, tt.ifs, got, tt.want)
		}
	}
}

// TestRepick checks that a network change moves an ordinary peer to an
// address in a family the host has, without a lookup, and that the session
// survives the move and the move back.
func TestRepick(t *testing.T) {
	r := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), freePort(t)}
	a := node{key.NewNode(), netip.MustParsePrefix("100.64.0.2/32"), freePort(t)}
	cfg := r.config(t, "", a, "Endpoint = name.invalid:1")
	v6 := netip.MustParseAddrPort("[2001:db8::1]:1")
	v4 := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), a.port)
	cfg.Peers[0].DiscoKey = key.DiscoPublic{}
	cfg.Peers[0].Addrs = []netip.AddrPort{v6, v4}
	er := startEcho(t, cfg)
	acfg := a.config(t, "", r, fmt.Sprintf("Endpoint = 127.0.0.1:%d", r.port))
	acfg.Peers[0].DiscoKey = key.DiscoPublic{}
	startEcho(t, acfg)
	pick := func(ifs *netmon.State, want netip.AddrPort) {
		t.Helper()
		er.repick(func() *netmon.State {
			if er.mu.TryLock() {
				er.mu.Unlock()
				t.Error("network state read without the apply lock")
			}
			return ifs
		})
		got := er.state.Load().nodes[a.priv.Public()].Endpoints().AsSlice()
		if !slices.Equal(got, []netip.AddrPort{want}) {
			t.Fatalf("after %v: endpoints = %v, want %v", ifs, got, want)
		}
	}
	pick(&netmon.State{HaveV4: true}, v4)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := er.stack.dialTCP(ctx, netip.AddrPortFrom(a.addr.Addr(), testEchoPort))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	deadline, _ := ctx.Deadline()
	if err := c.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	exchange := func(s string) {
		t.Helper()
		if _, err := c.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, len(s))
		if _, err := io.ReadFull(c, b); err != nil || string(b) != s {
			t.Fatalf("stream: %q, %v", b, err)
		}
	}
	exchange("before")
	handshake := er.peerStatus(a.priv.Public()).LastHandshake
	pick(&netmon.State{HaveV6: true}, v6)
	pick(&netmon.State{HaveV4: true}, v4)
	exchange("after")
	if got := er.peerStatus(a.priv.Public()).LastHandshake; !got.Equal(handshake) {
		t.Fatal("repick replaced the established session")
	}
}

func TestResolveEndpoint(t *testing.T) {
	k := key.NewNode()
	ordinary := config.Peer{PublicKey: k.Public()}
	discovery := config.Peer{PublicKey: k.Public(), DiscoKey: discokey.PublicForNode(k)}
	for _, tt := range []struct {
		peer     config.Peer
		endpoint string
		want     []netip.AddrPort
	}{
		{ordinary, "192.0.2.1:7", []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:7")}},
		{ordinary, "[::ffff:192.0.2.1]:7", []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:7")}},
		{discovery, "[fe80::1%1]:7", []netip.AddrPort{netip.MustParseAddrPort("[fe80::1%1]:7")}},
	} {
		tt.peer.Endpoint = tt.endpoint
		got, err := ResolveEndpoint(tt.peer)
		if err != nil || !slices.Equal(got, tt.want) {
			t.Errorf("%s (ordinary %v): got %v, %v, want %v", tt.endpoint, tt.peer.WireGuardOnly(), got, err, tt.want)
		}
	}
	ordinary.Endpoint = "name.invalid:1"
	if _, err := ResolveEndpoint(ordinary); err == nil || !strings.HasPrefix(err.Error(), "peer ") {
		t.Fatalf("unresolvable endpoint: %v", err)
	}
}

func TestResolveEndpointOrder(t *testing.T) {
	k := key.NewNode()
	for _, first := range []string{"2001:db8::1", "192.0.2.1"} {
		t.Run(first, func(t *testing.T) {
			addrs := []netip.AddrPort{
				netip.MustParseAddrPort("[2001:db8::1]:51820"),
				netip.MustParseAddrPort("192.0.2.1:51820"),
				netip.MustParseAddrPort("192.0.2.2:51820"),
			}
			if first == "192.0.2.1" {
				addrs[0], addrs[1] = addrs[1], addrs[0]
			}
			lookup := func(_ context.Context, host string) ([]net.IPAddr, error) {
				if host != "peer.example.com" {
					t.Fatalf("lookup host = %q", host)
				}
				var ips []net.IPAddr
				for _, a := range addrs {
					ips = append(ips, net.IPAddr{IP: a.Addr().AsSlice()})
				}
				return ips, nil
			}
			for _, disco := range []key.DiscoPublic{{}, discokey.PublicForNode(k)} {
				p := config.Peer{
					PublicKey: k.Public(),
					DiscoKey:  disco,
					Endpoint:  "peer.example.com:51820",
				}
				got, err := resolveEndpoint(p, lookup)
				if err != nil || !slices.Equal(got, addrs) {
					t.Errorf("ordinary %v: got %v, %v, want %v", p.WireGuardOnly(), got, err, addrs)
				}
			}
		})
	}
}
