package engine

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/views"
	"tailscale.com/wgengine/filter"

	"go4.org/netipx"

	"brof.dev/headwire/internal/config"
)

func testFilter(t *testing.T, cfg *config.Config) *filter.Filter {
	t.Helper()
	allowed, err := sourcePermissions(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return newFilter(&state{cfg: cfg, allowed: allowed}, nil, t.Logf)
}

// defaultFilter has one peer owning every source and no AllowIn anywhere.
func defaultFilter(t *testing.T) *filter.Filter {
	t.Helper()
	n := node{priv: key.NewNode(), addr: netip.MustParsePrefix("100.64.0.1/32")}
	//lint:ignore SA1019 raw keys; see config.EncodeKey.
	return testFilter(t, n.parse(t, "", "[Peer]\nPublicKey = "+config.EncodeKey(key.NewNode().Public().Raw32())+
		"\nEndpoint = 192.0.2.1:1\nAllowedIPs = 0.0.0.0/0, ::/0\n"))
}

// TestAllowProtocols admits every protocol number of both families through
// the default policy, and drops packets the decoder rejects.
func TestAllowProtocols(t *testing.T) {
	f := defaultFilter(t)
	for _, family := range []struct {
		src, dst  string
		protos    []ipproto.Proto
		malformed [][]byte
	}{
		{src: "100.64.0.2", dst: "100.64.0.1", malformed: [][]byte{{1, 2, 3}}},
		// IPv6 next-header numbers are extension headers, so only protocols.
		{src: "fd00::1", dst: "fd00::2", protos: []ipproto.Proto{ipproto.TCP, ipproto.UDP, ipproto.ICMPv6, 47, 50, 132}, malformed: [][]byte{{0x60, 0, 0, 0}}},
	} {
		src, dst := netip.MustParseAddr(family.src), netip.MustParseAddr(family.dst)
		protos := family.protos
		if protos == nil {
			for proto := 1; proto < 255; proto++ {
				protos = append(protos, ipproto.Proto(proto))
			}
		}
		for _, proto := range protos {
			payload := make([]byte, 32)
			payload[12], payload[13] = 0x50, byte(packet.TCPSyn)
			var q packet.Parsed
			q.Decode(packet.Generate(header(proto, src, dst), payload))
			if got := f.RunIn(&q, 0); got != filter.Accept {
				t.Errorf("%s protocol %d: %v", family.src, proto, got)
			}
		}
		// A header without its payload is malformed too.
		malformed := append(family.malformed, packet.Generate(header(ipproto.TCP, src, dst), nil))
		for _, b := range malformed {
			var q packet.Parsed
			q.Decode(b)
			if got := f.RunIn(&q, 0); got != filter.Drop {
				t.Errorf("malformed packet: %v", got)
			}
		}
	}
}

// header builds the IP header of src's family.
func header(proto ipproto.Proto, src, dst netip.Addr) packet.Header {
	if src.Is6() {
		return packet.IP6Header{IPProto: proto, Src: src, Dst: dst}
	}
	return packet.IP4Header{IPProto: proto, Src: src, Dst: dst}
}

func TestFilterGroupsDefaultPolicy(t *testing.T) {
	cfg := &config.Config{}
	for i := 2; i <= 16; i++ {
		cfg.Peers = append(cfg.Peers, config.Peer{
			PublicKey: key.NewNode().Public(),
			AllowedIPs: []netip.Prefix{
				netip.MustParsePrefix(fmt.Sprintf("100.64.0.%d/32", i)),
				netip.MustParsePrefix(fmt.Sprintf("fd00::%x/128", i)),
			},
		})
	}
	allowed, err := sourcePermissions(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(filterMatches(&state{cfg: cfg, allowed: allowed})); got != 1 {
		t.Fatalf("default policy emitted %d rules for %d peers, want 1",
			got, len(cfg.Peers))
	}
	f := testFilter(t, cfg)
	for _, p := range cfg.Peers {
		for _, source := range p.AllowedIPs {
			dst := netip.MustParseAddr("192.0.2.1")
			if source.Addr().Is6() {
				dst = netip.MustParseAddr("2001:db8::1")
			}
			for _, proto := range []ipproto.Proto{ipproto.TCP, ipproto.UDP, ipproto.SCTP, 47, 50} {
				if got := f.Check(source.Addr(), dst, 65535, proto); got != filter.Accept {
					t.Errorf("%s protocol %d: %v, want accept", source.Addr(), proto, got)
				}
			}
		}
	}
}

func TestFilterGroupsPolicies(t *testing.T) {
	for _, family := range []struct {
		self, target string
		sources      []string
	}{
		{
			self:   "100.64.0.1/24",
			target: "192.0.2.1/24",
			sources: []string{
				"10.0.0.1/8", "10.1.0.1/16", "10.2.0.1/16", "10.3.0.1/16", "10.4.0.1/16",
			},
		},
		{
			self:   "2001:db8::1/64",
			target: "2001:db8:ffff::1/64",
			sources: []string{
				"fd10::1/16", "fd10:1::1/32", "fd10:2::1/32", "fd10:3::1/32", "fd10:4::1/32",
			},
		},
	} {
		t.Run(family.self, func(t *testing.T) {
			self, target := netip.MustParsePrefix(family.self), netip.MustParsePrefix(family.target)
			toSelf := config.AllowDestination{Kind: config.DestinationSelf}
			toTarget := config.AllowDestination{Kind: config.DestinationPrefix, Prefix: target.Masked()}
			cfg := &config.Config{Interface: config.Interface{
				Addresses: []netip.Prefix{self},
				AllowIn: []config.AllowRule{
					{Protos: []uint8{6}, First: 20, Last: 22, Destination: toSelf},
					{Protos: []uint8{17}, First: 50, Last: 52, Destination: toTarget},
				},
			}}
			var sources []netip.Addr
			for i, source := range append(family.sources, family.sources[4]) {
				prefix := netip.MustParsePrefix(source)
				sources = append(sources, prefix.Addr())
				p := config.Peer{
					PublicKey:  key.NewNode().Public(),
					AllowedIPs: []netip.Prefix{prefix.Masked()},
				}
				switch i {
				case 0:
					p.AllowedIPs = append(p.AllowedIPs, self.Masked())
				case 2:
					p.AllowIn = []config.AllowRule{
						{Protos: []uint8{17}, First: 50, Last: 52, Destination: toSelf},
						{Protos: []uint8{6}, First: 20, Last: 22, Destination: toTarget},
					}
				case 3, 5:
					p.AllowIn = []config.AllowRule{}
				}
				cfg.Peers = append(cfg.Peers, p)
			}
			allowed, err := sourcePermissions(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if got := len(filterMatches(&state{cfg: cfg, allowed: allowed})); got != 4 {
				t.Fatalf("emitted %d distinct rules, want 4", got)
			}
			f := testFilter(t, cfg)
			for _, tt := range []struct {
				src, dst netip.Addr
				proto    ipproto.Proto
				port     uint16
				want     filter.Response
			}{
				{sources[0], self.Addr(), ipproto.TCP, 20, filter.Accept},
				{sources[1], self.Addr(), ipproto.TCP, 22, filter.Accept},
				{sources[1], self.Addr(), ipproto.TCP, 19, filter.Drop},
				{sources[1], self.Addr(), ipproto.TCP, 23, filter.Drop},
				{sources[1], self.Addr().Next(), ipproto.TCP, 22, filter.Drop},
				{sources[1], target.Addr(), ipproto.UDP, 50, filter.Accept},
				{sources[1], target.Addr(), ipproto.UDP, 52, filter.Accept},
				{sources[1], target.Addr(), ipproto.UDP, 49, filter.Drop},
				{sources[1], target.Addr(), ipproto.UDP, 53, filter.Drop},
				{sources[1], self.Addr(), ipproto.UDP, 50, filter.Drop},
				{sources[1], target.Addr(), ipproto.TCP, 20, filter.Drop},
				{sources[2], target.Addr(), ipproto.TCP, 20, filter.Accept},
				{sources[2], self.Addr(), ipproto.UDP, 50, filter.Accept},
				{sources[2], self.Addr(), ipproto.TCP, 20, filter.Drop},
				{sources[2], target.Addr(), ipproto.UDP, 50, filter.Drop},
				{sources[3], self.Addr(), ipproto.TCP, 20, filter.Drop},
				{sources[4], self.Addr(), ipproto.TCP, 20, filter.Drop},
				{self.Addr(), self.Addr(), ipproto.TCP, 20, filter.Drop},
			} {
				if got := f.Check(tt.src, tt.dst, tt.port, tt.proto); got != tt.want {
					t.Errorf("%s -> %s protocol %d port %d: %v, want %v",
						tt.src, tt.dst, tt.proto, tt.port, got, tt.want)
				}
			}
		})
	}
}

func TestAllowIn(t *testing.T) {
	n := node{priv: key.NewNode(), addr: netip.MustParsePrefix("100.64.0.1/32")}
	peer := func(addr, allowIn string) string {
		return fmt.Sprintf("[Peer]\nPublicKey = %s\nEndpoint = 192.0.2.1:1\nAllowedIPs = %s\n%s\n",
			//lint:ignore SA1019 raw keys; see config.EncodeKey.
			config.EncodeKey(key.NewNode().Public().Raw32()), addr, allowIn)
	}
	f := testFilter(t, n.parse(t, "AllowIn = none",
		peer("100.64.0.2, fd00::2", "AllowIn = tcp/22, udp/5000-5010\nAllowIn = 47")+
			peer("100.64.0.3", "AllowIn = icmp")+
			peer("100.64.0.4", "AllowIn = any")+
			peer("100.64.0.5", "")))
	for _, tt := range []struct {
		src   string
		proto ipproto.Proto
		port  uint16
		want  filter.Response
	}{
		{"100.64.0.2", ipproto.TCP, 22, filter.Accept},
		{"fd00::2", ipproto.TCP, 22, filter.Accept},
		{"100.64.0.2", ipproto.TCP, 23, filter.Drop},
		{"100.64.0.2", ipproto.UDP, 5005, filter.Accept},
		{"100.64.0.2", ipproto.UDP, 5011, filter.Drop},
		{"100.64.0.2", 47, 0, filter.Accept},
		{"100.64.0.2", 50, 0, filter.Drop},
		// The filter admits echo wherever any rule covers the addresses.
		{"100.64.0.2", ipproto.ICMPv4, 0, filter.Accept},
		{"100.64.0.3", ipproto.ICMPv4, 0, filter.Accept},
		{"100.64.0.3", ipproto.TCP, 22, filter.Drop},
		{"100.64.0.4", ipproto.TCP, 23, filter.Accept},
		{"100.64.0.4", 50, 0, filter.Accept},
		{"100.64.0.5", ipproto.TCP, 22, filter.Drop},
		{"100.64.0.5", ipproto.ICMPv4, 0, filter.Drop},
	} {
		src := netip.MustParseAddr(tt.src)
		dst := netip.MustParseAddr("100.64.0.1")
		if src.Is6() {
			dst = netip.MustParseAddr("fd00::1")
		}
		if got := f.Check(src, dst, tt.port, tt.proto); got != tt.want {
			t.Errorf("%s proto %d port %d: %v, want %v", tt.src, tt.proto, tt.port, got, tt.want)
		}
	}
}

// TestAllowInReload tightens and loosens B's policy for A without restart.
func TestAllowInReload(t *testing.T) {
	a := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), freePort(t)}
	b := node{key.NewNode(), netip.MustParsePrefix("100.64.0.2/32"), freePort(t)}
	eb := startEcho(t, b.config(t, "AllowIn = any", a, fmt.Sprintf("AllowIn = tcp/%d to 192.0.2.1", testEchoPort)))
	ea := startEcho(t, a.config(t, "", b, fmt.Sprintf("Endpoint = 127.0.0.1:%d", b.port)))
	target := netip.AddrPortFrom(b.addr.Addr(), testEchoPort)

	warm(t, ea.Engine, eb.Engine)
	denied(t, ea, target, "round trip passed a filter admitting only another destination")
	if err := eb.Reload(b.config(t, "AllowIn = none", a, fmt.Sprintf("AllowIn = tcp/%d to self", testEchoPort))); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := dialRoundTripUntil(ctx, ea, target); err != nil {
		t.Fatal(err)
	}
	if err := eb.Reload(b.config(t, "AllowIn = none", a, "")); err != nil {
		t.Fatal(err)
	}
	denied(t, ea, target, "round trip passed AllowIn = none")
}

func TestAllowInDestinations(t *testing.T) {
	n := node{priv: key.NewNode(), addr: netip.MustParsePrefix("100.64.0.1/24")}
	b := node{priv: key.NewNode(), addr: netip.MustParsePrefix("100.64.0.2/32")}
	c := node{priv: key.NewNode(), addr: netip.MustParsePrefix("100.64.0.3/32")}
	cfg := n.parse(t, "Address = fd00::1/64\nAllowIn = tcp/22 to self",
		b.peerSection("AllowedIPs = fd00::2/128, 10.0.0.0/8\nAllowIn = any to 192.168.1.0/24\nAllowIn = udp/53 to self")+
			c.peerSection("AllowedIPs = 10.1.0.0/16"))
	f := testFilter(t, cfg)
	for _, tt := range []struct {
		src, dst string
		proto    ipproto.Proto
		port     uint16
		want     filter.Response
	}{
		{"100.64.0.3", "100.64.0.1", ipproto.TCP, 22, filter.Accept},
		{"100.64.0.3", "100.64.0.9", ipproto.TCP, 22, filter.Drop},
		{"100.64.0.3", "192.168.1.1", ipproto.TCP, 22, filter.Drop},
		{"100.64.0.2", "100.64.0.1", ipproto.TCP, 22, filter.Drop}, // replaces default
		{"100.64.0.2", "192.168.1.1", ipproto.TCP, 22, filter.Accept},
		{"100.64.0.2", "192.168.2.1", ipproto.TCP, 22, filter.Drop},
		{"100.64.0.2", "100.64.0.1", ipproto.UDP, 53, filter.Accept},
		{"100.64.0.2", "100.64.0.1", ipproto.UDP, 54, filter.Drop},
		{"fd00::2", "fd00::1", ipproto.UDP, 53, filter.Accept},
		{"fd00::2", "fd00::9", ipproto.UDP, 53, filter.Drop},
		{"10.2.0.1", "192.168.1.1", 47, 0, filter.Accept},
		{"10.1.0.1", "192.168.1.1", 47, 0, filter.Drop}, // narrower owner has no grant
	} {
		if got := f.Check(netip.MustParseAddr(tt.src), netip.MustParseAddr(tt.dst), tt.port, tt.proto); got != tt.want {
			t.Errorf("%s -> %s proto %d port %d: %v, want %v", tt.src, tt.dst, tt.proto, tt.port, got, tt.want)
		}
	}
}

// TestAllowInPacketSemantics uses the packet path: Check synthesizes
// connection-opening packets and cannot establish the inherited exceptions
// or the lifetime of response state.
func TestAllowInPacketSemantics(t *testing.T) {
	for _, family := range []struct{ self, peer, other string }{
		{"100.64.0.1/32", "100.64.0.2/32", "100.64.0.9"},
		{"fd00::1/128", "fd00::2/128", "fd00::9"},
	} {
		t.Run(family.self, func(t *testing.T) {
			n := node{priv: key.NewNode(), addr: netip.MustParsePrefix(family.self)}
			p := node{priv: key.NewNode(), addr: netip.MustParsePrefix(family.peer)}
			cfg := n.config(t, "AllowIn = any", p, "AllowIn = tcp/22 to self")
			f := testFilter(t, cfg)
			makePacket := func(proto ipproto.Proto, src, dst netip.Addr, flags byte) *packet.Parsed {
				payload := make([]byte, 32)
				payload[0], payload[1], payload[3] = 0x12, 0x34, 22
				payload[12], payload[13] = 0x50, flags
				if proto == ipproto.ICMPv4 || proto == ipproto.ICMPv6 {
					payload[0], payload[1] = flags, 0
				}
				var h packet.Header = packet.IP4Header{IPProto: proto, Src: src, Dst: dst}
				if src.Is6() {
					h = packet.IP6Header{IPProto: proto, Src: src, Dst: dst}
				}
				q := new(packet.Parsed)
				q.Decode(packet.Generate(h, payload))
				return q
			}
			check := func(q *packet.Parsed, want filter.Response) {
				t.Helper()
				if got := f.RunIn(q, 0); got != want {
					t.Fatalf("%v: got %v, want %v", q, got, want)
				}
			}
			src, dst := p.addr.Addr(), n.addr.Addr()
			other := netip.MustParseAddr(family.other)
			check(makePacket(ipproto.TCP, src, dst, byte(packet.TCPSyn)), filter.Accept)
			check(makePacket(ipproto.TCP, src, other, byte(packet.TCPSyn)), filter.Drop)
			icmp, echo, reply, icmpError := ipproto.ICMPv4, byte(8), byte(0), byte(3)
			if src.Is6() {
				icmp, echo, reply, icmpError = ipproto.ICMPv6, 128, 129, 1
			}
			check(makePacket(icmp, src, dst, echo), filter.Accept) // even though rule says TCP
			check(makePacket(icmp, src, other, echo), filter.Drop)
			for _, proto := range []ipproto.Proto{ipproto.UDP, ipproto.SCTP} {
				q := makePacket(proto, src, dst, 0)
				check(q, filter.Drop)
				out := makePacket(proto, dst, src, 0)
				out.Src, out.Dst = q.Dst, q.Src
				f.RunOut(out, 0)
				check(q, filter.Accept)
			}
			cfg.Peers[0].AllowIn = []config.AllowRule{}
			allowed, err := sourcePermissions(cfg)
			if err != nil {
				t.Fatal(err)
			}
			f = newFilter(&state{cfg: cfg, allowed: allowed}, f, t.Logf)
			check(makePacket(ipproto.TCP, src, dst, byte(packet.TCPSyn)), filter.Drop)
			check(makePacket(ipproto.TCP, src, other, byte(packet.TCPAck)), filter.Accept)
			check(makePacket(icmp, src, dst, echo), filter.Drop)
			check(makePacket(icmp, src, other, reply), filter.Accept)
			check(makePacket(icmp, src, other, icmpError), filter.Accept)
			check(makePacket(ipproto.TSMP, src, other, 0), filter.Accept)
			for _, proto := range []ipproto.Proto{ipproto.UDP, ipproto.SCTP} {
				check(makePacket(proto, src, dst, 0), filter.Accept)
				check(makePacket(proto, src, other, 0), filter.Drop)
			}
			q := makePacket(ipproto.UDP, src, other, 0)
			buf := q.Buffer()
			if src.Is4() {
				buf[6], buf[7] = 0, 16 // non-first fragment, offset 128 bytes
			} else {
				buf[6] = 44 // IPv6 Fragment extension header
				buf[40], buf[41], buf[42], buf[43] = byte(ipproto.UDP), 0, 0, 128
			}
			q.Decode(buf)
			if q.IPProto != ipproto.Fragment {
				t.Fatal("not decoded as a fragment")
			}
			check(q, filter.Accept)
		})
	}
}

func TestMasqueradeMalformedIPv4(t *testing.T) {
	n := node{priv: key.NewNode(), addr: netip.MustParsePrefix("100.64.0.1/32")}
	p := node{priv: key.NewNode(), addr: netip.MustParsePrefix("100.64.0.2/32")}
	e, ch := startInjected(t, n.config(t, "", p, "MasqueradeAddress = 10.69.0.5"))
	ch.Inbound = make(chan []byte, 1)
	buf := packet.Generate(header(ipproto.UDP, p.addr.Addr(), netip.MustParseAddr("10.69.0.5")), nil)
	buf[0] = 0x4f // The declared 60-byte header exceeds the 20-byte packet.
	count, err := e.tun.Write([][]byte{buf}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 || len(ch.Inbound) != 0 {
		t.Fatal("malformed packet reached the device")
	}
}

// TestAllowInAfterMasquerade feeds decrypted packets through the production
// TUN wrapper, including its inbound DNAT. Matching the on-wire masquerade
// address would be incorrect.
func TestAllowInAfterMasquerade(t *testing.T) {
	for _, family := range []struct{ self, peer, masq string }{
		{"100.64.0.1/32", "100.64.0.2/32", "10.69.0.5"},
		{"fd00::1/128", "fd00::2/128", "fd69::5"},
	} {
		t.Run(family.self, func(t *testing.T) {
			n := node{priv: key.NewNode(), addr: netip.MustParsePrefix(family.self)}
			p := node{priv: key.NewNode(), addr: netip.MustParsePrefix(family.peer)}
			cfg := n.config(t, "AllowIn = any", p, "MasqueradeAddress = "+family.masq+"\nAllowIn = tcp/22 to self")
			e, ch := startInjected(t, cfg)
			// Write is synchronous, so buffer the device output for inspection.
			ch.Inbound = make(chan []byte, 1)
			for _, dest := range []string{"self", family.masq} {
				if dest != "self" {
					if err := e.Reload(n.config(t, "AllowIn = any", p, "MasqueradeAddress = "+family.masq+"\nAllowIn = tcp/22 to "+dest)); err != nil {
						t.Fatal(err)
					}
				}
				payload := make([]byte, 20)
				payload[1], payload[3], payload[12], payload[13] = 123, 22, 0x50, byte(packet.TCPSyn)
				src, dst := p.addr.Addr(), netip.MustParseAddr(family.masq)
				count, err := e.tun.Write([][]byte{packet.Generate(header(ipproto.TCP, src, dst), payload)}, 0)
				if err != nil {
					t.Fatal(err)
				}
				want := 0
				if dest == "self" {
					want = 1
				}
				if count != want {
					t.Fatalf("to %s: delivered %d packets, want %d", dest, count, want)
				}
				if count == 1 {
					var q packet.Parsed
					q.Decode(<-ch.Inbound)
					if q.Dst.Addr() != n.addr.Addr() {
						t.Fatalf("destination was not translated: %v", q.Dst)
					}
				}
			}
		})
	}
}

// TestFilterGroupsSharedSources gives one peer two grants, so two matches
// start from its sources, and then extends each match with a different peer.
// Neither extension may leak into the other match.
func TestFilterGroupsSharedSources(t *testing.T) {
	ssh := config.AllowRule{Protos: []uint8{6}, First: 22, Last: 22}
	dns := config.AllowRule{Protos: []uint8{17}, First: 53, Last: 53}
	cfg := &config.Config{Peers: []config.Peer{
		{
			PublicKey:  key.NewNode().Public(),
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			AllowIn:    []config.AllowRule{ssh, dns},
		},
		{
			PublicKey:  key.NewNode().Public(),
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")},
			AllowIn:    []config.AllowRule{ssh},
		},
		{
			PublicKey:  key.NewNode().Public(),
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("192.168.0.1/32")},
			AllowIn:    []config.AllowRule{dns},
		},
	}}
	allowed, err := sourcePermissions(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// The first peer's set has a hole, so its prefix slice has spare capacity
	// for an append to write into.
	if s := allowed[cfg.Peers[0].PublicKey].Prefixes(); cap(s) == len(s) {
		t.Fatalf("first peer's %d prefixes have no spare capacity", len(s))
	}
	f := testFilter(t, cfg)
	dst := netip.MustParseAddr("192.0.2.1")
	for _, tt := range []struct {
		src   string
		proto ipproto.Proto
		port  uint16
		want  filter.Response
	}{
		{"10.0.0.2", ipproto.TCP, 22, filter.Accept},
		{"10.0.0.2", ipproto.UDP, 53, filter.Accept},
		{"10.0.0.1", ipproto.TCP, 22, filter.Accept},
		{"10.0.0.1", ipproto.UDP, 53, filter.Drop},
		{"192.168.0.1", ipproto.UDP, 53, filter.Accept},
		{"192.168.0.1", ipproto.TCP, 22, filter.Drop},
	} {
		if got := f.Check(netip.MustParseAddr(tt.src), dst, tt.port, tt.proto); got != tt.want {
			t.Errorf("%s protocol %d port %d: %v, want %v", tt.src, tt.proto, tt.port, got, tt.want)
		}
	}
}

// ungroupedMatches is the reference policy: one match per peer per rule, from
// the sources that peer owns.
func ungroupedMatches(st *state) []filter.Match {
	self := hostAddrs(st.cfg.Interface.Addresses)
	var matches []filter.Match
	for _, p := range st.cfg.Peers {
		rules := p.AllowIn
		if rules == nil {
			rules = st.cfg.Interface.AllowIn
		}
		if rules == nil {
			rules = []config.AllowRule{{Last: 65535}}
		}
		for _, r := range rules {
			protos := protocols
			if r.Protos != nil {
				protos = nil
				for _, n := range r.Protos {
					protos = append(protos, ipproto.Proto(n))
				}
			}
			destinations := anyPrefixes
			switch r.Destination.Kind {
			case config.DestinationSelf:
				destinations = self
			case config.DestinationPrefix:
				destinations = []netip.Prefix{r.Destination.Prefix}
			}
			var dsts []filter.NetPortRange
			for _, dst := range destinations {
				ports := filter.PortRange{First: r.First, Last: r.Last}
				dsts = append(dsts, filter.NetPortRange{Net: dst, Ports: ports})
			}
			matches = append(matches, filter.Match{
				IPProto: views.SliceOf(protos),
				Srcs:    st.allowed[p.PublicKey].Prefixes(),
				Dsts:    dsts,
			})
		}
	}
	return matches
}

// TestFilterGroupingEquivalence checks that grouped grants admit exactly what
// the reference policy admits, on randomized configurations whose peers
// repeat, reorder and override rules.
func TestFilterGroupingEquivalence(t *testing.T) {
	selfPrefixes := []netip.Prefix{
		netip.MustParsePrefix("100.64.0.1/24"),
		netip.MustParsePrefix("fd00::1/64"),
	}
	toSelf := config.AllowDestination{Kind: config.DestinationSelf}
	to := func(prefix string) config.AllowDestination {
		return config.AllowDestination{
			Kind:   config.DestinationPrefix,
			Prefix: netip.MustParsePrefix(prefix),
		}
	}
	// The pool holds rules as the parser produces them, including pairs that
	// differ only in protocol, ports or destination.
	pool := []config.AllowRule{
		{Last: 65535},
		{Last: 65535, Destination: toSelf},
		{Protos: []uint8{6}, Last: 65535},
		{Protos: []uint8{6}, First: 22, Last: 22},
		{Protos: []uint8{6}, First: 22, Last: 22, Destination: toSelf},
		{Protos: []uint8{6}, First: 22, Last: 23},
		{Protos: []uint8{17}, First: 22, Last: 22},
		{Protos: []uint8{132}, First: 22, Last: 22},
		{Protos: []uint8{17}, First: 5000, Last: 5010},
		{Protos: []uint8{17}, First: 53, Last: 53, Destination: to("192.0.2.0/24")},
		{Protos: []uint8{17}, First: 53, Last: 53, Destination: to("2001:db8::/64")},
		{Protos: []uint8{1, 58}, Last: 65535},
		{Protos: []uint8{47}, Last: 65535},
		{Protos: []uint8{50}, Last: 65535, Destination: toSelf},
	}
	rng := rand.New(rand.NewPCG(3, 4))
	rules := func() []config.AllowRule {
		switch rng.IntN(4) {
		case 0:
			return nil
		case 1:
			return []config.AllowRule{}
		}
		var rs []config.AllowRule
		for range 1 + rng.IntN(3) {
			rs = append(rs, pool[rng.IntN(len(pool))])
		}
		return rs
	}
	randomIn := func(base netip.Prefix) netip.Addr {
		raw := base.Addr().AsSlice()
		for i := base.Bits() / 8; i < len(raw); i++ {
			raw[i] = byte(rng.Uint32())
		}
		addr, _ := netip.AddrFromSlice(raw)
		return addr
	}
	sourceSpaces := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("fd10::/16"),
	}
	for trial := range 12 {
		cfg := &config.Config{Interface: config.Interface{
			Addresses: selfPrefixes,
			AllowIn:   rules(),
		}}
		for i := range 6 {
			p := config.Peer{PublicKey: key.NewNode().Public(), AllowIn: rules()}
			for _, space := range sourceSpaces {
				for range 3 {
					addr := randomIn(space)
					bits := space.Bits() + rng.IntN(addr.BitLen()-space.Bits()+1)
					p.AllowedIPs = append(p.AllowedIPs, netip.PrefixFrom(addr, bits))
				}
			}
			switch {
			case i > 0 && rng.IntN(2) == 0:
				p.AllowedIPs = append(p.AllowedIPs, cfg.Peers[i-1].AllowedIPs[0])
			case rng.IntN(4) == 0:
				p.AllowedIPs = append(p.AllowedIPs, selfPrefixes...)
			}
			cfg.Peers = append(cfg.Peers, p)
		}
		allowed, err := sourcePermissions(cfg)
		if err != nil {
			t.Fatal(err)
		}
		st := &state{cfg: cfg, allowed: allowed}
		grouped, reference := filterMatches(st), ungroupedMatches(st)
		if len(grouped) > len(reference) {
			t.Fatalf("trial %d: %d grouped rules, %d ungrouped",
				trial, len(grouped), len(reference))
		}
		got := filter.New(grouped, nil, allIPs, allIPs, nil, logger.Discard)
		want := filter.New(reference, nil, allIPs, allIPs, nil, logger.Discard)

		var sources []netip.Addr
		for _, p := range cfg.Peers {
			for _, prefix := range p.AllowedIPs {
				first := prefix.Masked().Addr()
				sources = append(sources, first, first.Prev(), netipx.PrefixLastIP(prefix))
			}
		}
		for _, prefix := range selfPrefixes {
			sources = append(sources, prefix.Addr())
		}
		for range 16 {
			sources = append(sources, randomIn(sourceSpaces[rng.IntN(len(sourceSpaces))]))
		}
		destinations := map[bool][]netip.Addr{
			false: {
				selfPrefixes[0].Addr(),
				netip.MustParseAddr("192.0.2.1"),
				netip.MustParseAddr("198.51.100.1"),
			},
			true: {
				selfPrefixes[1].Addr(),
				netip.MustParseAddr("2001:db8::1"),
				netip.MustParseAddr("2001:db8:1::1"),
			},
		}
		protos := []ipproto.Proto{ipproto.TCP, ipproto.UDP, ipproto.SCTP, 47, 50}
		ports := []uint16{0, 21, 22, 23, 24, 53, 4999, 5000, 5010, 5011, 65535}
		for _, src := range sources {
			if !src.IsValid() {
				continue
			}
			icmp := ipproto.ICMPv4
			if src.Is6() {
				icmp = ipproto.ICMPv6
			}
			for _, dst := range destinations[src.Is6()] {
				for _, proto := range append(protos, icmp) {
					for _, port := range ports {
						g, w := got.Check(src, dst, port, proto), want.Check(src, dst, port, proto)
						if g != w {
							t.Fatalf("trial %d: %s -> %s protocol %d port %d: %v, want %v",
								trial, src, dst, proto, port, g, w)
						}
					}
				}
			}
		}
	}
}

func BenchmarkFilterCheck(b *testing.B) {
	for _, n := range []int{128, 1024, 4096} {
		cfg := &config.Config{}
		for i := range n {
			cfg.Peers = append(cfg.Peers, config.Peer{
				PublicKey: key.NewNode().Public(),
				AllowedIPs: []netip.Prefix{
					netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), 32),
				},
			})
		}
		allowed, err := sourcePermissions(cfg)
		if err != nil {
			b.Fatal(err)
		}
		st := &state{cfg: cfg, allowed: allowed}
		src := cfg.Peers[n-1].AllowedIPs[0].Addr()
		dst := netip.MustParseAddr("192.0.2.1")
		for _, mode := range []struct {
			name    string
			matches []filter.Match
		}{
			{"grouped", filterMatches(st)},
			{"ungrouped", ungroupedMatches(st)},
		} {
			f := filter.New(mode.matches, nil, allIPs, allIPs, nil, logger.Discard)
			b.Run(fmt.Sprintf("%s/%d", mode.name, n), func(b *testing.B) {
				for b.Loop() {
					if f.Check(src, dst, 443, ipproto.TCP) != filter.Accept {
						b.Fatal("dropped")
					}
				}
			})
		}
	}
}
