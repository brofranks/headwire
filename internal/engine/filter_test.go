package engine

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/net/packet"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/filter"

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

	warm(t, ea, eb)
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
