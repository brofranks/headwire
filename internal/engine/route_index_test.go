package engine

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"testing"

	"brof.dev/headwire/internal/config"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// linearPeerByIP is the reference longest-prefix scan: the longest matching
// prefix wins, and equal prefixes go to the last configured peer.
func linearPeerByIP(st *state, dst netip.Addr) (best tailcfg.NodeView, ok bool) {
	bits := -1
	for _, n := range st.nm.Peers {
		for _, prefix := range n.AllowedIPs().All() {
			if prefix.Contains(dst) && prefix.Bits() >= bits {
				best, bits, ok = n, prefix.Bits(), true
			}
		}
	}
	return best, ok
}

func TestRouteIndexOwnership(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for _, mode := range []string{"empty", "gaps", "IPv4 default", "IPv6 default", "dual default"} {
		t.Run(mode, func(t *testing.T) {
			cfg := &config.Config{Interface: config.Interface{PrivateKey: key.NewNode()}}
			if mode != "empty" {
				cfg.Interface.Addresses = []netip.Prefix{
					netip.MustParsePrefix("192.0.2.65/24"),
					netip.MustParsePrefix("2001:db8::41/64"),
					netip.MustParsePrefix("0.0.0.0/32"),
					netip.MustParsePrefix("::/128"),
					netip.MustParsePrefix("255.255.255.255/32"),
					netip.MustParsePrefix("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"),
				}
				for peer := range 4 {
					p := config.Peer{PublicKey: key.NewNode().Public()}
					for i := range 32 {
						var raw [16]byte
						for j := range raw {
							raw[j] = byte(rng.Uint32())
						}
						addr := netip.AddrFrom16(raw)
						if i%2 == 0 {
							addr = netip.AddrFrom4([4]byte(raw[:4]))
						}
						prefix := netip.PrefixFrom(addr, 1+rng.IntN(addr.BitLen()))
						if peer > 0 && i%4 == 0 {
							prefix = cfg.Peers[peer-1].AllowedIPs[i].Masked()
						}
						p.AllowedIPs = append(p.AllowedIPs, prefix)
					}
					// These prefixes exercise nesting, equal prefixes and host bits.
					for _, prefix := range [][]string{
						{"192.0.2.129/24", "2001:db8::81/120"},
						{"192.0.2.65/26", "2001:db8::41/122"},
						{"192.0.2.1/24", "2001:db8::1/120"},
						{"192.0.2.65/32", "2001:db8::41/128"},
					}[peer] {
						p.AllowedIPs = append(p.AllowedIPs, netip.MustParsePrefix(prefix))
					}
					cfg.Peers = append(cfg.Peers, p)
				}
				for _, prefix := range map[string][]string{
					"IPv4 default": {"0.0.0.0/0"},
					"IPv6 default": {"::/0"},
					"dual default": {"0.0.0.0/0", "::/0"},
				}[mode] {
					first := &cfg.Peers[0]
					first.AllowedIPs = append(first.AllowedIPs, netip.MustParsePrefix(prefix))
				}
			}
			st, err := newState(cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			ips := []netip.Addr{{}, netip.MustParseAddr("fe80::1%eth0")}
			for _, address := range []string{
				"0.0.0.0", "255.255.255.255", "::",
				"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
				"192.0.2.1", "2001:db8::1",
			} {
				ips = append(ips, netip.MustParseAddr(address))
			}
			for _, a := range cfg.Interface.Addresses {
				ips = append(ips, a.Addr())
			}
			for _, p := range cfg.Peers {
				for _, prefix := range p.AllowedIPs {
					first, last := prefix.Masked().Addr(), netipx.PrefixLastIP(prefix)
					ips = append(ips, prefix.Addr(), first.Prev(), first, last, last.Next())
				}
			}
			for _, ip := range ips {
				want, wantOK := linearPeerByIP(st, ip)
				got, ok := st.peerByIP(ip)
				if ok != wantOK || ok && got.Key() != want.Key() {
					t.Fatalf("route %s: got %v, %v; want %v, %v", ip, got, ok, want, wantOK)
				}
				for k, set := range st.allowed {
					allowed := wantOK && want.Key() == k && !cfg.Interface.HasAddress(ip)
					if set.Contains(ip) != allowed {
						t.Fatalf("source %s: incorrect permissions for %s", ip, k.ShortString())
					}
				}
			}
		})
	}
}

func BenchmarkPeerByIP(b *testing.B) {
	for _, n := range []int{128, 1024, 4096} {
		cfg := sparseOwnershipConfig(b, n)
		cfg.Interface.PrivateKey = key.NewNode()
		st, err := newState(cfg, nil)
		if err != nil {
			b.Fatal(err)
		}
		for _, method := range []struct {
			name   string
			lookup func(*state, netip.Addr) (tailcfg.NodeView, bool)
		}{
			{"index", (*state).peerByIP},
			{"linear", linearPeerByIP},
		} {
			for _, hit := range []bool{true, false} {
				ip := cfg.Peers[0].AllowedIPs[n-1].Addr()
				if !hit {
					ip = ip.Next()
				}
				b.Run(fmt.Sprintf("%d/%s/hit=%t", n, method.name, hit), func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						if _, ok := method.lookup(st, ip); ok != hit {
							b.Fatal("unexpected lookup result")
						}
					}
				})
			}
		}
	}
}
