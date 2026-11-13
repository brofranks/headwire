package config

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/tstest"
)

func TestDERPMapLabels(t *testing.T) {
	cfg := &Config{Regions: map[int]Region{
		1:  {ID: 1, Nodes: []string{"first.example", "second.example"}},
		12: {ID: 12, Nodes: []string{"third.example"}},
	}}
	dm := cfg.DERPMap()
	names := map[string]bool{}
	for id, region := range dm.Regions {
		if region.RegionCode != fmt.Sprint(id) || region.RegionName != "" {
			t.Fatalf("unexpected region labels: %+v", region)
		}
		for i, node := range region.Nodes {
			if node.Name != fmt.Sprintf("%d-%d", id, i) || names[node.Name] || node.HostName != cfg.Regions[int(id)].Nodes[i] {
				t.Fatalf("unexpected node: %+v", node)
			}
			names[node.Name] = true
		}
	}
}

func TestDERPMapAddrs(t *testing.T) {
	cfg := &Config{Regions: map[int]Region{1: {
		ID:    1,
		Nodes: []string{"both.example", "v6.example"},
		Addrs: [][]netip.Addr{
			{netip.MustParseAddr("::ffff:192.0.2.1"), netip.MustParseAddr("2001:db8::1")},
			{netip.MustParseAddr("2001:db8::2")},
		},
	}}}
	nodes := cfg.DERPMap().Regions[1].Nodes
	if n := nodes[0]; n.IPv4 != "192.0.2.1" || n.IPv6 != "2001:db8::1" || n.HostName != "both.example" {
		t.Fatalf("node %+v", n)
	}
	if n := nodes[1]; n.IPv4 != "none" || n.IPv6 != "2001:db8::2" {
		t.Fatalf("node %+v", n)
	}
}

func TestDERPMapUnresolvedNodes(t *testing.T) {
	cfg := &Config{Regions: map[int]Region{
		1: {
			ID:    1,
			Nodes: []string{"first.example", "second.example", "third.example"},
			Addrs: [][]netip.Addr{
				nil,
				{netip.MustParseAddr("192.0.2.1")},
				nil,
			},
		},
		2: {
			ID:    2,
			Nodes: []string{"other.example"},
			Addrs: [][]netip.Addr{nil},
		},
	}}
	dm := cfg.DERPMap()
	nodes := dm.Regions[1].Nodes
	if len(nodes) != 1 {
		t.Fatalf("resolved nodes = %+v", nodes)
	}
	if n := nodes[0]; n.Name != "1-1" || n.HostName != "second.example" ||
		n.IPv4 != "192.0.2.1" || n.IPv6 != "none" {
		t.Errorf("resolved node = %+v", n)
	}
	if nodes := dm.Regions[2].Nodes; len(nodes) != 0 {
		t.Errorf("unresolved region nodes = %+v", nodes)
	}
}

func TestDERPMapAddressFallback(t *testing.T) {
	cfg := &Config{Regions: map[int]Region{1: {
		ID:    1,
		Nodes: []string{"both.example", "v6.example"},
		Addrs: [][]netip.Addr{
			{
				netip.MustParseAddr("::ffff:192.0.2.1"),
				netip.MustParseAddr("2001:db8::1"),
				netip.MustParseAddr("192.0.2.2"),
				netip.MustParseAddr("2001:db8::2"),
				netip.MustParseAddr("192.0.2.3"),
			},
			{netip.MustParseAddr("2001:db8::3")},
		},
	}}}
	want := []string{
		"1-0 both.example 192.0.2.1 2001:db8::1 0 false",
		"1-1 v6.example none 2001:db8::3 0 false",
		"1-0-r2 both.example 192.0.2.1 2001:db8::1 0 true",
		"1-1-r3 v6.example none 2001:db8::3 0 true",
		"1-0-1 both.example 192.0.2.2 2001:db8::2 -1 false",
		"1-0-2 both.example 192.0.2.3 none -1 false",
	}
	nodes := cfg.DERPMap().Regions[1].Nodes
	if len(nodes) != len(want) {
		t.Fatalf("nodes = %+v, want %d", nodes, len(want))
	}
	for i, n := range nodes {
		got := fmt.Sprintf("%s %s %s %s %d %v", n.Name, n.HostName, n.IPv4, n.IPv6, n.STUNPort, n.STUNOnly)
		if got != want[i] || n.RegionID != 1 {
			t.Errorf("node %d = %q, want %q", i, got, want[i])
		}
	}
}

func TestDERPMapProbeSlots(t *testing.T) {
	hosts := []string{"a.example", "b.example", "c.example", "d.example", "e.example"}
	for count := 1; count <= len(hosts); count++ {
		for _, extra := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d hosts, extra %v", count, extra), func(t *testing.T) {
				var addrs [][]netip.Addr
				for i := range count {
					addrs = append(addrs, []netip.Addr{netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})})
				}
				addrs[0] = []netip.Addr{netip.MustParseAddr("2001:db8::1")}
				if extra {
					for j := 2; j <= 4; j++ {
						addrs[0] = append(addrs[0], netip.MustParseAddr(fmt.Sprintf("2001:db8::%d", j)))
					}
				}
				cfg := &Config{Regions: map[int]Region{1: {
					ID:    1,
					Nodes: append([]string{"unresolved.example"}, hosts[:count]...),
					Addrs: append([][]netip.Addr{nil}, addrs...),
				}}}
				nodes := cfg.DERPMap().Regions[1].Nodes
				want := count
				if extra {
					// Pads up to four probe slots, then the dial candidates.
					want = max(count, 4) + 3
				}
				if len(nodes) != want {
					t.Fatalf("nodes = %+v", nodes)
				}
				// Every slot netcheck can probe is a host's first address.
				for i := range 4 {
					n := nodes[i%len(nodes)]
					v4, v6 := fmt.Sprintf("192.0.2.%d", i%count), "none"
					if i%count == 0 {
						v4, v6 = "none", "2001:db8::1"
					}
					if n.HostName != hosts[i%count] || n.IPv4 != v4 || n.IPv6 != v6 ||
						n.STUNPort != 0 || n.STUNOnly != (extra && i >= count) {
						t.Errorf("probe slot %d = %+v", i, n)
					}
				}
				last := nodes[len(nodes)-1]
				if extra && (last.IPv4 != "none" || last.IPv6 != "2001:db8::4" ||
					last.STUNPort != -1 || last.STUNOnly) {
					t.Errorf("dial candidate = %+v", last)
				}
				names := map[string]bool{}
				for _, n := range nodes {
					if names[n.Name] {
						t.Errorf("duplicate node name %q", n.Name)
					}
					names[n.Name] = true
				}
			})
		}
	}
}

func TestDERPMapDialFallback(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	cfg := &Config{Regions: map[int]Region{1: {
		ID:    1,
		Nodes: []string{"relay.example.com"},
		Addrs: [][]netip.Addr{{
			netip.MustParseAddr("127.0.0.2"),
			netip.MustParseAddr("127.0.0.1"),
		}},
	}}}
	region := cfg.DERPMap().Regions[1]
	for _, n := range region.Nodes {
		n.DERPPort = srv.Listener.Addr().(*net.TCPAddr).Port
	}
	client := derphttp.NewNetcheckClient(tstest.WhileTestRunningLogger(t), netmon.NewStatic())
	client.TLSConfig = &tls.Config{RootCAs: roots}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, closer, node, err := client.DialRegionTLS(ctx, region)
	if err != nil {
		t.Fatal(err)
	}
	defer closer.Close()
	if node.IPv4 != "127.0.0.1" || node.STUNOnly {
		t.Errorf("connected node = %+v", node)
	}
	if got := conn.ConnectionState().ServerName; got != "relay.example.com" {
		t.Errorf("TLS server name = %q", got)
	}
}
