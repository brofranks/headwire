package config

import (
	"fmt"
	"net/netip"
	"testing"
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
