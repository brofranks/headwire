package config

import (
	"fmt"
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
