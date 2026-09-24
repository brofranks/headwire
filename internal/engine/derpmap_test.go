package engine

import (
	"testing"

	"brof.dev/headwire/internal/config"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestDERPMapFlagsNonHomeRegions(t *testing.T) {
	regions := map[int]config.Region{
		1: {ID: 1, Nodes: []string{"derp1.example"}},
		2: {ID: 2, Nodes: []string{"derp2.example"}},
		3: {ID: 3, Nodes: []string{"derp3.example"}},
	}
	for _, tc := range []struct {
		name    string
		home    int
		flagged map[tailcfg.DERPRegionID]bool
	}{
		{"home region measurable", 2, map[tailcfg.DERPRegionID]bool{1: true, 2: false, 3: true}},
		{"no home flags nothing", 0, map[tailcfg.DERPRegionID]bool{1: false, 2: false, 3: false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dm := derpMap(&config.Config{
				Interface: config.Interface{PrivateKey: key.NewNode(), HomeDERP: tc.home},
				Regions:   regions,
			})
			if len(dm.Regions) != len(tc.flagged) {
				t.Fatalf("got %d regions, want %d", len(dm.Regions), len(tc.flagged))
			}
			for id, want := range tc.flagged {
				if got := dm.Regions[id].NoMeasureNoHome; got != want {
					t.Errorf("region %d NoMeasureNoHome = %v, want %v", id, got, want)
				}
			}
		})
	}
}
