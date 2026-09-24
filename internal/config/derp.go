package config

import (
	"fmt"

	"tailscale.com/tailcfg"
)

// DERPMap returns the configured relay regions without public defaults.
func (cfg *Config) DERPMap() *tailcfg.DERPMap {
	dm := &tailcfg.DERPMap{
		OmitDefaultRegions: true,
		Regions:            map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{},
	}
	for id, r := range cfg.Regions {
		region := &tailcfg.DERPRegion{
			RegionID:   tailcfg.DERPRegionID(id),
			RegionCode: fmt.Sprint(id),
		}
		for i, host := range r.Nodes {
			region.Nodes = append(region.Nodes, &tailcfg.DERPNode{
				Name:     fmt.Sprintf("%d-%d", id, i),
				RegionID: region.RegionID,
				HostName: host,
			})
		}
		dm.Regions[region.RegionID] = region
	}
	return dm
}
