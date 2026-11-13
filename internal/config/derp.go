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
		var extras []*tailcfg.DERPNode
		for i, host := range r.Nodes {
			n := tailcfg.DERPNode{
				Name:     fmt.Sprintf("%d-%d", id, i),
				RegionID: region.RegionID,
				HostName: host,
			}
			if r.Addrs == nil {
				region.Nodes = append(region.Nodes, &n)
				continue
			}
			var v4, v6 []string
			for _, a := range r.Addrs[i] {
				if a = a.Unmap(); a.Is4() {
					v4 = append(v4, a.String())
				} else {
					v6 = append(v6, a.String())
				}
			}
			// Unresolved hosts must not consume the finite STUN probe plan.
			for j := range max(len(v4), len(v6)) {
				c := n
				// "none" makes the relay client skip that family instead of
				// resolving the hostname.
				c.IPv4, c.IPv6 = "none", "none"
				if j < len(v4) {
					c.IPv4 = v4[j]
				}
				if j < len(v6) {
					c.IPv6 = v6[j]
				}
				if j == 0 {
					region.Nodes = append(region.Nodes, &c)
					continue
				}
				// Later addresses are dial candidates only, after every
				// host's first addresses.
				c.Name = fmt.Sprintf("%s-%d", n.Name, j)
				c.STUNPort = -1
				extras = append(extras, &c)
			}
		}
		// Netcheck probes the first three nodes, four in the home region,
		// cycling when there are fewer. STUN-only repeats of the hosts keep
		// those probes off the dial-only candidates.
		hosts := len(region.Nodes)
		for i := hosts; len(extras) > 0 && i < 4; i++ {
			c := *region.Nodes[i%hosts]
			c.Name = fmt.Sprintf("%s-r%d", c.Name, i)
			c.STUNOnly = true
			region.Nodes = append(region.Nodes, &c)
		}
		region.Nodes = append(region.Nodes, extras...)
		dm.Regions[region.RegionID] = region
	}
	return dm
}
