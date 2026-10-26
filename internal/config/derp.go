package config

import (
	"fmt"
	"net/netip"

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
			n := &tailcfg.DERPNode{
				Name:     fmt.Sprintf("%d-%d", id, i),
				RegionID: region.RegionID,
				HostName: host,
			}
			if r.Addrs != nil {
				n.IPv4 = dialIP(r.Addrs[i], netip.Addr.Is4)
				n.IPv6 = dialIP(r.Addrs[i], netip.Addr.Is6)
			}
			region.Nodes = append(region.Nodes, n)
		}
		dm.Regions[region.RegionID] = region
	}
	return dm
}

// dialIP returns the first address in addrs of the family is reports, or
// "none" so the relay client skips that family instead of resolving the
// hostname.
func dialIP(addrs []netip.Addr, is func(netip.Addr) bool) string {
	for _, a := range addrs {
		if is(a.Unmap()) {
			return a.Unmap().String()
		}
	}
	return "none"
}
