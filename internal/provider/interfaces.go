package provider

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"

	"tailscale.com/net/netmon"
)

// Android denies net.Interfaces to app UIDs, so the host app sends the
// interface list it reads from ConnectivityManager as JSON:
//
//	[{"name":"wlan0","index":3,"mtu":1500,"up":true,
//	  "addresses":["192.168.1.5/24","fe80::1/64"]}]
type hostInterface struct {
	Name      string   `json:"name"`
	Index     int      `json:"index"`
	MTU       int      `json:"mtu"`
	Up        bool     `json:"up"`
	Addresses []string `json:"addresses"`
}

// parseInterfaces decodes the host's interface list. AltAddrs is never nil,
// since netmon falls back to net.Interface.Addrs for a nil slice.
func parseInterfaces(js []byte) ([]netmon.Interface, error) {
	var hosts []hostInterface
	if err := json.Unmarshal(js, &hosts); err != nil {
		return nil, fmt.Errorf("interfaces: %w", err)
	}
	ifs := make([]netmon.Interface, 0, len(hosts))
	for _, h := range hosts {
		if h.Name == "" {
			return nil, fmt.Errorf("interfaces: entry %d has no name", len(ifs))
		}
		addrs := make([]net.Addr, 0, len(h.Addresses))
		for _, a := range h.Addresses {
			p, err := netip.ParsePrefix(a)
			if err != nil {
				return nil, fmt.Errorf("interfaces: %s: %w", h.Name, err)
			}
			addrs = append(addrs, &net.IPNet{
				IP:   p.Addr().AsSlice(),
				Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen()),
			})
		}
		var flags net.Flags
		if h.Up {
			flags = net.FlagUp | net.FlagRunning
		}
		ifs = append(ifs, netmon.Interface{
			Interface: &net.Interface{
				Index: h.Index,
				MTU:   h.MTU,
				Name:  h.Name,
				Flags: flags,
			},
			AltAddrs: addrs,
		})
	}
	return ifs, nil
}
