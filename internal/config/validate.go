package config

import (
	"fmt"
	"net/netip"

	"tailscale.com/types/key"
)

// validate enforces the rules that span sections of a parsed config. Each
// error names the offending line and the rule it broke.
func validate(cfg *Config, peerLines []int) error {
	if id := cfg.Interface.HomeDERP; id != 0 {
		if _, ok := cfg.Regions[id]; !ok {
			return fmt.Errorf("[Interface] HomeDERP = %d does not match any [DERPRegion]", id)
		}
	}
	self := cfg.Interface.PrivateKey.Public()
	// Masquerading rewrites only one native source address per family, so a
	// second interface address would reach a masqueraded peer unrewritten.
	natives := map[bool]int{} // is IPv4 -> interface address count
	for _, a := range cfg.Interface.Addresses {
		natives[a.Addr().Is4()]++
	}
	pubs := map[key.NodePublic]int{}    // peer public key -> line
	discos := map[key.DiscoPublic]int{} // peer disco key -> line
	for i, p := range cfg.Peers {
		line := peerLines[i]
		if p.PublicKey == self {
			return fmt.Errorf("line %d: [Peer] PublicKey is this node's own public key", line)
		}
		if prev, dup := pubs[p.PublicKey]; dup {
			return fmt.Errorf("line %d: duplicate [Peer] PublicKey (also used by the [Peer] at line %d)", line, prev)
		}
		pubs[p.PublicKey] = line
		if p.WireGuardOnly() {
			// Without a discovery key a peer is reached only at its fixed
			// Endpoint, never through a relay.
			if p.Endpoint == "" || p.HomeDERP != 0 {
				return fmt.Errorf("line %d: [Peer] without DiscoKey requires Endpoint and cannot use HomeDERP", line)
			}
		} else {
			if prev, dup := discos[p.DiscoKey]; dup {
				return fmt.Errorf("line %d: duplicate [Peer] DiscoKey (also used by the [Peer] at line %d)", line, prev)
			}
			discos[p.DiscoKey] = line
		}
		// Restricting one peer must also state the policy for every other peer.
		if p.AllowIn != nil && cfg.Interface.AllowIn == nil {
			return fmt.Errorf("line %d: [Peer] AllowIn requires [Interface] AllowIn", line)
		}
		for _, masq := range []netip.Addr{p.Masquerade4, p.Masquerade6} {
			if !masq.IsValid() {
				continue
			}
			if n := natives[masq.Is4()]; n != 1 {
				return fmt.Errorf("line %d: [Peer] MasqueradeAddress %s requires exactly one [Interface] Address of the same family, found %d", line, masq, n)
			}
		}
		if p.HomeDERP == 0 {
			continue
		}
		// Both ends need a shared relay for call-me-maybe.
		if cfg.Interface.HomeDERP == 0 {
			return fmt.Errorf("line %d: [Peer] HomeDERP requires [Interface] HomeDERP", line)
		}
		if _, ok := cfg.Regions[p.HomeDERP]; !ok {
			return fmt.Errorf("line %d: [Peer] HomeDERP = %d does not match any [DERPRegion]", line, p.HomeDERP)
		}
	}
	return nil
}
