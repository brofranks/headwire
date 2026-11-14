package engine

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"brof.dev/headwire/internal/config"
	"github.com/gaissmai/bart"
	"go4.org/netipx"
	"tailscale.com/types/key"
)

// sourcePermissions converts global longest-prefix ownership of AllowedIPs
// into disjoint sets for the fork's per-peer source checks. Equal prefixes
// belong to the last configured peer. This node's own addresses belong to
// no peer: a default-route peer would otherwise be allowed to send as this
// node, which only a Linux kernel TUN rejects by itself.
func sourcePermissions(cfg *config.Config) (map[key.NodePublic]*netipx.IPSet, error) {
	var owners bart.Table[key.NodePublic]
	builders := map[key.NodePublic]*netipx.IPSetBuilder{}
	for _, p := range cfg.Peers {
		builders[p.PublicKey] = new(netipx.IPSetBuilder)
		for _, prefix := range p.AllowedIPs {
			if !prefix.IsValid() {
				return nil, fmt.Errorf("peer %s has an invalid AllowedIPs prefix", p.PublicKey.ShortString())
			}
			owners.Insert(prefix.Masked(), p.PublicKey)
		}
	}
	for _, a := range cfg.Interface.Addresses {
		if !a.IsValid() {
			return nil, errors.New("invalid interface address")
		}
		owners.Insert(netip.PrefixFrom(a.Addr(), a.Addr().BitLen()), key.NodePublic{})
	}
	var boundaries []netip.Addr
	for prefix := range owners.All() {
		boundaries = append(boundaries, prefix.Addr())
		if next := netipx.PrefixLastIP(prefix).Next(); next.IsValid() {
			boundaries = append(boundaries, next)
		}
	}
	slices.SortFunc(boundaries, netip.Addr.Compare)
	boundaries = slices.Compact(boundaries)
	// Ownership is constant between consecutive prefix boundaries.
	for i, from := range boundaries {
		owner, ok := owners.Lookup(from)
		if !ok || owner.IsZero() {
			continue
		}
		to := netipx.PrefixLastIP(netip.PrefixFrom(from, 0))
		if i+1 < len(boundaries) && boundaries[i+1].BitLen() == from.BitLen() {
			to = boundaries[i+1].Prev()
		}
		builders[owner].AddRange(netipx.IPRangeFrom(from, to))
	}
	allowed := make(map[key.NodePublic]*netipx.IPSet, len(builders))
	for k, b := range builders {
		allowed[k], _ = b.IPSet() // the sweep adds only ordered same-family ranges
	}
	return allowed, nil
}

// checkSourceOwnership keeps every existing peer's source permissions
// unchanged, because an in-flight lazy peer creation in the pinned engine can
// install the previous permissions after reload. A removed peer counts as
// owning nothing, so removing one that owns no addresses changes nothing.
func (st *state) checkSourceOwnership(next *state) error {
	for _, p := range st.cfg.Peers {
		if !st.allowed[p.PublicKey].Equal(cmp.Or(next.allowed[p.PublicKey], new(netipx.IPSet))) {
			return fmt.Errorf("reload would change source permissions of peer %s, so restart to apply AllowedIPs changes, ownership transfers or peer removal", p.PublicKey.ShortString())
		}
	}
	return nil
}
