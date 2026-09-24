package engine

import (
	"cmp"
	"fmt"
	"maps"
	"net/netip"
	"slices"

	"brof.dev/headwire/internal/config"
	"go4.org/netipx"
	"tailscale.com/types/key"
)

// sourcePermissions converts global longest-prefix ownership of AllowedIPs
// into disjoint sets for the fork's per-peer source checks. Equal prefixes
// belong to the last configured peer. This node's own addresses belong to
// no peer: a default-route peer would otherwise be allowed to send as this
// node, which only a Linux kernel TUN rejects by itself.
func sourcePermissions(cfg *config.Config) (map[key.NodePublic]*netipx.IPSet, error) {
	owners := map[netip.Prefix]key.NodePublic{}
	builders := map[key.NodePublic]*netipx.IPSetBuilder{}
	for _, p := range cfg.Peers {
		builders[p.PublicKey] = new(netipx.IPSetBuilder)
		for _, prefix := range p.AllowedIPs {
			owners[prefix.Masked()] = p.PublicKey
		}
	}
	prefixes := slices.SortedFunc(maps.Keys(owners), func(a, b netip.Prefix) int {
		return cmp.Or(cmp.Compare(b.Bits(), a.Bits()), a.Compare(b))
	})
	var claimed netipx.IPSetBuilder
	for _, a := range cfg.Interface.Addresses {
		claimed.Add(a.Addr())
	}
	for _, prefix := range prefixes {
		used, err := claimed.IPSet()
		if err != nil {
			return nil, err
		}
		var remaining netipx.IPSetBuilder
		remaining.AddPrefix(prefix)
		remaining.RemoveSet(used)
		set, err := remaining.IPSet()
		if err != nil {
			return nil, err
		}
		builders[owners[prefix]].AddSet(set)
		claimed.AddPrefix(prefix)
	}
	allowed := make(map[key.NodePublic]*netipx.IPSet, len(builders))
	for k, b := range builders {
		allowed[k], _ = b.IPSet() // built only from validated sets
	}
	return allowed, nil
}

// checkSourceOwnership prevents revocation from racing an in-flight lazy
// peer creation in the pinned engine. Additive changes are safe:
// an old config can be more restrictive, but never grants a revoked source.
func (st *state) checkSourceOwnership(next *state) error {
	for _, p := range st.cfg.Peers {
		for _, prefix := range st.allowed[p.PublicKey].Prefixes() {
			allowed := next.allowed[p.PublicKey]
			if allowed == nil || !allowed.ContainsPrefix(prefix) {
				return fmt.Errorf("reload would revoke source ownership from peer %s, so restart to apply AllowedIPs reductions, ownership transfers or peer removal", p.PublicKey.ShortString())
			}
		}
	}
	return nil
}
