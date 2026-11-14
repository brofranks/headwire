package engine

import (
	"net/netip"
	"slices"

	"go4.org/netipx"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
	"tailscale.com/types/views"
	"tailscale.com/wgengine/filter"

	"brof.dev/headwire/internal/config"
)

// anyPrefixes is every address of both families, as the prefixes a rule
// without a destination admits and, as an IP set, the filter's local net.
var anyPrefixes, allIPs = func() ([]netip.Prefix, *netipx.IPSet) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	var b netipx.IPSetBuilder
	for _, prefix := range prefixes {
		b.AddPrefix(prefix)
	}
	set, _ := b.IPSet() // the literal prefixes above are always valid
	return prefixes, set
}()

// protocols is every IP protocol number, for a rule that names none.
var protocols = func() []ipproto.Proto {
	all := make([]ipproto.Proto, 256)
	for i := range all {
		all[i] = ipproto.Proto(i)
	}
	return all
}()

// newFilter admits each peer's AllowIn rules from the sources that peer owns,
// to each rule's destinations. The default rule leaves source ownership to
// AllowedIPs without restricting the tunnel to TCP, UDP and ICMP. tailscale's
// filter decoder still rejects malformed packets and handles reserved and
// internal protocols. share carries the previous filter's flow state across
// a reload.
func newFilter(st *state, share *filter.Filter, logf logger.Logf) *filter.Filter {
	return filter.New(filterMatches(st), nil, allIPs, allIPs, share, logf)
}

// filterMatches emits one match per distinct grant. Peers whose rules grant
// identical protocols, ports and destination share that match, whose sources
// are every such peer's owned prefixes, so packet matching scans policies
// rather than peers.
func filterMatches(st *state) []filter.Match {
	type grant struct {
		protos      string // the rule's protocol numbers, empty for any
		first, last uint16
		destination config.AllowDestination
	}
	grants := map[grant]int{}
	self := hostAddrs(st.cfg.Interface.Addresses)
	var matches []filter.Match
	for _, p := range st.cfg.Peers {
		rules := p.AllowIn
		if rules == nil {
			rules = st.cfg.Interface.AllowIn
		}
		if rules == nil {
			rules = []config.AllowRule{{Last: 65535}}
		}
		// Clipped so appending to one match never writes into another that
		// shares this peer's slice.
		srcs := slices.Clip(st.allowed[p.PublicKey].Prefixes())
		for _, r := range rules {
			g := grant{string(r.Protos), r.First, r.Last, r.Destination}
			if i, ok := grants[g]; ok {
				matches[i].Srcs = append(matches[i].Srcs, srcs...)
				continue
			}
			grants[g] = len(matches)
			protos := protocols
			if r.Protos != nil {
				protos = make([]ipproto.Proto, len(r.Protos))
				for i, n := range r.Protos {
					protos[i] = ipproto.Proto(n)
				}
			}
			destinations := anyPrefixes
			switch r.Destination.Kind {
			case config.DestinationSelf:
				destinations = self
			case config.DestinationPrefix:
				destinations = []netip.Prefix{r.Destination.Prefix}
			}
			var dsts []filter.NetPortRange
			ports := filter.PortRange{First: r.First, Last: r.Last}
			for _, dst := range destinations {
				dsts = append(dsts, filter.NetPortRange{Net: dst, Ports: ports})
			}
			matches = append(matches, filter.Match{
				IPProto: views.SliceOf(protos),
				Srcs:    srcs,
				Dsts:    dsts,
			})
		}
	}
	return matches
}
