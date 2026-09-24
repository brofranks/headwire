// Package config parses and validates headwire's INI configuration: an
// [Interface] section, optional repeated [DERPRegion] sections forming a
// static DERP map, and repeated [Peer] sections.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/tailscale/wireguard-go/device"
	"go4.org/mem"
	"tailscale.com/types/key"
	"tailscale.com/util/dnsname"
)

// Config is a parsed and validated headwire configuration.
type Config struct {
	Interface Interface
	// Regions holds the inline [DERPRegion] sections keyed by ID. Nil when
	// no regions are configured.
	Regions map[int]Region
	Peers   []Peer
}

// Region is one statically configured DERP region. Nodes contains hostnames
// in connection preference order. DERP uses TLS on 443 and STUN on 3478.
type Region struct {
	ID    int
	Nodes []string
}

// Label names the region for status and diagnostics: its ID and node hostnames.
func (r Region) Label() string {
	return fmt.Sprintf("%d (%s)", r.ID, strings.Join(r.Nodes, ", "))
}

// Interface is the [Interface] section.
type Interface struct {
	PrivateKey key.NodePrivate
	Addresses  []netip.Prefix
	// HomeDERP is the region ID of the node's home DERP region, or 0 if
	// the node uses no DERP.
	HomeDERP int
	// ListenPort 0 requests a random port. MTU 0 uses the engine default.
	ListenPort uint16
	MTU        int
	// DNS and DNSSearch split the DNS key: entries that parse as addresses
	// are nameservers, the rest are search domains. Both apply system-wide
	// while the interface is up.
	DNS       []netip.Addr
	DNSSearch []dnsname.FQDN
	// AllowIn is the inbound policy of peers that set none of their own.
	// Nil admits everything and is only valid while no peer sets AllowIn.
	AllowIn []AllowRule
}

// AllowRule admits inbound packets of the listed IP protocols to a port
// range at Destination. No protocols means every protocol.
type AllowRule struct {
	Protos      []uint8
	First, Last uint16
	Destination AllowDestination
}

// AllowDestination selects any address (the zero value), this node's exact
// interface addresses, or a single prefix. Parsed selectors have only one kind.
type AllowDestination struct {
	Kind   DestinationKind
	Prefix netip.Prefix
}

type DestinationKind uint8

const (
	DestinationAny DestinationKind = iota
	DestinationSelf
	DestinationPrefix
)

// Peer is one [Peer] section. A discovery peer may set Endpoint, HomeDERP,
// both, or neither, and a peer with neither is passive, sendable only after
// an authenticated inbound packet supplies its address.
type Peer struct {
	PublicKey key.NodePublic
	// DiscoKey is the peer's discovery public key, printed by
	// `headwire discokey`. An omitted key identifies an ordinary WireGuard
	// peer with a fixed Endpoint.
	DiscoKey     key.DiscoPublic
	AllowedIPs   []netip.Prefix
	PresharedKey [32]byte // zero when unset
	// Endpoint is a fixed host:port probed as a direct candidate, or empty.
	// Name resolution is deferred to the engine.
	Endpoint string
	// HomeDERP is the peer's home DERP region ID, or 0. Such a peer is relayed
	// until disco probing of Endpoint or of exchanged candidates finds a
	// direct path.
	HomeDERP int
	// Masquerade4 and Masquerade6 replace the interface address of their
	// family as the source of packets sent to this peer, for a peer that
	// knows this node by another address. Invalid when unset.
	Masquerade4, Masquerade6 netip.Addr
	// AllowIn replaces the interface's AllowIn for this peer, which must
	// then be set. Nil when unset, empty admits nothing.
	AllowIn []AllowRule
}

// WireGuardOnly identifies a peer that speaks neither disco nor DERP.
func (p Peer) WireGuardOnly() bool { return p.DiscoKey.IsZero() }

// Parse parses and validates a headwire configuration.
func Parse(src []byte) (*Config, error) {
	sections, err := parseINI(src)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	var peerLines []int
	sawInterface := false
	for i := range sections {
		s := &sections[i]
		switch {
		case strings.EqualFold(s.name, "Interface"):
			if sawInterface {
				return nil, fmt.Errorf("line %d: duplicate [Interface] section", s.line)
			}
			sawInterface = true
			if err := parseInterface(s, &cfg.Interface); err != nil {
				return nil, err
			}
		case strings.EqualFold(s.name, "DERPRegion"):
			r, err := parseRegion(s)
			if err != nil {
				return nil, err
			}
			if _, dup := cfg.Regions[r.ID]; dup {
				return nil, fmt.Errorf("line %d: duplicate DERP region ID %d", s.line, r.ID)
			}
			if cfg.Regions == nil {
				cfg.Regions = map[int]Region{}
			}
			cfg.Regions[r.ID] = r
		case strings.EqualFold(s.name, "Peer"):
			p, err := parsePeer(s)
			if err != nil {
				return nil, err
			}
			cfg.Peers = append(cfg.Peers, p)
			peerLines = append(peerLines, s.line)
		default:
			return nil, fmt.Errorf("line %d: unknown section [%s]", s.line, s.name)
		}
	}
	if !sawInterface {
		return nil, errors.New("missing [Interface] section")
	}
	if err := validate(cfg, peerLines); err != nil {
		return nil, err
	}
	return cfg, nil
}

func parseInterface(s *section, iface *Interface) error {
	if err := s.checkKnownKeys("PrivateKey", "Address", "HomeDERP", "ListenPort", "MTU", "DNS", "AllowIn"); err != nil {
		return err
	}
	v, line, err := s.require("PrivateKey")
	if err != nil {
		return err
	}
	raw, err := DecodeKey(v)
	if err != nil {
		return fmt.Errorf("line %d: PrivateKey: %w", line, err)
	}
	//lint:ignore SA1019 raw keys; see EncodeKey.
	iface.PrivateKey = key.NodePrivateFromRaw32(mem.B(raw[:]))
	if iface.PrivateKey.IsZero() {
		return fmt.Errorf("line %d: PrivateKey: must not be zero", line)
	}

	if iface.Addresses, err = s.prefixes("Address"); err != nil {
		return err
	}
	if len(iface.Addresses) == 0 {
		return fmt.Errorf("line %d: [Interface] missing Address", s.line)
	}

	if err := s.optional("HomeDERP", func(v string) (err error) {
		iface.HomeDERP, err = parseRegionID(v)
		return err
	}); err != nil {
		return err
	}
	if err := s.optional("ListenPort", func(v string) (err error) {
		iface.ListenPort, err = parsePort(v)
		return err
	}); err != nil {
		return err
	}
	if err := s.optional("MTU", func(v string) (err error) {
		if iface.MTU, err = strconv.Atoi(v); err != nil || iface.MTU < 1 || iface.MTU > device.MaxContentSize {
			return fmt.Errorf("must be 1-%d, got %q", device.MaxContentSize, v)
		}
		return nil
	}); err != nil {
		return err
	}
	for line, v := range s.values("DNS") {
		addr, err := netip.ParseAddr(v)
		if err != nil {
			d, err := dnsname.ToFQDN(v)
			if err != nil || d == "." {
				return fmt.Errorf("line %d: DNS: invalid search domain %q", line, v)
			}
			iface.DNSSearch = append(iface.DNSSearch, d)
			continue
		}
		if addr.Zone() != "" {
			return fmt.Errorf("line %d: DNS: zone is only valid in an Endpoint, not a nameserver", line)
		}
		iface.DNS = append(iface.DNS, addr)
	}
	iface.AllowIn, err = s.allowIn()
	return err
}

func parseRegion(s *section) (Region, error) {
	var r Region
	if err := s.checkKnownKeys("ID", "Nodes"); err != nil {
		return r, err
	}
	v, line, err := s.require("ID")
	if err != nil {
		return r, err
	}
	r.ID, err = parseRegionID(v)
	if err != nil {
		return r, fmt.Errorf("line %d: ID: %w", line, err)
	}
	v, line, err = s.require("Nodes")
	if err != nil {
		return r, err
	}
	for hostname := range strings.SplitSeq(v, ",") {
		hostname = strings.TrimSpace(hostname)
		if hostname == "" {
			return r, fmt.Errorf("line %d: empty hostname in Nodes", line)
		}
		r.Nodes = append(r.Nodes, hostname)
	}
	return r, nil
}

func parsePeer(s *section) (Peer, error) {
	var p Peer
	if err := s.checkKnownKeys(
		"PublicKey", "DiscoKey", "AllowedIPs", "PresharedKey",
		"Endpoint", "HomeDERP", "MasqueradeAddress", "AllowIn",
	); err != nil {
		return p, err
	}
	v, line, err := s.require("PublicKey")
	if err != nil {
		return p, err
	}
	raw, err := DecodeKey(v)
	if err != nil {
		return p, fmt.Errorf("line %d: PublicKey: %w", line, err)
	}
	p.PublicKey = key.NodePublicFromRaw32(mem.B(raw[:]))
	if p.PublicKey.IsZero() {
		return p, fmt.Errorf("line %d: PublicKey: must not be zero", line)
	}

	if err := s.optional("DiscoKey", func(v string) error {
		raw, err := DecodeKey(v)
		if err != nil {
			return err
		}
		p.DiscoKey = key.DiscoPublicFromRaw32(mem.B(raw[:]))
		if p.DiscoKey.IsZero() {
			return errors.New("must not be zero")
		}
		//lint:ignore SA1019 raw keys; see EncodeKey.
		if p.DiscoKey.Raw32() == p.PublicKey.Raw32() {
			return errors.New("must differ from PublicKey")
		}
		return nil
	}); err != nil {
		return p, err
	}

	if p.AllowedIPs, err = s.prefixes("AllowedIPs"); err != nil {
		return p, err
	}
	for i, pfx := range p.AllowedIPs {
		p.AllowedIPs[i] = pfx.Masked()
	}

	if err := s.optional("PresharedKey", func(v string) (err error) {
		// The zero key means "no PSK" to WireGuard, so it would look like
		// protection while providing none.
		if p.PresharedKey, err = DecodeKey(v); err == nil && p.PresharedKey == ([32]byte{}) {
			err = errors.New("must not be zero")
		}
		return err
	}); err != nil {
		return p, err
	}
	if err := s.optional("Endpoint", func(v string) error {
		p.Endpoint = v
		return validateEndpoint(v)
	}); err != nil {
		return p, err
	}
	if err := s.optional("HomeDERP", func(v string) (err error) {
		p.HomeDERP, err = parseRegionID(v)
		return err
	}); err != nil {
		return p, err
	}

	for line, v := range s.values("MasqueradeAddress") {
		addr, err := netip.ParseAddr(v)
		if err != nil {
			return p, fmt.Errorf("line %d: MasqueradeAddress: %w", line, err)
		}
		if addr.Zone() != "" {
			return p, fmt.Errorf("line %d: MasqueradeAddress: zone is only valid in an Endpoint", line)
		}
		masq := &p.Masquerade6
		if addr = addr.Unmap(); addr.Is4() {
			masq = &p.Masquerade4
		}
		if masq.IsValid() {
			return p, fmt.Errorf("line %d: MasqueradeAddress: more than one address per family", line)
		}
		*masq = addr
	}
	p.AllowIn, err = s.allowIn()
	return p, err
}

// allowIn accumulates repeated, comma-separated AllowIn rules: "any", "none",
// or a protocol (tcp, udp, sctp, icmp for both families, or a number) with an
// optional /port or /first-last for the protocols that have ports, followed
// by an optional "to self|any|IP|CIDR" destination.
func (s *section) allowIn() ([]AllowRule, error) {
	var rules []AllowRule
	alone := false // unscoped "any" or "none" must be the only rule
	for line, v := range s.values("AllowIn") {
		fields := strings.Fields(v)
		if len(fields) != 1 && (len(fields) != 3 || fields[1] != "to") {
			return nil, fmt.Errorf("line %d: AllowIn: expected protocol[/port[-port]] [to self|any|IP|CIDR]", line)
		}
		rule := AllowRule{Last: 65535}
		if len(fields) == 3 {
			switch fields[2] {
			case "any":
			case "self":
				rule.Destination.Kind = DestinationSelf
			default:
				prefix, err := parsePrefix(fields[2])
				if err != nil {
					return nil, fmt.Errorf("line %d: AllowIn: invalid destination %q: %w", line, fields[2], err)
				}
				rule.Destination = AllowDestination{Kind: DestinationPrefix, Prefix: prefix.Masked()}
			}
		}
		standalone := fields[0] == "none" ||
			fields[0] == "any" && rule.Destination.Kind == DestinationAny
		if alone || rules != nil && standalone {
			return nil, fmt.Errorf("line %d: AllowIn: unscoped any and none cannot be combined with other rules", line)
		}
		alone = standalone
		if fields[0] == "none" && len(fields) == 1 {
			rules = []AllowRule{}
			continue
		}
		name, ports, hasPorts := strings.Cut(fields[0], "/")
		switch name {
		case "any":
		case "tcp":
			rule.Protos = []uint8{6}
		case "udp":
			rule.Protos = []uint8{17}
		case "sctp":
			rule.Protos = []uint8{132}
		case "icmp":
			rule.Protos = []uint8{1, 58}
		default:
			n, err := strconv.ParseUint(name, 10, 8)
			// The filter reserves 0 (unknown), 99 (TSMP) and 255 (its
			// non-first-fragment marker), so no rule controls them.
			if err != nil || n == 0 || n == 99 || n == 255 {
				return nil, fmt.Errorf("line %d: AllowIn: unknown protocol %q", line, name)
			}
			rule.Protos = []uint8{uint8(n)}
		}
		if hasPorts {
			if !slices.Contains([]string{"tcp", "udp", "sctp"}, name) {
				return nil, fmt.Errorf("line %d: AllowIn: %s takes no port", line, name)
			}
			first, last, isRange := strings.Cut(ports, "-")
			if !isRange {
				last = first
			}
			lo, err1 := strconv.ParseUint(first, 10, 16)
			hi, err2 := strconv.ParseUint(last, 10, 16)
			if err1 != nil || err2 != nil || lo > hi {
				return nil, fmt.Errorf("line %d: AllowIn: invalid port %q", line, ports)
			}
			rule.First, rule.Last = uint16(lo), uint16(hi)
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	if addr.Zone() != "" {
		return netip.Prefix{}, errors.New("zone is only valid in an Endpoint, not an address prefix")
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// prefixes accumulates repeated, comma-separated address or AllowedIPs lines.
// An absent field is empty, but an explicitly empty entry is a parse error.
func (s *section) prefixes(name string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for line, value := range s.values(name) {
		prefix, err := parsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("line %d: %s: %w", line, name, err)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

// HasAddress tests exact interface addresses, not their surrounding subnets.
func (i Interface) HasAddress(addr netip.Addr) bool {
	for _, prefix := range i.Addresses {
		if prefix.Addr() == addr {
			return true
		}
	}
	return false
}

func parseRegionID(s string) (int, error) {
	id, err := strconv.Atoi(s)
	if err != nil || id < 1 || id > 65535 {
		return 0, fmt.Errorf("region ID must be 1-65535, got %q", s)
	}
	return id, nil
}

func validateEndpoint(s string) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return err
	}
	if host == "" {
		return fmt.Errorf("host in %q must not be empty", s)
	}
	if _, err := parsePort(port); err != nil {
		return fmt.Errorf("invalid port in %q", s)
	}
	return nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("port must be 0-65535, got %q", s)
	}
	return uint16(n), nil
}

// EncodeKey renders 32 raw key bytes in the base64 form used by the config
// file and `pubkey` output. WireGuard-format configuration and interoperability
// are why Headwire reads raw keys out of Tailscale's key types, which deprecate
// that access (SA1019).
func EncodeKey(raw [32]byte) string {
	return base64.StdEncoding.EncodeToString(raw[:])
}

// DecodeKey parses a base64 32-byte key strictly: exactly 44 characters in
// canonical encoding.
func DecodeKey(s string) (raw [32]byte, err error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(s) != 44 || len(b) != len(raw) {
		return raw, errors.New("key must be 44 base64 characters encoding exactly 32 bytes")
	}
	copy(raw[:], b)
	return raw, nil
}
