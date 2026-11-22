// Package engine drives tailscale.com's wgengine and magicsock from a static
// headwire configuration: no control plane, no LocalBackend. The config is
// translated once into a DERP map and a network map, and per-peer config is
// served to the engine lazily. Each DERP-mode peer starts on its home relay,
// and magicsock exchanges disco call-me-maybe messages over it so both sides
// can upgrade to a direct path.
package engine

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"

	"brof.dev/headwire/internal/config"
	"brof.dev/headwire/internal/discokey"
	"github.com/gaissmai/bart"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"go4.org/netipx"
	"tailscale.com/health"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/routemanager"
	"tailscale.com/net/tsdial"
	"tailscale.com/net/tstun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/syspolicy/policyclient"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"

	// Registers the UPnP/NAT-PMP/PCP port mapper magicsock uses to open
	// pinholes. The OS router used in TUN mode is registered by cmd/headwire.
	_ "tailscale.com/feature/condregister/portmapper"
)

// TUNName is the interface name in TUN mode. Darwin allocates the next utun,
// and Windows names the Wintun adapter Headwire.
const TUNName = "headwire0"

// Options selects how the engine attaches to the network: a kernel TUN the
// engine creates, which needs root, unless Tun is set.
type Options struct {
	// Tun is an open packet device supplied by the caller, such as the utun
	// descriptor handed to an Apple NetworkExtension provider. The host owns
	// the interface address and routes, so the engine installs no OS router.
	// Start takes ownership of Tun and closes it on failure. After a
	// successful Start, Close releases it.
	Tun tun.Device
}

// Engine is a running headwire node.
type Engine struct {
	logf    logger.Logf
	tunName string
	state   atomic.Pointer[state]

	bus    *eventbus.Bus
	netMon *netmon.Monitor
	dialer *tsdial.Dialer
	eng    wgengine.Engine
	tun    *tstun.Wrapper
	mc     *magicsock.Conn

	dnsMu   sync.Mutex         // serializes DNS updates and restoration
	hostDNS dns.OSConfigurator // set when a kernel TUN has DNS
	unwatch func()             // stops the link-change callback

	mu    sync.Mutex       // serializes Reload and repick
	epsMu sync.Mutex       // guards eps
	eps   []netip.AddrPort // our endpoints as magicsock last reported them
}

// state is one immutable view of the configuration. Reload swaps it whole
// so the engine's lookup callbacks never see a half-applied change.
type state struct {
	// cfg is the configuration with each Endpoint's addresses resolved into
	// its peer's Addrs, so a network change picks again without DNS.
	cfg     *config.Config
	peers   map[key.NodePublic]config.Peer
	nodes   map[key.NodePublic]tailcfg.NodeView // nm.Peers by key
	allowed map[key.NodePublic]*netipx.IPSet
	routes  bart.Table[tailcfg.NodeView]
	nm      *netmap.NetworkMap
	// ids are the netmap node IDs handed out to peers, including peers since
	// removed. A peer keeps its ID across reloads: magicsock addresses peers
	// by ID and requires them to be unique and stable.
	ids map[key.NodePublic]tailcfg.NodeID
}

// Start brings the node up. Close releases it.
func Start(cfg *config.Config, logf logger.Logf, opts Options) (_ *Engine, err error) {
	e := &Engine{logf: logf}
	defer func() {
		if err != nil {
			e.Close()
		}
	}()

	e.bus = eventbus.New()
	tracker := health.NewTracker(e.bus)
	dev, rtr, err := e.attach(cfg, tracker, opts.Tun)
	if err != nil {
		return nil, err
	}
	e.dialer = &tsdial.Dialer{Logf: logf}
	e.dialer.SetNetMon(e.netMon)
	// ListenPort is configured explicitly when fixed-endpoint peers need to
	// name it. An omitted or zero port lets the OS choose.
	conf := wgengine.Config{
		Tun:           dev,
		Router:        rtr,
		NetMon:        e.netMon,
		HealthTracker: tracker,
		Metrics:       new(usermetric.Registry),
		Dialer:        e.dialer,
		EventBus:      e.bus,
		ListenPort:    cfg.Interface.ListenPort,
		ForceDiscoKey: discokey.PrivateForNode(cfg.Interface.PrivateKey),
		// The app name identifies Headwire to DERP operators.
		DERPAppName: "headwire",
		SetSubsystem: func(s any) {
			switch s := s.(type) {
			case *tstun.Wrapper:
				e.tun = s
			case *magicsock.Conn:
				e.mc = s
			}
		},
	}
	if e.eng, err = wgengine.NewUserspaceEngine(logf, conf); err != nil {
		return nil, err
	}
	// LocalBackend normally turns magicsock's per-message disco lines on from
	// a debug preference. They are all [v1], which every host's log writer
	// hides unless LOG_LEVEL is verbose or debug.
	e.mc.SetDebugLoggingEnabled(true)
	// magicsock falls back to a random port when the requested one is taken,
	// but Endpoint peers depend on the port. LocalPort exposes IPv4 only: it
	// cannot detect an IPv6-only fallback.
	if port := cfg.Interface.ListenPort; port != 0 && e.mc.LocalPort() != port {
		return nil, fmt.Errorf("UDP port %d: address already in use", port)
	}
	// The wrapper buffers all traffic until told the stack above it is ready.
	e.tun.Start()

	st, err := newState(cfg, nil, e.netMon.InterfaceState())
	if err != nil {
		return nil, err
	}
	e.state.Store(st)
	logf("disco public key: %v", e.mc.DiscoPublicKey())
	e.mc.SetPrivateKey(cfg.Interface.PrivateKey)
	e.mc.SetDERPMap(derpMap(cfg))
	if cfg.Interface.HomeDERP != 0 {
		// Peers relay to us via [Interface] HomeDERP and nothing can tell
		// them it moved, so set that region home before the first netcheck
		// rather than letting measured latency choose it. magicsock keeps
		// the home it already has, so a region that is down when the node
		// starts is retried instead of replaced.
		e.mc.ForceSetNearestDERP(tailcfg.DERPRegionID(cfg.Interface.HomeDERP))
	}
	e.mc.SetNetworkMap(st.nm.SelfNode, st.nm.Peers)
	e.eng.SetSelfNode(st.nm.SelfNode)
	e.mc.SetNetworkUp(true)
	e.eng.SetPeerConfigFunc(e.peerConfig)
	e.eng.SetPeerByIPPacketFunc(e.peerByIP)
	e.eng.SetPeerForIPFunc(e.peerForIP)
	e.eng.SetStatusCallback(e.onStatus)
	// tstun drops every packet until a filter is installed. AllowedIPs
	// enforce source ownership and AllowIn adds the protocol ACL.
	e.eng.SetFilter(newFilter(st, nil, logf))
	e.setPeerRoutes(st)

	if err := e.reconfig(cfg); err != nil {
		return nil, err
	}
	// The interface has its address by now, which resolved requires. The
	// resolvers go to the OS as configured: the engine's DNS manager would
	// route some public addresses through a forwarder headwire does not run.
	set := func() error {
		return e.setDNS(dns.OSConfig{Nameservers: cfg.Interface.DNS, SearchDomains: cfg.Interface.DNSSearch})
	}
	if err := set(); err != nil {
		return nil, err
	}
	e.unwatch = e.netMon.RegisterChangeCallback(func(d *netmon.ChangeDelta) {
		// Callbacks run unordered, so take the monitor's latest state rather
		// than the change that triggered this one.
		e.repick(e.netMon.InterfaceState)
		// NetworkManager restarts and suspend/resume clear resolved's
		// per-link settings, so a major link change re-applies them.
		if d.RebindLikelyRequired && d.AnyInterfaceUp() {
			if err := set(); err != nil {
				e.logf("dns: re-apply after link change: %v", err)
			}
		}
	})
	// A change between the state read above and the registration is picked up
	// here.
	e.repick(e.netMon.InterfaceState)
	return e, nil
}

// derpMap builds the map the engine installs. Every region other than the
// node's home is marked NoMeasureNoHome, so netcheck neither measures it nor
// selects it as home. Only the home region can be. Such a region stays
// connectable for reaching a peer that calls it home.
func derpMap(cfg *config.Config) *tailcfg.DERPMap {
	dm := cfg.DERPMap()
	for id, r := range dm.Regions {
		r.NoMeasureNoHome = cfg.Interface.HomeDERP != 0 &&
			id != tailcfg.DERPRegionID(cfg.Interface.HomeDERP)
	}
	return dm
}

// Host checks, the kernel device and DNS need OS access, so tests replace them.
var (
	checkHost         = checkKernelConfig
	createTUN         = tun.CreateTUN
	newOSConfigurator = func(
		e *Engine,
		tracker *health.Tracker,
		dev tun.Device,
	) (dns.OSConfigurator, error) {
		name, err := dnsInterfaceName(dev)
		if err != nil {
			return nil, err
		}
		// The Windows configurator refuses a nil policy client.
		return dns.NewOSConfigurator(e.logf, tracker, e.bus,
			policyclient.NoPolicyClient{}, nil, name)
	}
)

// attach opens the packet device, registers it with netmon as the tunnel,
// and creates the network monitor, recording them in e.tunName and e.netMon.
// For a device this process creates it also returns the OS router and sets
// e.hostDNS. attach closes either device on failure.
func (e *Engine) attach(
	cfg *config.Config,
	tracker *health.Tracker,
	injected tun.Device,
) (_ tun.Device, rtr router.Router, err error) {
	dev := injected
	if dev == nil {
		if dev, err = kernelTUN(cfg); err != nil {
			return nil, nil, err
		}
	}
	defer func() {
		if err != nil {
			dev.Close()
		}
	}()
	if e.tunName, err = dev.Name(); err != nil {
		return nil, nil, err
	}
	// netmon otherwise identifies its own tunnel by Tailscale's interface
	// names and addresses, which Headwire's are not. Registering it keeps the
	// tunnel out of netmon's link state and out of the local endpoints
	// magicsock advertises, which would offer peers a "direct" path through
	// the tunnel itself. The setting is process-wide, and it precedes the
	// monitor because the monitor's first snapshot decides which address
	// family an ordinary peer's endpoint is chosen from.
	netmon.SetTailscaleInterfaceProps(e.tunName, 0)
	if e.netMon, err = netmon.New(e.bus, e.logf); err != nil {
		return nil, nil, err
	}
	if injected != nil {
		return dev, nil, nil
	}
	// The process that owns the interface sets the host's DNS. Without a
	// nameserver no configurator exists, so the host's resolver setup is
	// neither probed nor touched.
	if len(cfg.Interface.DNS) > 0 {
		if e.hostDNS, err = newOSConfigurator(e, tracker, dev); err != nil {
			return nil, nil, err
		}
	}
	if rtr, err = router.New(e.logf, dev, e.netMon, tracker, e.bus); err != nil {
		return nil, nil, err
	}
	return dev, rtr, nil
}

// kernelTUN creates the interface this process owns.
func kernelTUN(cfg *config.Config) (tun.Device, error) {
	if err := checkHost(cfg); err != nil {
		return nil, err
	}
	name := TUNName
	switch runtime.GOOS {
	case "darwin":
		name = "utun"
	case "windows":
		name = "Headwire"
		// The Windows router resets the adapter MTU to the engine default on
		// every reconfiguration.
		if mtu := int(tstun.DefaultTUNMTU()); MTU(cfg) != mtu {
			return nil, fmt.Errorf("MTU is fixed at %d on Windows", mtu)
		}
	}
	return createTUN(name, MTU(cfg))
}

// MTU is the interface MTU: the configured one, else the engine's default.
func MTU(cfg *config.Config) int {
	return cmp.Or(cfg.Interface.MTU, int(tstun.DefaultTUNMTU()))
}

// reconfig applies the interface address and the routes implied by every
// peer's AllowedIPs. Peers are not configured here: the engine pulls them
// lazily through peerConfig. The engine's DNS manager gets nothing, because
// Start sets host DNS itself.
func (e *Engine) reconfig(cfg *config.Config) error {
	return e.eng.Reconfig(
		&wgcfg.Config{PrivateKey: cfg.Interface.PrivateKey, Addresses: cfg.Interface.Addresses},
		&router.Config{LocalAddrs: hostAddrs(cfg.Interface.Addresses), Routes: Routes(cfg)},
		&dns.Config{})
}

// hostAddrs narrows interface addresses to the single addresses this node
// answers for. The configured prefix sizes the interface's subnet, which
// Routes carries. Everywhere else a subnet claims addresses that belong to
// peers. The engine loops packets sent to a local address back into the host
// on darwin instead of the tunnel.
func hostAddrs(addrs []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, len(addrs))
	for i, a := range addrs {
		out[i] = netip.PrefixFrom(a.Addr(), a.Addr().BitLen())
	}
	return out
}

// setPeerRoutes gives the tun wrapper each peer's MasqueradeAddress, the
// per-peer NAT a control plane configures for Tailscale. The wrapper looks
// destinations up by longest prefix, so the table holds every peer: a mesh
// peer's /32 must win over an exit peer's /0.
func (e *Engine) setPeerRoutes(st *state) {
	if !slices.ContainsFunc(
		st.cfg.Peers,
		func(p config.Peer) bool { return p.Masquerade4.IsValid() || p.Masquerade6.IsValid() },
	) {
		e.eng.SetPeerRoutes(netip.Addr{}, netip.Addr{}, nil)
		return
	}
	var native4, native6 netip.Addr
	for _, a := range slices.Backward(st.cfg.Interface.Addresses) {
		if a.Addr().Is4() {
			native4 = a.Addr()
		} else {
			native6 = a.Addr()
		}
	}
	routes := new(bart.Table[*routemanager.PeerRoute])
	for k, p := range st.peers {
		route := &routemanager.PeerRoute{Key: k, MasqAddr4: p.Masquerade4, MasqAddr6: p.Masquerade6}
		for _, pfx := range st.allowed[k].Prefixes() {
			routes.Insert(pfx, route)
		}
	}
	e.eng.SetPeerRoutes(native4, native6, routes)
}

// Routes is what the host must route into the tunnel: each interface subnet
// and every peer's AllowedIPs. An embedder that owns the interface installs
// these itself.
func Routes(cfg *config.Config) []netip.Prefix {
	var routes []netip.Prefix
	for _, a := range cfg.Interface.Addresses {
		if !a.IsSingleIP() {
			routes = append(routes, a.Masked())
		}
	}
	for _, p := range cfg.Peers {
		routes = append(routes, p.AllowedIPs...)
	}
	slices.SortFunc(routes, netip.Prefix.Compare)
	return slices.Compact(routes)
}

// NetworkChanged tells the engine the host's interfaces changed, for hosts
// whose sandbox hides the route socket the monitor listens on.
func (e *Engine) NetworkChanged() { e.netMon.InjectEvent() }

// repick reads the latest network state under the apply lock and gives each
// ordinary peer an endpoint in an available family, without resolving names.
func (e *Engine) repick(interfaceState func() *netmon.State) {
	e.mu.Lock()
	defer e.mu.Unlock()
	old := e.state.Load()
	st, err := newState(old.cfg, old.ids, interfaceState())
	if err != nil {
		e.logf("endpoints: %v", err)
		return
	}
	e.apply(old, st)
}

// ReloadApplyError means publication has occurred and the engine must be
// closed. The caller must not continue serving or retry against partially
// applied state.
type ReloadApplyError struct{ Err error }

func (e *ReloadApplyError) Error() string { return "reload partially applied: " + e.Err.Error() }

// Reload applies a changed configuration to the running node: peer additions
// and updates preserve existing sessions. Changes to an existing peer's
// PresharedKey or source permissions, including peer removal and ownership
// transfers, require restart, because the pinned engine can apply a stale lazy
// peer config after a sync. Only [Peer] sections and AllowIn may change. Other
// [Interface] and [DERPRegion] changes are refused and the old configuration
// stays live.
func (e *Engine) Reload(cfg *config.Config) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	old := e.state.Load()
	before, after := old.cfg.Interface, cfg.Interface
	before.MTU, after.MTU = MTU(old.cfg), MTU(cfg)
	after.AllowIn = before.AllowIn // applied live below
	if !reflect.DeepEqual(after, before) || !reflect.DeepEqual(cfg.Regions, old.cfg.Regions) {
		return errors.New("reload can only change [Peer] sections and AllowIn, so restart to apply other [Interface] or [DERPRegion] changes")
	}
	for _, p := range cfg.Peers {
		was, ok := old.peers[p.PublicKey]
		if ok && was.PresharedKey != p.PresharedKey {
			return fmt.Errorf("peer %s: restart to change PresharedKey", p.PublicKey.ShortString())
		}
		if ok && was.WireGuardOnly() != p.WireGuardOnly() {
			return fmt.Errorf("peer %s: restart to add or remove DiscoKey", p.PublicKey.ShortString())
		}
	}
	st, err := newState(cfg, old.ids, e.netMon.InterfaceState())
	if err != nil {
		return err
	}
	if err := old.checkSourceOwnership(st); err != nil {
		return err
	}
	e.apply(old, st)
	if err := e.reconfig(cfg); err != nil && !errors.Is(err, wgengine.ErrNoChanges) {
		return &ReloadApplyError{Err: err}
	}
	return nil
}

// apply publishes st in place of old and brings the filter, peer routes and
// magicsock's peers in line with it. Unchanged peers are left alone, and an
// updated peer keeps its session.
func (e *Engine) apply(old, st *state) {
	e.state.Store(st)
	e.eng.SetFilter(newFilter(st, e.tun.GetFilter(), e.logf))
	e.setPeerRoutes(st)
	for k := range old.peers {
		if _, ok := st.peers[k]; !ok {
			e.mc.RemovePeer(old.ids[k])
			e.eng.SyncDevicePeer(k)
		}
	}
	for _, p := range st.cfg.Peers {
		was, existed := old.peers[p.PublicKey]
		was.AllowIn = p.AllowIn // the filter above already applied it
		if existed && reflect.DeepEqual(was, p) &&
			slices.Equal(
				old.nodes[p.PublicKey].Endpoints().AsSlice(),
				st.nodes[p.PublicKey].Endpoints().AsSlice(),
			) {
			continue
		}
		e.mc.UpsertPeer(st.nodes[p.PublicKey])
		e.eng.SyncDevicePeer(p.PublicKey)
		if existed && was.DiscoKey != p.DiscoKey {
			// A new disco key means the peer restarted with a new node
			// identity's derivation, so its old sessions are dead.
			e.eng.MarkDevicePeerForHandshake(p.PublicKey)
		}
	}
}

// setDNS serializes resolver updates with shutdown restoration.
func (e *Engine) setDNS(c dns.OSConfig) error {
	e.dnsMu.Lock()
	defer e.dnsMu.Unlock()
	if e.hostDNS == nil {
		return nil
	}
	return e.hostDNS.SetDNS(c)
}

// Close tears the node down in reverse dependency order.
func (e *Engine) Close() {
	if e.unwatch != nil {
		e.unwatch()
	}
	e.dnsMu.Lock()
	if e.hostDNS != nil {
		e.hostDNS.Close()
		e.hostDNS = nil
	}
	e.dnsMu.Unlock()
	if e.eng != nil {
		e.eng.Close()
	}
	if e.netMon != nil {
		e.netMon.Close()
	}
	if e.dialer != nil {
		e.dialer.Close()
	}
	if e.bus != nil {
		e.bus.Close()
	}
}

// newState synthesises the netmap a control plane would have sent: self as
// node 1 and each configured peer under its stable ID. Endpoint-mode peers
// get their (resolved) endpoint seeded, DERP-mode peers their home region,
// and passive peers neither. An Endpoint whose peer has no Addrs is resolved,
// and ifs, if known, selects among an ordinary peer's addresses. ids are the
// running state's, and a rejected candidate leaves them untouched.
func newState(
	cfg *config.Config,
	ids map[key.NodePublic]tailcfg.NodeID,
	ifs *netmon.State,
) (*state, error) {
	allowed, err := sourcePermissions(cfg)
	if err != nil {
		return nil, err
	}
	self := cfg.Interface
	st := &state{
		peers:   map[key.NodePublic]config.Peer{},
		nodes:   map[key.NodePublic]tailcfg.NodeView{},
		allowed: allowed,
		ids:     map[key.NodePublic]tailcfg.NodeID{},
		nm: &netmap.NetworkMap{
			NodeKey: self.PrivateKey.Public(),
			SelfNode: (&tailcfg.Node{
				ID:         1,
				StableID:   "1",
				Name:       "self.headwire.",
				User:       100,
				Key:        self.PrivateKey.Public(),
				DiscoKey:   discokey.PublicForNode(self.PrivateKey),
				Addresses:  hostAddrs(self.Addresses),
				AllowedIPs: self.Addresses,
				HomeDERP:   tailcfg.DERPRegionID(self.HomeDERP),
			}).View(),
		},
	}
	maps.Copy(st.ids, ids)
	resolved := *cfg
	resolved.Peers = slices.Clone(cfg.Peers)
	st.cfg = &resolved
	for i := range resolved.Peers {
		p := &resolved.Peers[i]
		if p.Addrs == nil && p.Endpoint != "" {
			if p.Addrs, err = ResolveEndpoint(*p); err != nil {
				return nil, err
			}
		}
		st.peers[p.PublicKey] = *p
		id, ok := st.ids[p.PublicKey]
		if !ok {
			id = tailcfg.NodeID(len(st.ids) + 2)
			st.ids[p.PublicKey] = id
		}
		n := peerNode(*p, id, ifs)
		st.nodes[p.PublicKey] = n
		for _, prefix := range p.AllowedIPs {
			st.routes.Insert(prefix, n)
		}
		st.nm.Peers = append(st.nm.Peers, n)
	}
	return st, nil
}

func peerNode(p config.Peer, id tailcfg.NodeID, ifs *netmon.State) tailcfg.NodeView {
	n := &tailcfg.Node{
		ID:              id,
		StableID:        tailcfg.StableNodeID(fmt.Sprint(id)),
		Name:            fmt.Sprintf("peer%d.headwire.", id),
		User:            100,
		Key:             p.PublicKey,
		DiscoKey:        p.DiscoKey,
		IsWireGuardOnly: p.WireGuardOnly(),
		AllowedIPs:      p.AllowedIPs,
		HomeDERP:        tailcfg.DERPRegionID(p.HomeDERP),
	}
	for _, pfx := range p.AllowedIPs {
		if pfx.IsSingleIP() {
			n.Addresses = append(n.Addresses, pfx)
		}
	}
	n.Endpoints = endpoints(p, ifs)
	return n.View()
}

// endpoints returns the addresses p's node carries. A discovery peer's are all
// probed as direct candidates. An ordinary peer gets one: the first in a
// family the host has an address in, or the first when ifs is unknown or has
// neither family.
func endpoints(p config.Peer, ifs *netmon.State) []netip.AddrPort {
	if !p.WireGuardOnly() || len(p.Addrs) == 0 {
		return p.Addrs
	}
	// The ordinary-peer selector uses raw ICMP to rank multiple addresses.
	for _, a := range p.Addrs {
		if ifs != nil && (a.Addr().Is4() && ifs.HaveV4 || a.Addr().Is6() && ifs.HaveV6) {
			return []netip.AddrPort{a}
		}
	}
	return p.Addrs[:1]
}

// ResolveEndpoint returns the addresses of p's Endpoint in the resolver's
// preference order.
func ResolveEndpoint(p config.Peer) ([]netip.AddrPort, error) {
	return resolveEndpoint(p, net.DefaultResolver.LookupIPAddr)
}

func resolveEndpoint(
	p config.Peer,
	lookup func(context.Context, string) ([]net.IPAddr, error),
) ([]netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(p.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("peer %s: %w", p.PublicKey.ShortString(), err)
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("peer %s: %w", p.PublicKey.ShortString(), err)
	}
	addrs, err := lookup(context.Background(), host)
	if err != nil {
		return nil, fmt.Errorf("peer %s: %w", p.PublicKey.ShortString(), err)
	}
	var eps []netip.AddrPort
	for _, a := range addrs {
		ip, _ := netip.AddrFromSlice(a.IP)
		eps = append(eps, netip.AddrPortFrom(ip.Unmap().WithZone(a.Zone), uint16(n)))
	}
	return eps, nil
}

// peerConfig is the engine's lazy per-peer config source.
func (e *Engine) peerConfig(k key.NodePublic) (wgcfg.PeerConfig, bool) {
	st := e.state.Load()
	p, ok := st.peers[k]
	if !ok {
		return wgcfg.PeerConfig{}, false
	}
	return wgcfg.PeerConfig{
		AllowedIPs:   st.allowed[k].Prefixes(),
		PresharedKey: device.NoisePresharedKey(p.PresharedKey),
	}, true
}

// peerByIP routes an outbound packet to the peer with the longest
// matching AllowedIPs prefix.
func (e *Engine) peerByIP(dst netip.Addr) (best key.NodePublic, ok bool) {
	n, ok := e.state.Load().peerByIP(dst)
	if !ok {
		return key.NodePublic{}, false
	}
	return n.Key(), true
}

func (st *state) peerByIP(dst netip.Addr) (best tailcfg.NodeView, ok bool) {
	if dst.Zone() != "" {
		return tailcfg.NodeView{}, false
	}
	return st.routes.Lookup(dst)
}

// peerForIP is peerByIP for the engine's cold paths (Ping, TSMP), which
// want the node view.
func (e *Engine) peerForIP(ip netip.Addr) (wgengine.PeerForIP, bool) {
	st := e.state.Load()
	if st.cfg.Interface.HasAddress(ip) {
		return wgengine.PeerForIP{Node: st.nm.SelfNode, IsSelf: true}, true
	}
	n, ok := st.peerByIP(ip)
	if !ok {
		return wgengine.PeerForIP{}, false
	}
	return wgengine.PeerForIP{Node: n}, true
}

// onStatus records our UDP endpoints whenever magicsock reports them, for
// the status endpoints field.
func (e *Engine) onStatus(st *wgengine.Status, err error) {
	if err != nil {
		return
	}
	var eps []netip.AddrPort
	for _, ep := range st.LocalAddrs {
		eps = append(eps, ep.Addr)
	}
	slices.SortFunc(eps, netip.AddrPort.Compare)
	e.epsMu.Lock()
	e.eps = slices.Compact(eps)
	e.epsMu.Unlock()
}
