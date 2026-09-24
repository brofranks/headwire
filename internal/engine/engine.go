// Package engine drives tailscale.com's wgengine and magicsock from a static
// headwire configuration: no control plane, no LocalBackend. The config is
// translated once into a DERP map and a network map, per-peer config is
// served to the engine lazily, and endpoints are advertised to DERP-mode
// peers with disco call-me-maybe messages so both sides can upgrade from
// the relay to a direct path.
package engine

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"

	"brof.dev/headwire/internal/config"
	"brof.dev/headwire/internal/discokey"
	"github.com/gaissmai/bart"
	"github.com/tailscale/wireguard-go/device"
	"github.com/tailscale/wireguard-go/tun"
	"go4.org/netipx"
	"tailscale.com/disco"
	"tailscale.com/health"
	"tailscale.com/net/dns"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/net/routemanager"
	"tailscale.com/net/tsdial"
	"tailscale.com/net/tstun"
	"tailscale.com/proxymap"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/nettype"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/usermetric"
	"tailscale.com/wgengine"
	"tailscale.com/wgengine/magicsock"
	"tailscale.com/wgengine/netstack"
	"tailscale.com/wgengine/router"
	"tailscale.com/wgengine/wgcfg"

	// Registers the UPnP/NAT-PMP/PCP port mapper magicsock uses to open
	// pinholes. The OS router used in TUN mode is registered by cmd/headwire.
	_ "tailscale.com/feature/condregister/portmapper"
)

// TUNName is the interface name in TUN mode. Darwin allocates the next utun.
const TUNName = "headwire0"

// Options selects how the engine attaches to the network.
type Options struct {
	// Netstack runs an in-process TCP/IP stack instead of a kernel TUN.
	// Netstack needs no privileges, TUN mode needs root.
	Netstack bool
	// TCPHandler serves inbound tunnel TCP flows addressed to the node
	// (netstack only).
	TCPHandler func(net.Conn)
	// Tun is a packet device the caller already owns, for embedders that
	// are handed one by the host: an Apple NetworkExtension provider gets a
	// utun descriptor it cannot ask the engine to create. The engine then
	// installs no OS router, because the host owns the interface address
	// and routes. Close takes the device down.
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
	dns    *dns.Manager
	ns     *netstack.Impl // nil in TUN mode

	hostDNS dns.OSConfigurator // set when a kernel TUN has DNS
	unwatch func()             // stops the link-change DNS re-apply

	mu  sync.Mutex       // serializes Reload and guards eps
	eps []netip.AddrPort // last advertised endpoints
}

// state is one immutable view of the configuration. Reload swaps it whole
// so the engine's lookup callbacks never see a half-applied change.
type state struct {
	cfg     *config.Config
	peers   map[key.NodePublic]config.Peer
	nodes   map[key.NodePublic]tailcfg.NodeView // nm.Peers by key
	allowed map[key.NodePublic]*netipx.IPSet
	nm      *netmap.NetworkMap
	// ids are the netmap node IDs handed out to peers, including peers since
	// removed. A peer keeps its ID across reloads: magicsock addresses peers
	// by ID and requires them to be unique and stable.
	ids map[key.NodePublic]tailcfg.NodeID
}

// Start brings the node up. Close releases it.
func Start(cfg *config.Config, logf logger.Logf, opts Options) (_ *Engine, err error) {
	e := &Engine{logf: logf, tunName: "netstack"}
	defer func() {
		if err != nil {
			e.Close()
		}
	}()

	e.bus = eventbus.New()
	tracker := health.NewTracker(e.bus)
	if e.netMon, err = netmon.New(e.bus, logf); err != nil {
		return nil, err
	}
	e.dialer = &tsdial.Dialer{Logf: logf}
	e.dialer.SetNetMon(e.netMon)
	// ListenPort is configured explicitly when fixed-endpoint peers need to
	// name it. An omitted or zero port lets the OS choose.
	conf := wgengine.Config{
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
			case *dns.Manager:
				e.dns = s
			}
		},
	}
	switch {
	case opts.Netstack:
		// Nothing on the host needs to route around a tunnel that isn't there.
		netns.SetEnabled(false)
	case opts.Tun != nil:
		conf.Tun = opts.Tun
		if e.tunName, err = opts.Tun.Name(); err != nil {
			return nil, err
		}
	default:
		if err := e.kernelTUN(cfg, tracker, &conf); err != nil {
			return nil, err
		}
	}
	// Both settings are process-wide and netstack has no interface to name.
	if !opts.Netstack {
		// netmon identifies its own tunnel by Tailscale's interface
		// names, or on darwin by a utun holding a Tailscale CGNAT
		// address. Headwire's names and overlay addresses are neither, so
		// without this the tunnel counts as an ordinary interface in
		// netmon's link state.
		netmon.SetTailscaleInterfaceProps(e.tunName, 0)
		// That does not keep the tunnel's address out of magicsock's
		// endpoints: netmon.LocalAddresses skips only Tailscale's own
		// ranges, and magicsock sends the result in its own
		// call-me-maybes. A peer probing it would find a "direct" path
		// that runs through the tunnel it is meant to carry.
		netmon.RegisterInterfaceGetter(interfacesExcept(e.tunName))
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
	if opts.Netstack {
		if e.ns, err = netstack.Create(logf, e.tun, e.eng, e.mc, e.dialer, e.dns, new(proxymap.Mapper)); err != nil {
			return nil, err
		}
		e.ns.ProcessLocalIPs = true
		// A flow no handler claims is refused: netstack would otherwise
		// forward it to the host, rewriting this node's address to loopback.
		e.ns.GetTCPHandlerForFlow = func(src, dst netip.AddrPort) (func(net.Conn), bool) {
			return opts.TCPHandler, true
		}
		e.ns.GetUDPHandlerForFlow = func(src, dst netip.AddrPort) (func(nettype.ConnPacketConn), bool) {
			return nil, true
		}
		if err := e.ns.Start(nil); err != nil {
			return nil, err
		}
	}
	// The wrapper buffers all traffic until told the stack above it is ready.
	e.tun.Start()

	st, err := newState(cfg, nil)
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
	if e.ns != nil {
		e.ns.UpdateNetstackIPs(st.nm)
	}
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
	if e.hostDNS != nil {
		set := func() error {
			return e.hostDNS.SetDNS(dns.OSConfig{Nameservers: cfg.Interface.DNS, SearchDomains: cfg.Interface.DNSSearch})
		}
		if err := set(); err != nil {
			return nil, err
		}
		// NetworkManager restarts and suspend/resume clear resolved's
		// per-link settings, so a major link change re-applies them.
		e.unwatch = e.netMon.RegisterChangeCallback(func(d *netmon.ChangeDelta) {
			if d.RebindLikelyRequired && d.AnyInterfaceUp() {
				if err := set(); err != nil {
					e.logf("dns: re-apply after link change: %v", err)
				}
			}
		})
	}
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

// The kernel device and host DNS need root, so tests replace them.
var (
	createTUN         = tun.CreateTUN
	newOSConfigurator = dns.NewOSConfigurator
)

// kernelTUN creates the interface this process owns, with its OS router.
func (e *Engine) kernelTUN(
	cfg *config.Config,
	tracker *health.Tracker,
	conf *wgengine.Config,
) (err error) {
	name := TUNName
	if runtime.GOOS == "darwin" {
		name = "utun"
	}
	dev, err := createTUN(name, MTU(cfg))
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			dev.Close()
		}
	}()
	if e.tunName, err = dev.Name(); err != nil {
		return err
	}
	conf.Tun = dev
	if conf.Router, err = router.New(e.logf, dev, e.netMon, tracker, e.bus); err != nil {
		return err
	}
	// The process that owns the interface sets the host's DNS. Without a
	// DNS line no configurator exists, so the host's resolver setup is
	// neither probed nor touched.
	if len(cfg.Interface.DNS)+len(cfg.Interface.DNSSearch) > 0 {
		e.hostDNS, err = newOSConfigurator(e.logf, tracker, e.bus, nil, nil, e.tunName)
		e.unwatch = func() {}
	}
	return err
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
// on darwin instead of the tunnel, and netstack treats the rest of a
// registered subnet as on-link with no route to it.
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

// ReloadApplyError means publication has occurred and the engine must be
// closed. The caller must not continue serving or retry against partially
// applied state.
type ReloadApplyError struct{ Err error }

func (e *ReloadApplyError) Error() string { return "reload partially applied: " + e.Err.Error() }

// Reload applies a changed configuration to the running node: peer additions
// and updates preserve existing sessions. Source-permission revocations,
// including peer removal and ownership transfers, require restart, because the
// pinned engine can apply a stale lazy peer config after a sync. Only [Peer]
// sections and AllowIn may change. Other [Interface] and [DERPRegion] changes
// are refused and the old configuration stays live.
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
		if was, ok := old.peers[p.PublicKey]; ok && was.WireGuardOnly() != p.WireGuardOnly() {
			return fmt.Errorf("peer %s: restart to add or remove DiscoKey", p.PublicKey.ShortString())
		}
	}
	st, err := newState(cfg, old.ids)
	if err != nil {
		return err
	}
	if err := old.checkSourceOwnership(st); err != nil {
		return err
	}
	e.state.Store(st)
	e.eng.SetFilter(newFilter(st, e.tun.GetFilter(), e.logf))
	e.setPeerRoutes(st)
	for k := range old.peers {
		if _, ok := st.peers[k]; !ok {
			e.mc.RemovePeer(old.ids[k])
			e.eng.SyncDevicePeer(k)
		}
	}
	for _, p := range cfg.Peers {
		was, existed := old.peers[p.PublicKey]
		was.AllowIn = p.AllowIn // the filter above already applied it
		if existed && reflect.DeepEqual(was, p) &&
			old.allowed[p.PublicKey].Equal(st.allowed[p.PublicKey]) &&
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
	if err := e.reconfig(cfg); err != nil && !errors.Is(err, wgengine.ErrNoChanges) {
		return &ReloadApplyError{Err: err}
	}
	if e.ns != nil {
		e.ns.UpdateNetstackIPs(st.nm)
	}
	if len(e.eps) > 0 {
		go e.advertiseEndpoints(e.eps)
	}
	return nil
}

// Close tears the node down in reverse dependency order.
func (e *Engine) Close() {
	if e.ns != nil {
		e.ns.Close()
	}
	if e.hostDNS != nil {
		e.unwatch()
		e.hostDNS.Close()
	}
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
// and passive peers neither. ids are the running state's, and a rejected
// candidate leaves them untouched.
func newState(cfg *config.Config, ids map[key.NodePublic]tailcfg.NodeID) (*state, error) {
	allowed, err := sourcePermissions(cfg)
	if err != nil {
		return nil, err
	}
	self := cfg.Interface
	st := &state{
		cfg:     cfg,
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
	for _, p := range cfg.Peers {
		st.peers[p.PublicKey] = p
		id, ok := st.ids[p.PublicKey]
		if !ok {
			id = tailcfg.NodeID(len(st.ids) + 2)
			st.ids[p.PublicKey] = id
		}
		n, err := peerNode(p, id)
		if err != nil {
			return nil, err
		}
		st.nodes[p.PublicKey] = n
		st.nm.Peers = append(st.nm.Peers, n)
	}
	return st, nil
}

func peerNode(p config.Peer, id tailcfg.NodeID) (tailcfg.NodeView, error) {
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
	if p.Endpoint != "" {
		addr, err := net.ResolveUDPAddr("udp", p.Endpoint)
		if err != nil {
			return tailcfg.NodeView{}, fmt.Errorf("peer %s: %w", p.PublicKey.ShortString(), err)
		}
		n.Endpoints = []netip.AddrPort{
			netip.AddrPortFrom(addr.AddrPort().Addr().Unmap(), uint16(addr.Port)),
		}
	}
	return n.View(), nil
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
	bits := -1
	for _, n := range st.nm.Peers {
		for _, pfx := range n.AllowedIPs().All() {
			if pfx.Contains(dst) && pfx.Bits() >= bits {
				best, bits, ok = n, pfx.Bits(), true
			}
		}
	}
	return best, ok
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

// interfacesExcept lists the system's interfaces without the named one. The
// getter it feeds is process-wide, like the rest of netmon's tunnel identity.
func interfacesExcept(name string) func() ([]netmon.Interface, error) {
	return func() ([]netmon.Interface, error) {
		ifs, err := net.Interfaces()
		var ret []netmon.Interface
		for i := range ifs {
			if ifs[i].Name != name {
				ret = append(ret, netmon.Interface{Interface: &ifs[i]})
			}
		}
		return ret, err
	}
}

// onStatus advertises our UDP endpoints whenever magicsock learns a new
// set. Without a control plane nobody else tells DERP-mode peers where we
// are, and magicsock only starts probing a peer once it has at least one
// endpoint for it.
func (e *Engine) onStatus(st *wgengine.Status, err error) {
	if err != nil {
		return
	}
	var eps []netip.AddrPort
	for _, ep := range st.LocalAddrs {
		eps = append(eps, ep.Addr)
	}
	slices.SortFunc(eps, netip.AddrPort.Compare)
	eps = slices.Compact(eps)
	e.mu.Lock()
	changed := !slices.Equal(eps, e.eps)
	e.eps = eps
	e.mu.Unlock()
	if changed && len(eps) > 0 {
		go e.advertiseEndpoints(eps)
	}
}

// advertiseEndpoints sends eps to every DERP-mode peer as a disco
// call-me-maybe over the peer's home region, framed and sealed exactly as
// magicsock's own sendDiscoMessage does so the peer processes it natively:
// it disco-pings the endpoints, learning a direct path to us and teaching
// us its address from the pings we receive.
func (e *Engine) advertiseEndpoints(eps []netip.AddrPort) {
	payload := (&disco.CallMeMaybe{MyNumber: eps}).AppendMarshal(nil)
	cfg := e.state.Load().cfg
	discoPriv := discokey.PrivateForNode(cfg.Interface.PrivateKey)
	for _, p := range cfg.Peers {
		if p.HomeDERP == 0 {
			continue
		}
		pkt := append([]byte(disco.Magic), e.mc.DiscoPublicKey().AppendTo(nil)...)
		pkt = append(pkt, discoPriv.Shared(p.DiscoKey).Seal(payload)...)
		if _, err := e.mc.SendDERPPacketTo(p.PublicKey, tailcfg.DERPRegionID(p.HomeDERP), pkt); err != nil {
			e.logf("advertise endpoints to %v: %v", p.PublicKey.ShortString(), err)
		}
	}
}
