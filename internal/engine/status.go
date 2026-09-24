package engine

import (
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"strings"
	"time"

	"brof.dev/headwire/internal/config"
	"brof.dev/headwire/internal/discokey"
	"brof.dev/headwire/internal/status"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/netns"
	"tailscale.com/tsconst"
)

// status merges wireguard-go's per-peer counters and handshake time with
// magicsock's view of each peer's path.
func (e *Engine) status() *ipnstate.Status {
	sb := &ipnstate.StatusBuilder{WantPeers: true}
	e.eng.UpdateStatus(sb)
	return sb.Status()
}

// peerLine is one peer's config with its runtime status, nil before the
// engine has seen it.
type peerLine struct {
	config.Peer
	st       *ipnstate.PeerStatus
	endpoint netip.AddrPort
}

// path is the peer's endpoint column: the direct ip:port in use, else the
// configured endpoint or DERP relay, else (none).
func (p peerLine) path() string {
	switch {
	case p.st != nil && p.st.CurAddr != "":
		return p.st.CurAddr
	case p.endpoint.IsValid():
		return p.endpoint.String()
	case p.HomeDERP != 0:
		return fmt.Sprintf("relay:%d", p.HomeDERP)
	}
	return "(none)"
}

func (p peerLine) handshake() time.Time {
	if p.st == nil {
		return time.Time{}
	}
	return p.st.LastHandshake
}

// live reports a session younger than WireGuard's REJECT_AFTER_TIME. Lazy
// peer eviction resets handshake history, so an idle peer can read as not live.
func (p peerLine) live(now time.Time) bool {
	return now.Sub(p.handshake()) < 180*time.Second
}

func (p peerLine) transfer() (rx, tx int64) {
	if p.st == nil {
		return 0, 0
	}
	return p.st.RxBytes, p.st.TxBytes
}

func (p peerLine) psk() string {
	if p.PresharedKey == [32]byte{} {
		return "(none)"
	}
	return "(hidden)"
}

func (p peerLine) allowed(sep string) string {
	if len(p.AllowedIPs) == 0 {
		return "(none)"
	}
	var parts []string
	for _, pfx := range p.AllowedIPs {
		parts = append(parts, pfx.String())
	}
	return strings.Join(parts, sep)
}

// peers lists configured peers in file order with one runtime snapshot merged
// in. Only the human-readable output sorts them by latest handshake.
func peers(st *state, s *ipnstate.Status) []peerLine {
	var ps []peerLine
	for _, p := range st.cfg.Peers {
		line := peerLine{Peer: p, st: s.Peer[p.PublicKey]}
		if eps := st.nodes[p.PublicKey].Endpoints(); eps.Len() > 0 {
			line.endpoint = eps.At(0)
		}
		ps = append(ps, line)
	}
	return ps
}

// statusFields renders each name in the status field vocabulary as
// newline-terminated lines, per-peer fields led by the peer's public key and a
// tab. A test holds it to exactly that set of names.
var statusFields = map[string]func(statusView) string{
	"public-key":     func(v statusView) string { return v.publicKey() + "\n" },
	"private-key":    func(statusView) string { return "(hidden)\n" },
	"listen-port":    func(v statusView) string { return fmt.Sprintf("%d\n", v.port) },
	"fwmark":         func(v statusView) string { return v.mark + "\n" },
	"peers":          func(v statusView) string { return v.perPeer(func(peerLine) string { return "" }) },
	"preshared-keys": func(v statusView) string { return v.perPeer(func(p peerLine) string { return "\t" + p.psk() }) },
	"endpoints":      func(v statusView) string { return v.perPeer(func(p peerLine) string { return "\t" + p.path() }) },
	"allowed-ips":    func(v statusView) string { return v.perPeer(func(p peerLine) string { return "\t" + p.allowed(" ") }) },
	"latest-handshakes": func(v statusView) string {
		return v.perPeer(func(p peerLine) string { return fmt.Sprintf("\t%d", max(p.handshake().Unix(), 0)) })
	},
	"transfer": func(v statusView) string {
		return v.perPeer(func(p peerLine) string {
			rx, tx := p.transfer()
			return fmt.Sprintf("\t%d\t%d", rx, tx)
		})
	},
	"persistent-keepalive": func(v statusView) string { return v.perPeer(func(peerLine) string { return "\toff" }) },
	"dump": func(v statusView) string {
		return fmt.Sprintf("(hidden)\t%s\t%d\t%s\n", v.publicKey(), v.port, v.mark) +
			v.perPeer(func(p peerLine) string {
				rx, tx := p.transfer()
				return fmt.Sprintf("\t%s\t%s\t%s\t%d\t%d\t%d\toff",
					p.psk(), p.path(), p.allowed(","), max(p.handshake().Unix(), 0), rx, tx)
			})
	},
}

// useSocketMark is replaced by tests: netns marks sockets only as root.
var useSocketMark = netns.UseSocketMark

// fwmark describes the transport sockets, not the tunnel device.
func (e *Engine) fwmark() string {
	if runtime.GOOS == "linux" && e.ns == nil && useSocketMark() {
		return fmt.Sprintf("0x%x", tsconst.LinuxBypassMarkNum)
	}
	return "off"
}

// Status renders the node for `show`: the human-readable summary when field
// is empty, otherwise the tab-separated lines of that one field. Every field
// is reported even where the value is fixed (keepalive) or withheld (keys).
// Endpoints may name a relay, keys are redacted, listen-port reports the IPv4
// socket only, and peer lifetimes are the backend's.
// The "ip [-1|-4|-6]" and "ping IP" requests share every host's transport.
func (e *Engine) Status(field string) (string, error) {
	if field == "ip" || strings.HasPrefix(field, "ip ") {
		return interfaceIPs(e.state.Load().cfg.Interface.Addresses, field)
	}
	if ip, ok := strings.CutPrefix(field, "ping "); ok {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return "", err
		}
		return e.Ping(addr)
	}
	if err := status.ValidateField(field); err != nil {
		return "", err
	}
	st := e.state.Load()
	s := e.status()
	v := statusView{
		cfg:   st.cfg,
		peers: peers(st, s),
		name:  e.tunName,
		port:  e.mc.LocalPort(),
		mark:  e.fwmark(),
		eps:   e.endpoints(),
	}
	return v.render(field, time.Now()), nil
}

// interfaceIPs reports Headwire-managed addresses, independently of OS
// interface state, peer routes, or transport endpoints. Keep host bits from
// Address.
func interfaceIPs(addresses []netip.Prefix, request string) (string, error) {
	if request != "ip" && request != "ip -1" && request != "ip -4" && request != "ip -6" {
		return "", fmt.Errorf("invalid request: %q", request)
	}
	var b strings.Builder
	for _, prefix := range addresses {
		ip := prefix.Addr()
		if request == "ip -4" && !ip.Is4() || request == "ip -6" && !ip.Is6() {
			continue
		}
		fmt.Fprintln(&b, ip)
		if request == "ip -1" {
			break
		}
	}
	if b.Len() == 0 {
		return "", fmt.Errorf("no configured interface addresses matching %q", request)
	}
	return b.String(), nil
}

// statusView captures all inputs once, including the configuration used for
// resolved endpoints. Rendering never resolves DNS or reloads engine state.
type statusView struct {
	cfg   *config.Config
	peers []peerLine
	name  string
	port  uint16
	mark  string
	// eps is the endpoint set onStatus last advertised.
	eps []netip.AddrPort
}

// endpoints returns the advertised endpoint set.
func (e *Engine) endpoints() []netip.AddrPort {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.eps)
}

func (v statusView) publicKey() string {
	//lint:ignore SA1019 raw keys; see config.EncodeKey.
	return config.EncodeKey(v.cfg.Interface.PrivateKey.Public().Raw32())
}

func (v statusView) perPeer(f func(peerLine) string) string {
	var b strings.Builder
	for _, p := range v.peers {
		//lint:ignore SA1019 raw keys; see config.EncodeKey.
		fmt.Fprintf(&b, "%s%s\n", config.EncodeKey(p.PublicKey.Raw32()), f(p))
	}
	return b.String()
}

// render expects a field status.ValidateField accepts.
func (v statusView) render(field string, now time.Time) string {
	f, ok := statusFields[field]
	if !ok {
		return v.statusText(now)
	}
	return f(v)
}

// statusText renders the pretty print, one block for the
// interface and one per configured peer.
func (v statusView) statusText(now time.Time) string {
	cfg, ps := v.cfg, slices.Clone(v.peers)
	slices.SortStableFunc(ps, func(a, b peerLine) int { return b.handshake().Compare(a.handshake()) })
	var b strings.Builder
	fmt.Fprintf(&b, "interface: %s\n", v.name)
	fmt.Fprintf(&b, "  public key: %s\n", v.publicKey())
	b.WriteString("  private key: (hidden)\n")
	//lint:ignore SA1019 raw keys; see config.EncodeKey.
	fmt.Fprintf(&b, "  disco key: %s\n", config.EncodeKey(discokey.PublicForNode(cfg.Interface.PrivateKey).Raw32()))
	fmt.Fprintf(&b, "  listening port: %d\n", v.port)
	if v.mark != "off" {
		fmt.Fprintf(&b, "  fwmark: %s\n", v.mark)
	}
	if cfg.Interface.HomeDERP != 0 {
		fmt.Fprintf(&b, "  home derp: %s\n", cfg.Regions[cfg.Interface.HomeDERP].Label())
	}
	if len(v.eps) > 0 {
		eps := make([]string, len(v.eps))
		for i, ep := range v.eps {
			eps[i] = ep.String()
		}
		fmt.Fprintf(&b, "  endpoints: %s\n", strings.Join(eps, ", "))
	}
	for _, p := range ps {
		//lint:ignore SA1019 raw keys; see config.EncodeKey.
		fmt.Fprintf(&b, "\npeer: %s\n", config.EncodeKey(p.PublicKey.Raw32()))
		if p.PresharedKey != ([32]byte{}) {
			b.WriteString("  preshared key: (hidden)\n")
		}
		if !p.WireGuardOnly() {
			//lint:ignore SA1019 raw keys; see config.EncodeKey.
			fmt.Fprintf(&b, "  disco key: %s\n", config.EncodeKey(p.DiscoKey.Raw32()))
		}
		if path := p.path(); strings.HasPrefix(path, "relay:") {
			fmt.Fprintf(&b, "  relay: %s", cfg.Regions[p.HomeDERP].Label())
			if !p.live(now) {
				b.WriteString(" (configured)")
			}
			b.WriteByte('\n')
		} else if path != "(none)" {
			fmt.Fprintf(&b, "  endpoint: %s", path)
			if p.st == nil || p.st.CurAddr == "" {
				b.WriteString(" (configured)")
			}
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "  allowed ips: %s\n", p.allowed(", "))
		if hs := p.handshake(); !hs.IsZero() {
			fmt.Fprintf(&b, "  latest handshake: %s\n", handshakeAge(hs, now))
		}
		if rx, tx := p.transfer(); rx|tx != 0 {
			fmt.Fprintf(&b, "  transfer: %s received, %s sent\n", prettyBytes(rx), prettyBytes(tx))
		}
	}
	return b.String()
}

func handshakeAge(hs, now time.Time) string {
	seconds := now.Unix() - hs.Unix()
	if seconds == 0 {
		return "Now"
	}
	if seconds < 0 {
		return "(System clock wound backward; connection problems may ensue.)"
	}
	return prettyDuration(time.Duration(seconds)*time.Second) + " ago"
}

// prettyDuration spells d out in every non-zero unit:
// "1 hour, 2 minutes, 3 seconds".
func prettyDuration(d time.Duration) string {
	secs := int64(d / time.Second)
	var parts []string
	for _, u := range []struct {
		name string
		secs int64
	}{{"year", 365 * 86400}, {"day", 86400}, {"hour", 3600}, {"minute", 60}, {"second", 1}} {
		if n := secs / u.secs; n > 0 || (u.secs == 1 && parts == nil) {
			s := ""
			if n != 1 {
				s = "s"
			}
			parts = append(parts, fmt.Sprintf("%d %s%s", n, u.name, s))
			secs -= n * u.secs
		}
	}
	return strings.Join(parts, ", ")
}

func prettyBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < len("KMGT")-1; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(n)/float64(div), "KMGT"[exp])
}
