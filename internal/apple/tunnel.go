// Package apple is the lifecycle behind the C ABI in bridge/apple: an Apple
// NetworkExtension provider prepares a configuration, applies the
// returned settings to the system, then starts the engine on the utun
// descriptor the system gave it.
package apple

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"brof.dev/headwire/internal/config"
	"brof.dev/headwire/internal/engine"
	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/types/logger"
)

// Settings is what the provider hands to setTunnelNetworkSettings, split by
// family the way NEIPv4Settings and NEIPv6Settings take it.
type Settings struct {
	MTU           int      `json:"mtu"`
	IPv4Addresses []Prefix `json:"ipv4Addresses"`
	IPv4Routes    []Prefix `json:"ipv4Routes"`
	IPv6Addresses []Prefix `json:"ipv6Addresses"`
	IPv6Routes    []Prefix `json:"ipv6Routes"`
	// DNSServers and DNSSearch feed NEDNSSettings, which the provider
	// applies system-wide.
	DNSServers []string `json:"dnsServers"`
	DNSSearch  []string `json:"dnsSearch"`
}

// Prefix carries both spellings: IPv4 settings want Mask, IPv6 want Bits.
type Prefix struct {
	Address string `json:"address"`
	Mask    string `json:"mask,omitempty"`
	Bits    int    `json:"bits"`
}

func split(pfxs []netip.Prefix) (v4, v6 []Prefix) {
	for _, p := range pfxs {
		if p.Addr().Is4() {
			v4 = append(
				v4,
				Prefix{p.Addr().String(), net.IP(net.CIDRMask(p.Bits(), 32)).String(), p.Bits()},
			)
		} else {
			v6 = append(v6, Prefix{Address: p.Addr().String(), Bits: p.Bits()})
		}
	}
	return v4, v6
}

// A process holds one session: handle names it, zero when there is none, and
// eng is nil until Start succeeds. Handles are never reused, so a late Stop
// from an earlier provider cannot release a newer session.
var (
	mu     sync.Mutex
	next   int32
	handle int32
	cfg    *config.Config
	eng    *engine.Engine
)

// Prepare returns a handle for Start with the settings the system needs
// first: the utun descriptor only exists once they are applied. A default
// route is installed as a route only, with nothing keeping traffic off the
// underlay while the tunnel is down.
func Prepare(c *config.Config) (int32, *Settings, error) {
	s := &Settings{MTU: engine.MTU(c)}
	s.IPv4Addresses, s.IPv6Addresses = split(c.Interface.Addresses)
	s.IPv4Routes, s.IPv6Routes = split(engine.Routes(c))
	for _, a := range c.Interface.DNS {
		s.DNSServers = append(s.DNSServers, a.String())
	}
	for _, d := range c.Interface.DNSSearch {
		s.DNSSearch = append(s.DNSSearch, d.WithoutTrailingDot())
	}
	mu.Lock()
	defer mu.Unlock()
	// Admission precedes the provider's asynchronous network-settings call.
	// Separate controllers can race to start providers in this process.
	if handle != 0 {
		return 0, nil, errors.New("another headwire tunnel is starting or running")
	}
	next++
	handle, cfg = next, c
	return handle, s, nil
}

// Start runs the engine for a prepared handle on dev, which the engine owns
// from here on. A failed start keeps the handle until Stop.
func Start(h int32, dev tun.Device, logf logger.Logf) error {
	mu.Lock()
	defer mu.Unlock()
	if h != handle || eng != nil {
		dev.Close()
		return fmt.Errorf("handle %d is not prepared", h)
	}
	e, err := engine.Start(cfg, logf, engine.Options{Tun: dev})
	if err != nil {
		dev.Close()
		return err
	}
	eng = e
	return nil
}

// Status is engine.Status for a running handle: status fields and command
// requests.
func Status(h int32, field string) (string, error) {
	mu.Lock()
	defer mu.Unlock()
	if h != handle || eng == nil {
		return "", fmt.Errorf("handle %d is not running", h)
	}
	return eng.Status(field)
}

func NetworkChanged(h int32) {
	mu.Lock()
	defer mu.Unlock()
	if h == handle && eng != nil {
		eng.NetworkChanged()
	}
}

// Stop releases a handle in either state.
func Stop(h int32) {
	mu.Lock()
	defer mu.Unlock()
	if h != handle {
		return
	}
	if eng != nil {
		eng.Close()
	}
	handle, cfg, eng = 0, nil, nil
}
