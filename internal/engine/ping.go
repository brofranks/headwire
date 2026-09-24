package engine

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"brof.dev/headwire/internal/status"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
)

// pingTimeout stays under the status socket's connection deadline, as the
// engine never expires a pending disco ping itself.
const pingTimeout = 3 * time.Second

// Ping sends one disco ping to the peer owning ip and names the path that
// answered first: a direct ip:port, or relay:<id> when only the DERP region
// replied.
func (e *Engine) Ping(ip netip.Addr) (string, error) {
	p, ok := e.peerForIP(ip)
	switch {
	case !ok:
		return "", fmt.Errorf("no peer's AllowedIPs contain %s", ip)
	case p.IsSelf:
		return "", fmt.Errorf("%s is a local address", ip)
	case p.Node.DiscoKey().IsZero():
		// magicsock drops a ping to such a peer and never calls back.
		return "", errors.New("peer has no DiscoKey, use ping(8)")
	}
	done := make(chan *ipnstate.PingResult, 1)
	e.eng.Ping(ip, tailcfg.PingDisco, 0, func(res *ipnstate.PingResult) { done <- res })
	select {
	case res := <-done:
		if res.Err != "" {
			return "", errors.New(res.Err)
		}
		latency := time.Duration(res.LatencySeconds * float64(time.Second)).Round(time.Millisecond)
		if res.Endpoint != "" {
			return fmt.Sprintf("pong from %s via %s in %s\n", ip, res.Endpoint, latency), nil
		}
		return fmt.Sprintf("pong from %s%s%d in %s\n",
			ip, status.PingViaRelay, res.DERPRegionID, latency), nil
	case <-time.After(pingTimeout):
		// A probe timeout is a result, transport and peer errors are terminal.
		return fmt.Sprintf("ping %s%s", ip, status.PingTimedOut), nil
	}
}
