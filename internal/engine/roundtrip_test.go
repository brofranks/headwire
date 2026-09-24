package engine

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
)

const testEchoPort = 25820

// echo serves ordinary TCP bytes. The test client owns completion and teardown.
func echo(ctx context.Context, c net.Conn) error {
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	_, err := io.Copy(c, c)
	return err
}

// warm confirms a disco path in both directions before traffic so a test does
// not wait out WireGuard's 5 s handshake retry: a peer's handshake response is
// dropped until its own ping has confirmed an address, and a passive peer
// learns the initiator's address only from the initiator's ping, so the order
// matters. TestFixedAndPassiveNetstackRoundTrip stays cold to prove
// convergence without it.
func warm(t *testing.T, a, b *Engine) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, pair := range [][2]*Engine{{a, b}, {b, a}} {
		from, to := pair[0], pair[1]
		result := make(chan *ipnstate.PingResult, 1)
		for _, peer := range from.state.Load().nm.Peers {
			if peer.Key() == to.state.Load().cfg.Interface.PrivateKey.Public() {
				from.mc.Ping(peer, new(ipnstate.PingResult), 0, func(r *ipnstate.PingResult) { result <- r })
			}
		}
		select {
		case r := <-result:
			if r.Err != "" {
				t.Fatal(r.Err)
			}
		case <-ctx.Done():
			t.Fatal("discovery unavailable")
		}
	}
}

// dialRoundTripUntil retries fresh connections while discovery establishes a
// usable path.
func dialRoundTripUntil(ctx context.Context, e *Engine, target netip.AddrPort) error {
	for {
		if err := roundTrip(ctx, e, target); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// denied fails when a round trip completes within one WireGuard handshake
// retry, so a merely slow handshake cannot pass for a refusal.
func denied(t *testing.T, e *Engine, target netip.AddrPort, what string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := dialRoundTripUntil(ctx, e, target); err == nil {
		t.Fatal(what)
	}
}

func roundTrip(ctx context.Context, e *Engine, target netip.AddrPort) error {
	attempt, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	c, err := e.ns.DialContextTCP(attempt, target)
	if err != nil {
		return err
	}
	defer c.Close()
	stop := context.AfterFunc(attempt, func() { c.Close() })
	defer stop()
	deadline, _ := attempt.Deadline()
	if err := c.SetDeadline(deadline); err != nil {
		return err
	}
	payload := []byte("headwire round trip")
	if _, err := c.Write(payload); err != nil {
		return err
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("unexpected echo %q", got)
	}
	return nil
}

// TestIPv6UnderlayRoundTrip carries the dual-stack overlay over a loopback
// IPv6 endpoint. TestFixedAndPassiveNetstackRoundTrip covers IPv4.
func TestIPv6UnderlayRoundTrip(t *testing.T) {
	a := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), freePort(t)}
	b := node{key.NewNode(), netip.MustParsePrefix("100.64.0.2/32"), freePort(t)}
	ac := a.config(t, "", b, fmt.Sprintf("Endpoint = [::1]:%d", b.port))
	bc := b.config(t, "", a, "")
	dualStack(ac, bc)
	eb := startEcho(t, bc)
	e := startEcho(t, ac)
	warm(t, e, eb)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, address := range bc.Interface.Addresses {
		if err := dialRoundTripUntil(ctx, e, netip.AddrPortFrom(address.Addr(), testEchoPort)); err != nil {
			t.Fatal(err)
		}
	}
	if mark, _ := e.Status("fwmark"); mark != "off\n" {
		t.Fatalf("netstack mark: %q", mark)
	}
}
