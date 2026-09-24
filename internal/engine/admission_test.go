package engine

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/packet"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
)

// TestDiscoUpdateSource checks that a TSMP disco-key advertisement updates
// only the peer owning its source address. Peer a, whose AllowedIPs include
// the default route, advertises its key from its own address and from peer
// v's. The update log must name only a, and disco pings to both peers then
// confirm the keys the receiver holds.
func TestDiscoUpdateSource(t *testing.T) {
	for _, family := range []string{"4", "6"} {
		t.Run(family, func(t *testing.T) {
			prefixes := []string{"100.64.0.1/32", "100.64.0.2/32", "100.64.0.3/32", "0.0.0.0/0"}
			if family == "6" {
				prefixes = []string{"fd00::1/128", "fd00::2/128", "fd00::3/128", "::/0"}
			}
			r := node{key.NewNode(), netip.MustParsePrefix(prefixes[0]), freePort(t)}
			v := node{key.NewNode(), netip.MustParsePrefix(prefixes[1]), freePort(t)}
			a := node{key.NewNode(), netip.MustParsePrefix(prefixes[2]), freePort(t)}
			cfg := r.parse(t, "", v.peerSection(fmt.Sprintf("Endpoint = 127.0.0.1:%d", v.port))+a.peerSection(fmt.Sprintf("Endpoint = 127.0.0.1:%d", a.port)))
			cfg.Peers[1].AllowedIPs = append(cfg.Peers[1].AllowedIPs, netip.MustParsePrefix(prefixes[3]))
			var updates tstest.MemLogger
			updated := make(chan struct{}, 1)
			testLogf := tstest.WhileTestRunningLogger(t)
			logf := func(format string, args ...any) {
				line := fmt.Sprintf(format, args...)
				testLogf("%s", line)
				if strings.HasPrefix(line, "magicsock: updated disco key for peer ") {
					updates.Logf("%s", line)
					select {
					case updated <- struct{}{}:
					default:
					}
				}
			}
			er, err := Start(cfg, logf, Options{
				Netstack:   true,
				TCPHandler: func(c net.Conn) { echo(context.Background(), c) },
			})
			if err != nil {
				t.Fatal(err)
			}
			defer er.Close()
			startEcho(t, v.config(t, "", r, fmt.Sprintf("Endpoint = 127.0.0.1:%d", r.port)))
			ea := startEcho(t, a.config(t, "", r, fmt.Sprintf("Endpoint = 127.0.0.1:%d", r.port)))
			warm(t, ea, er)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := dialRoundTripUntil(ctx, ea, netip.AddrPortFrom(r.addr.Addr(), testEchoPort)); err != nil {
				t.Fatal(err)
			}
			// Make the receiver's configured key stale, leaving the sender's
			// established path intact. RotateDiscoKey also starts ReSTUN,
			// which can rebind and clear that path before these one-shot
			// advertisements leave the sender in an offline test.
			stale := er.state.Load().nm.Peers[1].AsStruct()
			stale.DiscoKey = key.NewDisco().Public()
			er.mc.UpsertPeer(stale.View())
			for _, src := range []netip.Addr{v.addr.Addr(), a.addr.Addr()} {
				update := packet.TSMPDiscoKeyAdvertisement{
					Src: src,
					Dst: r.addr.Addr(),
					Key: ea.mc.DiscoPublicKey(),
				}
				pkt, err := update.Marshal()
				if err != nil {
					t.Fatal(err)
				}
				if err := ea.tun.InjectOutbound(pkt); err != nil {
					t.Fatal(err)
				}
			}
			checkUpdate := func() {
				t.Helper()
				want := fmt.Sprintf("magicsock: updated disco key for peer %v to %v\n", a.priv.Public().ShortString(), ea.mc.DiscoPublicKey().ShortString())
				if got := updates.String(); got != want {
					t.Fatalf("discovery updates: %q; want %q", got, want)
				}
			}
			select {
			case <-updated:
				checkUpdate()
			case <-ctx.Done():
				t.Fatal("own discovery update not applied")
			}
			for _, peer := range er.state.Load().nm.Peers {
				result := make(chan *ipnstate.PingResult, 1)
				er.mc.Ping(peer, new(ipnstate.PingResult), 0, func(r *ipnstate.PingResult) { result <- r })
				select {
				case r := <-result:
					if r.Err != "" {
						t.Fatal(r.Err)
					}
				case <-ctx.Done():
					t.Fatalf("discovery failed for %v", peer.Key())
				}
			}
			checkUpdate()
		})
	}
}

func TestPeerAdmission(t *testing.T) {
	for _, mode := range []string{"unknown", "wrong-psk", "correct-psk"} {
		t.Run(mode, func(t *testing.T) {
			a := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), freePort(t)}
			b := node{key.NewNode(), netip.MustParsePrefix("100.64.0.2/32"), freePort(t)}
			ac, bc := a.config(t, "", b, fmt.Sprintf("Endpoint = 127.0.0.1:%d", b.port)), b.config(t, "", a, fmt.Sprintf("Endpoint = 127.0.0.1:%d", a.port))
			if mode == "unknown" {
				bc.Peers = nil
			} else {
				ac.Peers[0].PresharedKey[0] = 1
				bc.Peers[0].PresharedKey[0] = 1
				if mode == "wrong-psk" {
					bc.Peers[0].PresharedKey[0] = 2
				}
			}
			eb := startEcho(t, bc)
			ea := startEcho(t, ac)
			if mode != "unknown" {
				// Discovery must work before PSK rejection is tested,
				// so a cold/unreachable path cannot produce a false pass.
				warm(t, ea, eb)
			}
			target := netip.AddrPortFrom(b.addr.Addr(), testEchoPort)
			if mode != "correct-psk" {
				denied(t, ea, target, "unexpected peer admitted")
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := dialRoundTripUntil(ctx, ea, target); err != nil {
				t.Fatalf("admission: %v", err)
			}
		})
	}
}

func TestRestartRevokesPeer(t *testing.T) {
	r := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), freePort(t)}
	a := node{key.NewNode(), netip.MustParsePrefix("100.64.0.2/32"), freePort(t)}
	b := node{key.NewNode(), netip.MustParsePrefix("100.64.0.3/32"), freePort(t)}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	er, err := Start(r.config(t, "", a, ""), t.Logf, Options{Netstack: true, TCPHandler: func(c net.Conn) { echo(ctx, c) }})
	if err != nil {
		t.Fatal(err)
	}
	ea := startEcho(t, a.config(t, "", r, fmt.Sprintf("Endpoint = 127.0.0.1:%d", r.port)))
	target := netip.AddrPortFrom(r.addr.Addr(), testEchoPort)
	warm(t, ea, er)
	if err := dialRoundTripUntil(ctx, ea, target); err != nil {
		er.Close()
		t.Fatal(err)
	}
	er.Close()
	er = startEcho(t, r.config(t, "", b, ""))
	eb := startEcho(t, b.config(t, "", r, fmt.Sprintf("Endpoint = 127.0.0.1:%d", r.port)))
	warm(t, eb, er)
	if err := dialRoundTripUntil(ctx, eb, target); err != nil {
		t.Fatal("restarted receiver unavailable:", err)
	}
	// A retains its old WireGuard session. Neither it nor a new handshake may
	// reach the receiver after the clean restart with A removed.
	denied, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	if err := dialRoundTripUntil(denied, ea, target); err == nil {
		t.Fatal("revoked peer reached restarted receiver")
	}
}
