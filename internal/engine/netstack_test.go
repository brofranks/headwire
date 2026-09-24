package engine

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"brof.dev/headwire/internal/config"
	"brof.dev/headwire/internal/discokey"
	"tailscale.com/types/key"
)

// TestNetstackKeepsPeersOffTheHost sends a peer's UDP and DNS-port traffic at
// a node that also holds Tailscale's service address. Netstack would forward
// the first to the host's loopback and hand the second to its DNS manager.
func TestNetstackKeepsPeersOffTheHost(t *testing.T) {
	host, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	port := uint16(host.LocalAddr().(*net.UDPAddr).Port)

	a := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), freePort(t)}
	b := node{key.NewNode(), netip.MustParsePrefix("100.64.0.2/32"), freePort(t)}
	eb := startEcho(t, b.config(t, "Address = 100.100.100.100/32", a, ""))
	ea := startEcho(t, a.parse(t, "", fmt.Sprintf("[Peer]\nPublicKey = %s\nDiscoKey = %s\nAllowedIPs = 100.64.0.2/32, 100.100.100.100/32\nEndpoint = 127.0.0.1:%d\n",
		//lint:ignore SA1019 raw keys; see config.EncodeKey.
		config.EncodeKey(b.priv.Public().Raw32()), config.EncodeKey(discokey.PublicForNode(b.priv).Raw32()), b.port)))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	target := netip.AddrPortFrom(b.addr.Addr(), testEchoPort)
	warm(t, ea, eb)
	if err := dialRoundTripUntil(ctx, ea, target); err != nil {
		t.Fatal(err)
	}
	for _, dst := range []netip.AddrPort{netip.AddrPortFrom(b.addr.Addr(), port), netip.MustParseAddrPort("100.100.100.100:53")} {
		c, err := ea.ns.DialContextUDP(ctx, dst)
		if err != nil {
			t.Fatal(err)
		}
		c.Write([]byte("hello"))
		c.Close()
	}
	short, cancelShort := context.WithTimeout(ctx, 2*time.Second)
	defer cancelShort()
	if c, err := ea.ns.DialContextTCP(short, netip.MustParseAddrPort("100.100.100.100:53")); err == nil {
		c.Close()
	}
	host.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, from, err := host.ReadFrom(make([]byte, 16)); err == nil {
		t.Fatalf("host loopback received %d bytes from %v", n, from)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := dialRoundTripUntil(ctx, ea, target); err != nil {
		t.Fatalf("node did not survive: %v", err)
	}
}
