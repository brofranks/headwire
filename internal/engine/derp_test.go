package engine

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"tailscale.com/derp/derpserver"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// localDERP serves one relay region, with DERP and STUN, on loopback.
func localDERP(t *testing.T) *tailcfg.DERPMap {
	t.Helper()
	d := derpserver.New(key.NewNode(), t.Logf)
	srv := httptest.NewUnstartedServer(derpserver.Handler(d))
	srv.Config.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	srv.StartTLS()
	stunAddr, stunCleanup := stuntest.Serve(t)
	t.Cleanup(func() {
		srv.CloseClientConnections()
		srv.Close()
		d.Close()
		stunCleanup()
	})
	return &tailcfg.DERPMap{OmitDefaultRegions: true, Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{1: {
		RegionID: 1, RegionCode: "1",
		Nodes: []*tailcfg.DERPNode{{
			Name: "1-0", RegionID: 1, HostName: "localhost", IPv4: "127.0.0.1", IPv6: "none",
			STUNPort: stunAddr.Port, DERPPort: srv.Listener.Addr().(*net.TCPAddr).Port, InsecureForTests: true,
		}},
	}}}
}

// inRelayOnlyProcess reports whether direct UDP is disabled for this process.
// When it is not, the calling test runs again in a child process started with
// TS_DEBUG_NEVER_DIRECT_UDP set, and the child's failure fails the caller.
// magicsock reads that knob without synchronization from heartbeat timers
// that can outlive Close, so setting it in a process that has run engines
// races. It has to be in the environment before the process starts.
func inRelayOnlyProcess(t *testing.T) bool {
	t.Helper()
	if os.Getenv("TS_DEBUG_NEVER_DIRECT_UDP") != "" {
		return true
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^"+strings.ReplaceAll(t.Name(), "/", "$/^")+"$")
	// A coverage-instrumented child would write counter files into the
	// parent's GOCOVERDIR and break its profile merge.
	cmd.Env = append(os.Environ(), "TS_DEBUG_NEVER_DIRECT_UDP=true", "GOCOVERDIR=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return false
}

// startRelayed starts an echo engine using dm, since the configured region only
// names a host. Forcing the nearest region lets the home connection start
// before the first netcheck's probe timeout.
func startRelayed(t *testing.T, dm *tailcfg.DERPMap, self, peer node) *Engine {
	t.Helper()
	e := startEcho(t, self.config(t, "HomeDERP = 1\n[DERPRegion]\nID = 1\nNodes = localhost\n", peer, "HomeDERP = 1"))
	e.mc.SetDERPMap(dm)
	e.mc.ForceSetNearestDERP(1)
	return e
}

// TestDERPRoundTrip carries TCP between two passive peers over a local relay
// with direct paths disabled, then lets a fresh pair upgrade to loopback
// through the call-me-maybe the engine sends over that relay.
func TestDERPRoundTrip(t *testing.T) {
	a := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), 0}
	b := node{key.NewNode(), netip.MustParsePrefix("100.64.0.2/32"), 0}
	t.Run("relay-only", func(t *testing.T) {
		if !inRelayOnlyProcess(t) {
			return
		}
		dm := localDERP(t)
		startRelayed(t, dm, b, a)
		ea := startRelayed(t, dm, a, b)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := dialRoundTripUntil(ctx, ea, netip.AddrPortFrom(b.addr.Addr(), testEchoPort)); err != nil {
			t.Fatal(err)
		}
		pong, err := ea.Ping(b.addr.Addr())
		if err != nil || !strings.Contains(pong, " via relay:1 ") {
			t.Fatalf("ping = %q, %v", pong, err)
		}
		if text, _ := ea.Status(""); !strings.Contains(text, "  relay: 1 (localhost)\n") {
			t.Fatalf("status:\n%s", text)
		}
	})
	t.Run("direct-upgrade", func(t *testing.T) {
		dm := localDERP(t)
		startRelayed(t, dm, b, a)
		ea := startRelayed(t, dm, a, b)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := dialRoundTripUntil(ctx, ea, netip.AddrPortFrom(b.addr.Addr(), testEchoPort)); err != nil {
			t.Fatal(err)
		}
		for {
			if st := ea.peerStatus(b.priv.Public()); st != nil && st.CurAddr != "" {
				return
			}
			select {
			case <-ctx.Done():
				t.Fatal("no direct upgrade")
			case <-time.After(200 * time.Millisecond):
			}
		}
	})
}
