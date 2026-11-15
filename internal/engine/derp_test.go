package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/derp/derpserver"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

// localDERP serves one relay region, with DERP and STUN, on loopback.
func localDERP(t *testing.T) *tailcfg.DERPMap {
	t.Helper()
	d := derpserver.New(key.NewNode(), tstest.WhileTestRunningLogger(t))
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
func startRelayed(t *testing.T, dm *tailcfg.DERPMap, self, peer node, logf logger.Logf) *testNode {
	t.Helper()
	cfg := self.config(t, "HomeDERP = 1\n[DERPRegion]\nID = 1\nNodes = localhost\n", peer, "HomeDERP = 1")
	e := startEchoLogf(t, cfg, logf)
	e.mc.SetDERPMap(dm)
	e.mc.ForceSetNearestDERP(1)
	return e
}

// TestDERPRoundTrip carries TCP between two passive peers over a local relay
// with direct paths disabled, then lets a fresh pair upgrade to loopback
// through the call-me-maybe magicsock sends over that relay.
func TestDERPRoundTrip(t *testing.T) {
	a := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), 0}
	b := node{key.NewNode(), netip.MustParsePrefix("100.64.0.2/32"), 0}
	t.Run("relay-only", func(t *testing.T) {
		if !inRelayOnlyProcess(t) {
			return
		}
		dm := localDERP(t)
		startRelayed(t, dm, b, a, tstest.WhileTestRunningLogger(t))
		ea := startRelayed(t, dm, a, b, tstest.WhileTestRunningLogger(t))
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
		startRelayed(t, dm, b, a, tstest.WhileTestRunningLogger(t))
		ea := startRelayed(t, dm, a, b, tstest.WhileTestRunningLogger(t))
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := dialRoundTripUntil(ctx, ea, netip.AddrPortFrom(b.addr.Addr(), testEchoPort)); err != nil {
			t.Fatal(err)
		}
		awaitDirect(ctx, t, ea, b)
	})
}

// awaitDirect fails t unless e reaches peer directly before ctx ends.
func awaitDirect(ctx context.Context, t *testing.T, e *testNode, peer node) {
	t.Helper()
	for {
		if st := e.peerStatus(peer.priv.Public()); st != nil && st.CurAddr != "" {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("no direct path to %v", peer.addr)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// logWatch forwards to the test log and lets a test wait for a line.
type logWatch struct {
	logf  logger.Logf
	mu    sync.Mutex
	lines []string
	grew  chan struct{} // closed and replaced on each line
}

func newLogWatch(t *testing.T) *logWatch {
	return &logWatch{logf: tstest.WhileTestRunningLogger(t), grew: make(chan struct{})}
}

func (w *logWatch) Logf(format string, args ...any) {
	w.logf(format, args...)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lines = append(w.lines, fmt.Sprintf(format, args...))
	close(w.grew)
	w.grew = make(chan struct{})
}

// await fails t unless a line containing s is logged within timeout.
func (w *logWatch) await(t *testing.T, s string, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for next := 0; ; {
		w.mu.Lock()
		for ; next < len(w.lines); next++ {
			if strings.Contains(w.lines[next], s) {
				w.mu.Unlock()
				return
			}
		}
		grew := w.grew
		w.mu.Unlock()
		select {
		case <-grew:
		case <-deadline:
			t.Fatalf("no log line containing %q within %v", s, timeout)
		}
	}
}

// TestDERPDirectAfterLateJoinOrRestart requires two DERP-mode peers to reach
// each other directly when one joins the relay after the other started
// sending to it, and when one restarts. Neither peer has the other's
// endpoints, so each side's call-me-maybe over the relay is the only way the
// other learns them, and one sent while the peer is absent is dropped.
func TestDERPDirectAfterLateJoinOrRestart(t *testing.T) {
	a := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), 0}
	b := node{key.NewNode(), netip.MustParsePrefix("100.64.0.2/32"), 0}
	toB := netip.AddrPortFrom(b.addr.Addr(), testEchoPort)
	toA := netip.AddrPortFrom(a.addr.Addr(), testEchoPort)
	// connect completes a round trip from x to y, then waits for both
	// peers to reach each other directly.
	connect := func(t *testing.T, x, y *testNode, nx, ny node, to netip.AddrPort) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := dialRoundTripUntil(ctx, x, to); err != nil {
			t.Fatal(err)
		}
		awaitDirect(ctx, t, x, ny)
		awaitDirect(ctx, t, y, nx)
	}
	t.Run("late-join", func(t *testing.T) {
		dm := localDERP(t)
		wa := newLogWatch(t)
		ea := startRelayed(t, dm, a, b, wa.Logf)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		done := make(chan struct{})
		var dialErr error
		go func() {
			dialErr = dialRoundTripUntil(ctx, ea, toB)
			close(done)
		}()
		defer func() {
			cancel()
			<-done
		}()
		wa.await(t, "does not know about peer "+b.priv.Public().ShortString(), 30*time.Second)
		eb := startRelayed(t, dm, b, a, tstest.WhileTestRunningLogger(t))
		select {
		case <-done:
			if dialErr != nil {
				t.Fatal(dialErr)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		awaitDirect(ctx, t, ea, b)
		awaitDirect(ctx, t, eb, a)
	})
	t.Run("restart", func(t *testing.T) {
		dm := localDERP(t)
		ea := startRelayed(t, dm, a, b, tstest.WhileTestRunningLogger(t))
		// The subtest's cleanup closes the first instance of b.
		if !t.Run("first", func(t *testing.T) {
			eb := startRelayed(t, dm, b, a, tstest.WhileTestRunningLogger(t))
			connect(t, ea, eb, a, b, toB)
		}) {
			return
		}
		eb := startRelayed(t, dm, b, a, tstest.WhileTestRunningLogger(t))
		connect(t, eb, ea, b, a, toA)
	})
}
