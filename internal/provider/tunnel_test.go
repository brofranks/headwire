package provider

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"brof.dev/headwire/internal/config"
	"brof.dev/headwire/internal/discokey"
	"github.com/tailscale/wireguard-go/tun"
	"github.com/tailscale/wireguard-go/tun/tuntest"
	"tailscale.com/types/key"
)

// write installs main.conf in a fresh config.Dir with one peer.
func write(t *testing.T, allowed string) {
	t.Helper()
	config.Dir = t.TempDir()
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	peer := key.NewNode()
	src := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 100.64.0.1/32\nAddress = fd00::1/128\nListenPort = %d\nDNS = 100.64.0.53, corp.example\n\n[Peer]\nPublicKey = %s\nDiscoKey = %s\nAllowedIPs = %s\n",
		config.EncodeKey(key.NewNode().Raw32()), c.LocalAddr().(*net.UDPAddr).Port,
		//lint:ignore SA1019 raw keys; see config.EncodeKey.
		config.EncodeKey(peer.Public().Raw32()), config.EncodeKey(discokey.PublicForNode(peer).Raw32()), allowed)
	if err := os.WriteFile(filepath.Join(config.Dir, "main.conf"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLifecycle(t *testing.T) {
	write(t, "0.0.0.0/0, 100.64.0.2/32, 10.1.0.0/16, ::/0, fd00::2/128")
	cfg, err := config.LoadName("main")
	if err != nil {
		t.Fatal(err)
	}
	h, s, err := Prepare(cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := &Settings{
		MTU:           1280,
		IPv4Addresses: []Prefix{{"100.64.0.1", "255.255.255.255", 32}},
		IPv4Routes: []Prefix{
			{"0.0.0.0", "0.0.0.0", 0},
			{"10.1.0.0", "255.255.0.0", 16},
			{"100.64.0.2", "255.255.255.255", 32},
		},
		IPv6Addresses: []Prefix{{"fd00::1", "", 128}},
		IPv6Routes:    []Prefix{{"::", "", 0}, {"fd00::2", "", 128}},
		DNSServers:    []string{"100.64.0.53"},
		DNSSearch:     []string{"corp.example"},
	}
	if !reflect.DeepEqual(s, want) {
		t.Errorf("settings = %+v, want %+v", s, want)
	}
	if _, err := Status(h, ""); err == nil {
		t.Error("Status succeeded before Start")
	}
	var updates, arms, disarms int
	update := func() error { updates++; return nil }
	if err := NetworkChanged(h, update); err != nil || updates != 1 {
		t.Errorf("NetworkChanged before Start = %v after %d updates", err, updates)
	}
	if err := Start(h, tuntest.NewChannelTUN().TUN(), t.Logf, func() { arms++ }); err != nil {
		t.Fatal(err)
	}
	if err := Start(h, tuntest.NewChannelTUN().TUN(), t.Logf, func() { arms++ }); err == nil {
		t.Error("handle started twice")
	}
	if arms != 1 {
		t.Errorf("arm ran %d times", arms)
	}
	out, err := Status(h, "")
	if err != nil || !strings.Contains(out, "private key: (hidden)") {
		t.Errorf("Status = %q, %v", out, err)
	}
	for request, want := range map[string]string{"ip": "100.64.0.1\nfd00::1\n", "ip -4": "100.64.0.1\n", "ip -6": "fd00::1\n"} {
		if got, err := Status(h, request); err != nil || got != want {
			t.Errorf("Status(%q) = %q, %v; want %q", request, got, err, want)
		}
	}
	if err := NetworkChanged(h, update); err != nil {
		t.Error(err)
	}
	if err := NetworkChanged(h+1, update); err == nil || updates != 2 {
		t.Errorf("stale NetworkChanged = %v after %d updates", err, updates)
	}
	if Stop(h+1, func() { disarms++ }) || disarms != 0 {
		t.Error("a stale Stop disarmed the session")
	}
	if !Stop(h, func() { disarms++ }) || disarms != 1 {
		t.Errorf("Stop disarmed %d times", disarms)
	}
	if _, err := Status(h, ""); err == nil {
		t.Error("Status succeeded after Stop")
	}
	if _, err := Status(h, "ip"); err == nil {
		t.Error("ip succeeded after Stop")
	}
}

func TestDERPProfile(t *testing.T) {
	write(t, "100.64.0.2/32")
	path := filepath.Join(config.Dir, "main.conf")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Replace(string(src), "[Interface]\n", "[Interface]\nHomeDERP = 1\n", 1) + "\n# Relay location\n[DERPRegion]\nID = 1\nNodes = relay.example\n"
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	// macOS loads a file and iOS parses imported text. Both feed Prepare.
	for _, load := range []func() (*config.Config, error){
		func() (*config.Config, error) {
			return config.LoadName("main")
		},
		func() (*config.Config, error) { return config.Parse([]byte(text)) },
	} {
		cfg, err := load()
		if err != nil {
			t.Fatal(err)
		}
		h, _, err := Prepare(cfg)
		if err != nil {
			t.Fatal(err)
		}
		Stop(h, nil)
	}
}

// TestExclusivePreparation covers admission over both prepared settings and
// a running engine, including starts requested by separate controllers in
// the same provider process.
func TestExclusivePreparation(t *testing.T) {
	write(t, "100.64.0.2/32")
	cfg, err := config.LoadName("main")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	handles := make(chan int32, 16)
	for range 16 {
		wg.Go(func() {
			h, _, err := Prepare(cfg)
			if err == nil {
				handles <- h
				return
			}
			if !strings.Contains(err.Error(), "another headwire tunnel") {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	close(handles)
	if len(handles) != 1 {
		t.Fatalf("admitted %d providers", len(handles))
	}
	h := <-handles
	t.Cleanup(func() { Stop(h, nil) })
	if Stop(h+1, nil) { // A rejected/non-owning provider cannot release admission.
		t.Fatal("stale handle released admission")
	}
	if _, _, err := Prepare(cfg); err == nil {
		t.Fatal("lost reservation")
	}
	if err := Start(h, tuntest.NewChannelTUN().TUN(), t.Logf, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Prepare(cfg); err == nil {
		t.Fatal("admitted alongside running engine")
	}
	if !Stop(h, nil) {
		t.Fatal("owner could not release admission")
	}
	next, _, err := Prepare(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if Stop(h, nil) { // A late stop cannot release the newer provider.
		t.Fatal("late stop released new owner")
	}
	if _, _, err := Prepare(cfg); err == nil {
		t.Fatal("late stop released new owner")
	}
	Stop(next, nil)
}

func TestNetworkChangedSerializesStop(t *testing.T) {
	h, _, err := Prepare(&config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Stop(h, nil) })
	entered, release := make(chan struct{}), make(chan struct{})
	updated := make(chan error, 1)
	var updateFinished bool
	go func() {
		updated <- NetworkChanged(h, func() error {
			close(entered)
			<-release
			updateFinished = true
			return nil
		})
	}()
	<-entered
	if mu.TryLock() {
		mu.Unlock()
		t.Error("network update runs outside the session lock")
	}
	var closed bool
	dev := closeTun{tuntest.NewChannelTUN().TUN(), &closed}
	var ready, done sync.WaitGroup
	for _, operation := range []func(){
		func() {
			if err := Start(h-1, dev, t.Logf, func() { t.Error("stale Start armed hooks") }); err == nil {
				t.Error("stale Start succeeded")
			}
		},
		func() {
			if err := NetworkChanged(h-1, func() error {
				t.Error("stale NetworkChanged updated hooks")
				return nil
			}); err == nil {
				t.Error("stale NetworkChanged succeeded")
			}
		},
		func() {
			if Stop(h-1, func() { t.Error("stale Stop disarmed hooks") }) {
				t.Error("stale Stop released the session")
			}
		},
		func() {
			if !Stop(h, func() {
				if !updateFinished {
					t.Error("Stop disarmed hooks before the network update finished")
				}
			}) {
				t.Error("owner Stop did not release the session")
			}
		},
	} {
		ready.Add(1)
		done.Go(func() {
			ready.Done()
			operation()
		})
	}
	ready.Wait()
	close(release)
	done.Wait()
	if err := <-updated; err != nil {
		t.Fatal(err)
	}
	if !closed {
		t.Error("stale Start left its device open")
	}
}

func TestStopSerializesReplacementPreparation(t *testing.T) {
	cfg := &config.Config{}
	h, _, err := Prepare(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Stop(h, nil) })
	entered, release := make(chan struct{}), make(chan struct{})
	stopped := make(chan bool, 1)
	go func() {
		stopped <- Stop(h, func() {
			close(entered)
			<-release
		})
	}()
	<-entered
	if mu.TryLock() {
		mu.Unlock()
		t.Error("disarm runs outside the session lock")
	}
	ready, prepared := make(chan struct{}), make(chan struct{})
	var replacement int32
	var prepareErr error
	go func() {
		close(ready)
		replacement, _, prepareErr = Prepare(cfg)
		close(prepared)
	}()
	<-ready
	close(release)
	<-prepared
	if !<-stopped {
		t.Error("owner Stop did not release the session")
	}
	if prepareErr != nil {
		t.Fatal(prepareErr)
	}
	t.Cleanup(func() { Stop(replacement, nil) })
	if replacement == h || replacement == 0 {
		t.Fatalf("replacement handle = %d, previous = %d", replacement, h)
	}
	if Stop(h, func() { t.Error("late Stop disarmed replacement hooks") }) {
		t.Error("late Stop released the replacement")
	}
	if err := NetworkChanged(replacement, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}

type failingNameTun struct{ tun.Device }

func (f failingNameTun) Name() (string, error) { return "", errors.New("test device failure") }

func TestFailedStartHoldsAdmissionUntilProviderCleanup(t *testing.T) {
	write(t, "100.64.0.2/32")
	cfg, err := config.LoadName("main")
	if err != nil {
		t.Fatal(err)
	}
	h, _, err := Prepare(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { Stop(h, nil) })
	if err := Start(h, failingNameTun{tuntest.NewChannelTUN().TUN()}, t.Logf, nil); err == nil {
		t.Fatal("start succeeded")
	}
	if _, _, err := Prepare(cfg); err == nil {
		t.Fatal("released before provider cleaned up network settings")
	}
	Stop(h, nil)
	next, _, err := Prepare(cfg)
	if err != nil {
		t.Fatal(err)
	}
	Stop(next, nil)
}

type closeTun struct {
	tun.Device
	closed *bool
}

func (c closeTun) Close() error {
	*c.closed = true
	return c.Device.Close()
}

func TestStartWithoutSession(t *testing.T) {
	var closed bool
	if err := Start(0, closeTun{tuntest.NewChannelTUN().TUN(), &closed}, t.Logf, nil); err == nil {
		t.Fatal("start succeeded")
	}
	if !closed {
		t.Fatal("device left open")
	}
}

func TestResolve(t *testing.T) {
	c := &config.Config{
		Regions: map[int]config.Region{1: {ID: 1, Nodes: []string{"localhost"}}},
		Peers:   []config.Peer{{Endpoint: "localhost:51820"}, {}},
	}
	if err := Resolve(c); err != nil {
		t.Fatal(err)
	}
	if a, err := netip.ParseAddrPort(c.Peers[0].Endpoint); err != nil || !a.Addr().IsLoopback() || a.Port() != 51820 {
		t.Fatalf("endpoint %q", c.Peers[0].Endpoint)
	}
	if c.Peers[1].Endpoint != "" {
		t.Fatalf("passive peer gained endpoint %q", c.Peers[1].Endpoint)
	}
	n := c.DERPMap().Regions[1].Nodes[0]
	if n.HostName != "localhost" || (n.IPv4 != "127.0.0.1" && n.IPv6 != "::1") {
		t.Fatalf("node %+v", n)
	}
	c.Regions[1] = config.Region{ID: 1, Nodes: []string{"relay.invalid"}}
	if err := Resolve(c); err == nil || !strings.Contains(err.Error(), "relay.invalid") {
		t.Fatalf("unresolvable node: %v", err)
	}
}
