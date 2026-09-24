package apple

import (
	"errors"
	"fmt"
	"net"
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
	NetworkChanged(h) // ignored before Start
	if err := Start(h, tuntest.NewChannelTUN().TUN(), t.Logf); err != nil {
		t.Fatal(err)
	}
	if err := Start(h, tuntest.NewChannelTUN().TUN(), t.Logf); err == nil {
		t.Error("handle started twice")
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
	NetworkChanged(h)
	NetworkChanged(h + 1) // ignored for a stale handle
	Stop(h)
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
		Stop(h)
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
	t.Cleanup(func() { Stop(h) })
	Stop(h + 1) // A rejected/non-owning provider cannot release admission.
	if _, _, err := Prepare(cfg); err == nil {
		t.Fatal("lost reservation")
	}
	if err := Start(h, tuntest.NewChannelTUN().TUN(), t.Logf); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Prepare(cfg); err == nil {
		t.Fatal("admitted alongside running engine")
	}
	Stop(h)
	next, _, err := Prepare(cfg)
	if err != nil {
		t.Fatal(err)
	}
	Stop(h) // A late stop cannot release the newer provider.
	if _, _, err := Prepare(cfg); err == nil {
		t.Fatal("late stop released new owner")
	}
	Stop(next)
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
	t.Cleanup(func() { Stop(h) })
	if err := Start(h, failingNameTun{tuntest.NewChannelTUN().TUN()}, t.Logf); err == nil {
		t.Fatal("start succeeded")
	}
	if _, _, err := Prepare(cfg); err == nil {
		t.Fatal("released before provider cleaned up network settings")
	}
	Stop(h)
	next, _, err := Prepare(cfg)
	if err != nil {
		t.Fatal(err)
	}
	Stop(next)
}
