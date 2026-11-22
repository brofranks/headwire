package engine

import (
	"errors"
	"net/netip"
	"runtime"
	"slices"
	"testing"

	"brof.dev/headwire/internal/config"
	"github.com/tailscale/wireguard-go/tun"
	"github.com/tailscale/wireguard-go/tun/tuntest"
	"tailscale.com/health"
	"tailscale.com/net/dns"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/router"
)

// TestKernelTUNHostCheck checks that Start returns a host rejection before
// creating a TUN.
func TestKernelTUNHostCheck(t *testing.T) {
	oldCheck, oldCreate := checkHost, createTUN
	t.Cleanup(func() { checkHost, createTUN = oldCheck, oldCreate })
	want := errors.New("unsupported host")
	checkHost = func(*config.Config) error { return want }
	createTUN = func(string, int, ...tun.Option) (tun.Device, error) {
		t.Fatal("created a TUN after host rejection")
		return nil, nil
	}
	a := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), 0}
	e, err := Start(a.parse(t, "", ""), tstest.WhileTestRunningLogger(t), Options{})
	if e != nil {
		e.Close()
		t.Fatal("started on an unsupported host")
	}
	if !errors.Is(err, want) {
		t.Fatalf("host rejection = %v, want %v", err, want)
	}
}

// TestKernelTUN runs Start's default arm on a channel device standing in for
// the kernel TUN, with fake host checks, an OS router and a DNS configurator.
// The real device and configurator need root.
func TestKernelTUN(t *testing.T) {
	oldCheck, oldCreate, oldDNS, oldMark := checkHost, createTUN, newOSConfigurator, useSocketMark
	t.Cleanup(func() {
		checkHost, createTUN, newOSConfigurator, useSocketMark = oldCheck, oldCreate, oldDNS, oldMark
	})
	checkHost = func(*config.Config) error { return nil }
	a := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), 0}
	plain, withDNS := a.parse(t, "", ""), a.parse(t, "DNS = 192.0.2.53, example.com", "")
	device := func(dev tun.Device, err error) func(string, int, ...tun.Option) (tun.Device, error) {
		return func(string, int, ...tun.Option) (tun.Device, error) { return dev, err }
	}
	dnsErr, setErr := errors.New("no resolver"), errors.New("no resolved")
	rec := &recordingDNS{}
	configurator := func(newErr, setErr error) {
		newOSConfigurator = func(*Engine, *health.Tracker, tun.Device) (dns.OSConfigurator, error) {
			if newErr != nil {
				return nil, newErr
			}
			rec.OSConfigurator, _ = dns.NewNoopManager()
			rec.err = setErr
			return rec, nil
		}
	}
	logf := tstest.WhileTestRunningLogger(t)

	// Without osrouter linked, router.New fails as on an unsupported OS.
	for name, create := range map[string]func(string, int, ...tun.Option) (tun.Device, error){
		"create": device(nil, errors.New("no /dev/net/tun")),
		"name":   device(unnamedTun{tuntest.NewChannelTUN().TUN()}, nil),
		"router": device(tuntest.NewChannelTUN().TUN(), nil),
	} {
		createTUN = create
		if _, err := Start(plain, logf, Options{}); err == nil {
			t.Fatalf("%s: started", name)
		}
	}

	configurator(dnsErr, nil)
	createTUN = device(tuntest.NewChannelTUN().TUN(), nil)
	if _, err := Start(withDNS, logf, Options{}); !errors.Is(err, dnsErr) {
		t.Fatalf("DNS setup failure = %v, want %v", err, dnsErr)
	}
	configurator(nil, nil)
	createTUN = device(tuntest.NewChannelTUN().TUN(), nil)
	if _, err := Start(withDNS, logf, Options{}); err == nil || !rec.closed {
		t.Fatalf("router setup failure = %v, DNS closed = %v", err, rec.closed)
	}

	t.Run("router up", func(t *testing.T) {
		upErr := errors.New("router failed to start")
		t.Cleanup(router.HookNewUserspaceRouter.SetForTest(func(o router.NewOpts) (router.Router, error) {
			return failingUpRouter{Router: router.NewFake(o.Logf), err: upErr}, nil
		}))
		dev := &countingTun{Device: tuntest.NewChannelTUN().TUN()}
		createTUN = device(dev, nil)
		if _, err := Start(plain, tstest.WhileTestRunningLogger(t), Options{}); !errors.Is(err, upErr) {
			t.Fatalf("router startup failure = %v, want %v", err, upErr)
		}
		if dev.closes != 1 {
			t.Fatalf("device closed %d times, want 1", dev.closes)
		}
	})

	defer router.HookNewUserspaceRouter.SetForTest(func(o router.NewOpts) (router.Router, error) {
		return router.NewFake(o.Logf), nil
	})()
	configurator(nil, setErr)
	createTUN = device(tuntest.NewChannelTUN().TUN(), nil)
	if _, err := Start(withDNS, logf, Options{}); !errors.Is(err, setErr) {
		t.Fatalf("SetDNS failure = %v, want %v", err, setErr)
	}
	configurator(nil, nil)
	*rec = recordingDNS{}
	createTUN = device(tuntest.NewChannelTUN().TUN(), nil)
	searchOnly, err := Start(a.parse(t, "DNS = corp.example", ""), logf, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if searchOnly.hostDNS != nil {
		t.Fatal("search-only DNS configured a host resolver")
	}
	searchOnly.Close()
	if rec.closed {
		t.Fatal("search-only DNS closed a host resolver")
	}
	useSocketMark = func() bool { return true }
	// Only Linux marks the transport sockets.
	wantMark := "off\n"
	if runtime.GOOS == "linux" {
		wantMark = "0x80000\n"
	}
	for _, cfg := range []*config.Config{plain, withDNS} {
		*rec = recordingDNS{}
		createTUN = device(tuntest.NewChannelTUN().TUN(), nil)
		e, err := Start(cfg, logf, Options{})
		if err != nil {
			t.Fatal(err)
		}
		mark, _ := e.Status("fwmark")
		e.Close()
		if mark != wantMark {
			t.Fatalf("fwmark = %q", mark)
		}
		if !slices.Equal(rec.set.Nameservers, cfg.Interface.DNS) ||
			!slices.Equal(rec.set.SearchDomains, cfg.Interface.DNSSearch) {
			t.Fatalf("SetDNS %+v, want %v %v", rec.set, cfg.Interface.DNS, cfg.Interface.DNSSearch)
		}
		if rec.closed != (cfg == withDNS) {
			t.Fatalf("closed = %v", rec.closed)
		}
	}

	// Only Windows refuses an MTU other than the engine default.
	createTUN = device(tuntest.NewChannelTUN().TUN(), nil)
	e, err := Start(a.parse(t, "MTU = 1420", ""), logf, Options{})
	if (err != nil) != (runtime.GOOS == "windows") {
		t.Fatalf("MTU 1420: %v", err)
	}
	if err == nil {
		e.Close()
	}
}

type failingUpRouter struct {
	router.Router
	err error
}

func (r failingUpRouter) Up() error { return r.err }

// recordingDNS is the OS configurator Start receives, keeping what it set.
type recordingDNS struct {
	dns.OSConfigurator
	err    error
	set    dns.OSConfig
	closed bool
}

func (r *recordingDNS) SetDNS(c dns.OSConfig) error { r.set = c; return r.err }
func (r *recordingDNS) Close() error                { r.closed = true; return nil }
