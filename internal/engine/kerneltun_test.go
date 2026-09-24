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
	"tailscale.com/control/controlknobs"
	"tailscale.com/health"
	"tailscale.com/net/dns"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
	"tailscale.com/util/syspolicy/policyclient"
	"tailscale.com/wgengine/router"
)

// TestKernelTUN runs Start's default arm on a channel device standing in for
// the kernel TUN, with a fake OS router and DNS configurator: the real ones
// need root.
func TestKernelTUN(t *testing.T) {
	oldCreate, oldDNS, oldMark := createTUN, newOSConfigurator, useSocketMark
	t.Cleanup(func() { createTUN, newOSConfigurator, useSocketMark = oldCreate, oldDNS, oldMark })
	a := node{key.NewNode(), netip.MustParsePrefix("100.64.0.1/32"), 0}
	plain, withDNS := a.parse(t, "", ""), a.parse(t, "DNS = 192.0.2.53, example.com", "")
	device := func(dev tun.Device, err error) func(string, int) (tun.Device, error) {
		return func(string, int) (tun.Device, error) { return dev, err }
	}
	dnsErr, setErr := errors.New("no resolver"), errors.New("no resolved")
	rec := &recordingDNS{}
	configurator := func(newErr, setErr error) {
		newOSConfigurator = func(logger.Logf, *health.Tracker, *eventbus.Bus, policyclient.Client, *controlknobs.Knobs, string) (dns.OSConfigurator, error) {
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
	for name, create := range map[string]func(string, int) (tun.Device, error){
		"create": device(nil, errors.New("no /dev/net/tun")),
		"name":   device(unnamedTun{tuntest.NewChannelTUN().TUN()}, nil),
		"router": device(tuntest.NewChannelTUN().TUN(), nil),
	} {
		createTUN = create
		if _, err := Start(plain, logf, Options{}); err == nil {
			t.Fatalf("%s: started", name)
		}
	}

	defer router.HookNewUserspaceRouter.SetForTest(func(o router.NewOpts) (router.Router, error) {
		return router.NewFake(o.Logf), nil
	})()
	for _, want := range []error{dnsErr, setErr} {
		configurator(dnsErr, setErr)
		dnsErr = nil // the second round reaches SetDNS
		createTUN = device(tuntest.NewChannelTUN().TUN(), nil)
		if _, err := Start(withDNS, logf, Options{}); !errors.Is(err, want) {
			t.Fatalf("DNS failure %v: %v", want, err)
		}
	}
	configurator(nil, nil)
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
}

// recordingDNS is the OS configurator Start receives, keeping what it set.
type recordingDNS struct {
	dns.OSConfigurator
	err    error
	set    dns.OSConfig
	closed bool
}

func (r *recordingDNS) SetDNS(c dns.OSConfig) error { r.set = c; return r.err }
func (r *recordingDNS) Close() error                { r.closed = true; return nil }
