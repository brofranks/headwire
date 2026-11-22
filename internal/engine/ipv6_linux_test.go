//go:build !android

package engine

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/tailscale/wireguard-go/tun"
	"github.com/tailscale/wireguard-go/tun/tuntest"
	"tailscale.com/net/netmon"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/router"
)

type ipv6TestRouter struct {
	available bool
	calls     []string
}

func (r *ipv6TestRouter) Up() error {
	r.calls = append(r.calls, "up")
	return nil
}

func (r *ipv6TestRouter) IPv6Available() bool {
	r.calls = append(r.calls, "IPv6Available")
	return r.available
}

func (r *ipv6TestRouter) Set(cfg *router.Config) error {
	if cfg != nil {
		r.calls = append(r.calls, "set")
	}
	return nil
}

func (*ipv6TestRouter) Close() error { return nil }

func (r *ipv6TestRouter) wantCalls(t *testing.T, want ...string) {
	t.Helper()
	if !slices.Equal(r.calls, want) {
		t.Fatalf("router calls = %v, want %v", r.calls, want)
	}
	r.calls = nil
}

func useIPv6TestRouter(t *testing.T, disableIPv6 string) *ipv6TestRouter {
	t.Helper()
	oldCreate, oldRead := createTUN, readTunnelDisableIPv6
	t.Cleanup(func() {
		createTUN, readTunnelDisableIPv6 = oldCreate, oldRead
		netmon.SetTailscaleInterfaceProps("", 0)
	})
	createTUN = func(string, int, ...tun.Option) (tun.Device, error) {
		return tuntest.NewChannelTUN().TUN(), nil
	}
	r := new(ipv6TestRouter)
	readTunnelDisableIPv6 = func(logger.Logf, string) ([]byte, error) {
		r.calls = append(r.calls, "disable_ipv6")
		return []byte(disableIPv6 + "\n"), nil
	}
	t.Cleanup(router.HookNewUserspaceRouter.SetForTest(func(router.NewOpts) (router.Router, error) {
		r.calls = append(r.calls, "new")
		return r, nil
	}))
	return r
}

func TestStartChecksTunnelIPv6(t *testing.T) {
	a := node{key.NewNode(), netip.MustParsePrefix("fd42::1/128"), 0}
	cfg := a.parse(t, "", "")
	for _, tc := range []struct {
		setting string
		wantErr string
		calls   []string
	}{
		{"2", "IPv6 is disabled", []string{"disable_ipv6"}},
		{"0", "IPv6 is unavailable", []string{"disable_ipv6", "new", "up", "IPv6Available"}},
	} {
		t.Run("disable_ipv6="+tc.setting, func(t *testing.T) {
			r := useIPv6TestRouter(t, tc.setting)
			e, err := Start(cfg, tstest.WhileTestRunningLogger(t), Options{})
			if e != nil {
				e.Close()
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Start = %v, want %q", err, tc.wantErr)
			}
			r.wantCalls(t, tc.calls...)
		})
	}
}

func TestReloadChecksTunnelIPv6(t *testing.T) {
	r := useIPv6TestRouter(t, "0")
	a := node{key.NewNode(), netip.MustParsePrefix("10.99.0.1/32"), 0}
	peer6 := node{key.NewNode(), netip.MustParsePrefix("fd42::2/128"), 0}
	peer4 := node{key.NewNode(), netip.MustParsePrefix("10.99.0.3/32"), 0}
	const endpoint = "Endpoint = 127.0.0.1:51820"
	v6Peer := peer6.peerSection(endpoint)
	dual := a.parse(t, "", v6Peer)
	e, err := Start(a.parse(t, "", ""), tstest.WhileTestRunningLogger(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	r.wantCalls(t, "new", "up", "set")

	before := e.state.Load()
	err = e.Reload(dual)
	_, partial := errors.AsType[*ReloadApplyError](err)
	if err == nil || partial || !strings.Contains(err.Error(), "IPv6") {
		t.Fatalf("reload with IPv6 unavailable = %v", err)
	}
	if e.state.Load() != before {
		t.Fatal("rejected reload replaced the running configuration")
	}
	r.wantCalls(t, "IPv6Available")

	r.available = true
	if err := e.Reload(dual); err != nil {
		t.Fatal(err)
	}
	r.wantCalls(t, "IPv6Available", "set")
	r.available = false
	if err := e.Reload(dual); err != nil {
		t.Fatalf("unchanged IPv6 routes: %v", err)
	}
	if err := e.Reload(a.parse(t, "", v6Peer+peer4.peerSection(endpoint))); err != nil {
		t.Fatalf("IPv4 peer addition: %v", err)
	}
	r.wantCalls(t, "set")
}
