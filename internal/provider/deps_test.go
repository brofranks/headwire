package provider

import (
	"maps"
	"testing"

	"tailscale.com/tstest/deptest"
)

// badDeps is what no provider links: the host owns addresses, routes and
// DNS, and the iOS provider lives under the NetworkExtension memory limit,
// so growth is a defect.
var badDeps = map[string]string{
	"testing":                                "do not use testing package in production code",
	"text/template":                          "linker bloat (MethodByName)",
	"html/template":                          "linker bloat (MethodByName)",
	"tailscale.com/net/wsconn":               "https://github.com/tailscale/tailscale/issues/13762",
	"github.com/coder/websocket":             "https://github.com/tailscale/tailscale/issues/13762",
	"database/sql/driver":                    "no SQL database",
	"tailscale.com/feature/capture":          "no debug packet capture",
	"tailscale.com/wgengine/router/osrouter": "the host owns addresses and routes",
}

func TestIOSDeps(t *testing.T) {
	deptest.DepChecker{GOOS: "ios", GOARCH: "arm64", BadDeps: badDeps}.Check(t)
}

// TestAndroidDeps models the cgo c-shared build, where the Linux firewall
// and D-Bus packages and Tailscale's own Android features must stay out.
func TestAndroidDeps(t *testing.T) {
	bad := maps.Clone(badDeps)
	for _, p := range []string{
		"github.com/godbus/dbus/v5",
		"github.com/google/nftables",
		"github.com/coreos/go-iptables/iptables",
		"tailscale.com/util/linuxfw",
		"tailscale.com/feature/androidbin",
		"tailscale.com/feature/androiddns",
	} {
		bad[p] = "the host owns the network stack"
	}
	deptest.DepChecker{
		GOOS:     "android",
		GOARCH:   "arm64",
		ExtraEnv: []string{"CGO_ENABLED=1"},
		BadDeps:  bad,
	}.Check(t)
}
