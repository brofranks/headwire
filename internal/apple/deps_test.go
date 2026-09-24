package apple

import (
	"testing"

	"tailscale.com/tstest/deptest"
)

// TestIOSDeps bounds what the iOS provider links: it lives under the
// NetworkExtension memory limit, so growth is a defect.
func TestIOSDeps(t *testing.T) {
	deptest.DepChecker{
		GOOS:   "ios",
		GOARCH: "arm64",
		BadDeps: map[string]string{
			"testing":                                "do not use testing package in production code",
			"text/template":                          "linker bloat (MethodByName)",
			"html/template":                          "linker bloat (MethodByName)",
			"tailscale.com/net/wsconn":               "https://github.com/tailscale/tailscale/issues/13762",
			"github.com/coder/websocket":             "https://github.com/tailscale/tailscale/issues/13762",
			"database/sql/driver":                    "no SQL database",
			"tailscale.com/feature/capture":          "no debug packet capture",
			"tailscale.com/wgengine/router/osrouter": "the host owns addresses and routes",
		},
	}.Check(t)
}
