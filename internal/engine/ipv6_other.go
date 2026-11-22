//go:build !linux || android

package engine

import (
	"brof.dev/headwire/internal/config"
	"tailscale.com/wgengine/router"
)

func (*Engine) checkTunnelIPv6(*config.Config) error { return nil }

func routerIPv6(router.Router) func() bool { return nil }
