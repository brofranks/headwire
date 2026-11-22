//go:build !android

package engine

import (
	"fmt"
	"os"
	"strings"

	"brof.dev/headwire/internal/config"
	"tailscale.com/types/logger"
	"tailscale.com/util/linuxfw"
	"tailscale.com/wgengine/router"
)

// readTunnelDisableIPv6 checks host IPv6 support before reading the tunnel's
// own disable_ipv6 setting.
var readTunnelDisableIPv6 = func(logf logger.Logf, name string) ([]byte, error) {
	if err := linuxfw.CheckIPv6(logf); err != nil {
		return nil, err
	}
	return os.ReadFile("/proc/sys/net/ipv6/conf/" + name + "/disable_ipv6")
}

// checkTunnelIPv6 rejects a known host or tunnel IPv6 failure before the
// router takes ownership of its policy rules.
func (e *Engine) checkTunnelIPv6(cfg *config.Config) error {
	if !addsTunnelIPv6(nil, cfg) {
		return nil
	}
	b, err := readTunnelDisableIPv6(e.logf, e.tunName)
	if err != nil {
		return fmt.Errorf("checking IPv6 on %s: %w", e.tunName, err)
	}
	if strings.TrimSpace(string(b)) != "0" {
		return fmt.Errorf("IPv6 is disabled on %s, set net.ipv6.conf.default.disable_ipv6=0 before startup", e.tunName)
	}
	return nil
}

// routerIPv6 returns the native router's availability report when it has one.
func routerIPv6(r router.Router) func() bool {
	if v, ok := r.(interface{ IPv6Available() bool }); ok {
		return v.IPv6Available
	}
	return nil
}
