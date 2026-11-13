//go:build unix

package engine

import (
	"brof.dev/headwire/internal/config"
	"github.com/tailscale/wireguard-go/tun"
)

// checkKernelConfig has nothing to refuse outside Windows.
func checkKernelConfig(*config.Config) error { return nil }

// dnsInterfaceName names the device for the OS DNS configurator.
func dnsInterfaceName(dev tun.Device) (string, error) {
	return dev.Name()
}
