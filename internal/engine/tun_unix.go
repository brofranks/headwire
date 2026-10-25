//go:build unix

package engine

import "github.com/tailscale/wireguard-go/tun"

// dnsInterfaceName names the device for the OS DNS configurator.
func dnsInterfaceName(dev tun.Device) (string, error) {
	return dev.Name()
}
