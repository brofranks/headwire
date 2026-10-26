package provider

import "github.com/tailscale/wireguard-go/tun"

// OpenTun adopts the descriptor VpnService.establish returned, which the
// engine owns from here on. The interface MTU is whatever the app set before
// establishing the tunnel.
func OpenTun(fd int) (tun.Device, error) {
	dev, _, err := tun.CreateUnmonitoredTUNFromFD(fd)
	return dev, err
}
