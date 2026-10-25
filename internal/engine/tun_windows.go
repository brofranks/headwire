package engine

import (
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// dnsInterfaceName names the device for the OS DNS configurator, which on
// Windows addresses the adapter by its GUID rather than its name.
func dnsInterfaceName(dev tun.Device) (string, error) {
	guid, err := winipcfg.LUID(dev.(*tun.NativeTun).LUID()).GUID()
	if err != nil {
		return "", err
	}
	return guid.String(), nil
}

func init() {
	// engine imports tstun, so tstun's init has already set the Tailscale
	// client's adapter GUID and tunnel type. A Headwire node beside an
	// installed Tailscale needs its own adapter. The tunnel type stays
	// "Tailscale": the adapter description it yields is how tailscale.com's
	// netmon and netns tell this tunnel from the host's adapters when they
	// bind sockets and pick a default route.
	tun.WintunStaticRequestedGUID = &windows.GUID{
		Data1: 0x69048b9c,
		Data2: 0xa860,
		Data3: 0x4627,
		Data4: [8]byte{0xa3, 0x7f, 0x0b, 0x4a, 0x61, 0xc0, 0xb3, 0x8f},
	}
}
