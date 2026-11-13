package engine

import (
	"errors"
	"fmt"

	"brof.dev/headwire/internal/config"
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
	// client's adapter GUID and tunnel type. Headwire uses its own GUID, and
	// host networking requires Tailscale to be absent. The tunnel type stays
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

// checkKernelConfig refuses host configurations whose Windows router or DNS
// configurator would act on Tailscale's firewall rules, NRPT rules or
// killswitch helper.
func checkKernelConfig(cfg *config.Config) error {
	// The DNS configurator owns NRPT rules under Tailscale's registry key.
	if len(cfg.Interface.DNS) > 0 {
		return errors.New("DNS nameservers are not supported for Windows host networking")
	}
	// The router starts a /firewall child process for a default route.
	for _, route := range Routes(cfg) {
		if route.Bits() == 0 {
			return errors.New("default routes are not supported for Windows host networking")
		}
	}
	// The router replaces the Tailscale-In and Tailscale-Process firewall
	// rules. This checks at startup only and cannot exclude a portable
	// Tailscale or one installed later.
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return fmt.Errorf("inspect Tailscale service: %w", err)
	}
	defer windows.CloseServiceHandle(manager)
	service, err := windows.OpenService(manager, windows.StringToUTF16Ptr("Tailscale"), windows.SERVICE_QUERY_STATUS)
	if err == nil {
		windows.CloseServiceHandle(service)
		return errors.New("host networking on Windows requires the Tailscale service to be absent")
	}
	if !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return fmt.Errorf("inspect Tailscale service: %w", err)
	}
	return nil
}
