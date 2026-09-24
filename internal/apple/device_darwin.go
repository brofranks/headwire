package apple

import (
	"os"

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
)

// OpenTun wraps a duplicate of the provider's utun descriptor, so closing the
// engine never closes a descriptor NetworkExtension still owns. MTU 0 leaves
// the interface MTU to the network settings.
func OpenTun(fd int) (tun.Device, error) {
	dup, err := unix.Dup(fd)
	if err != nil {
		return nil, err
	}
	if err := unix.SetNonblock(dup, true); err != nil {
		unix.Close(dup)
		return nil, err
	}
	return tun.CreateTUNFromFile(os.NewFile(uintptr(dup), "utun"), 0)
}
