package provider

import (
	"sync/atomic"

	"tailscale.com/net/netmon"
)

// interfaces is the list the host app last pushed. Without one netmon sees no
// network at all and closes the relay connection, so the app pushes before
// HeadwireStart and again on every network change.
var interfaces atomic.Pointer[[]netmon.Interface]

func init() {
	netmon.RegisterInterfaceGetter(func() ([]netmon.Interface, error) {
		if ifs := interfaces.Load(); ifs != nil {
			return *ifs, nil
		}
		return []netmon.Interface{}, nil
	})
}

// UpdateInterfaces replaces the cached list. A malformed list leaves the
// current one in place.
func UpdateInterfaces(js []byte) error {
	ifs, err := parseInterfaces(js)
	if err != nil {
		return err
	}
	interfaces.Store(&ifs)
	return nil
}

// ClearInterfaces forgets the list when the session that pushed it stops.
func ClearInterfaces() { interfaces.Store(nil) }
