//go:build darwin && !ios

package main

/*
#include <stdint.h>
*/
import "C"

import "brof.dev/headwire/internal/config"

// HeadwirePrepareProfile loads the root-owned profile the name selects, since
// the provider runs as root on behalf of an unprivileged app.
//
//export HeadwirePrepareProfile
func HeadwirePrepareProfile(name *C.char, handle *C.int32_t, settings **C.char) *C.char {
	return guard(func() error {
		cfg, err := config.LoadName(C.GoString(name))
		if err != nil {
			return err
		}
		return prepare(cfg, handle, settings)
	})
}
