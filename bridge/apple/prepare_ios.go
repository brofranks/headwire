//go:build ios

package main

/*
#include <stdint.h>
*/
import "C"

import "brof.dev/headwire/internal/config"

// HeadwirePrepareConfig takes the whole configuration text, which the
// provider reads from the keychain: iOS has no /etc.
//
//export HeadwirePrepareConfig
func HeadwirePrepareConfig(text *C.char, handle *C.int32_t, settings **C.char) *C.char {
	return guard(func() error {
		cfg, err := config.Parse([]byte(C.GoString(text)))
		if err != nil {
			return err
		}
		return prepare(cfg, handle, settings)
	})
}
