// The C ABI an Android VpnService links, built with -buildmode=c-shared by
// build.sh. include/headwire_android.h is the contract. Every function returns
// NULL or an error string the caller frees with HeadwireFree. Panics are
// contained because they would take the app down.
package main

/*
#cgo LDFLAGS: -llog
#include <stdint.h>
#include <stdlib.h>
#include <android/log.h>

typedef int32_t (*HWProtect)(void *, int32_t);
static int32_t hw_protect(HWProtect protect, void *context, int32_t fd) {
	return protect(context, fd);
}

static void hw_log(const char *s) {
	__android_log_write(ANDROID_LOG_INFO, "headwire", s);
}
*/
import "C"

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"unsafe"

	"brof.dev/headwire/internal/cli"
	"brof.dev/headwire/internal/config"
	"brof.dev/headwire/internal/provider"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
)

// logf applies the CLI's LOG_LEVEL filter before logcat: the app sets no
// LOG_LEVEL, so the engine's [v1]/[v2] lines, including magicsock's
// per-message disco traffic with peer endpoints, stay out of the log.
var logf = log.New(cli.LogWriter(logcat{}), "", 0).Printf

type logcat struct{}

func (logcat) Write(p []byte) (int, error) {
	s := C.CString(string(bytes.TrimSuffix(p, []byte("\n"))))
	defer C.free(unsafe.Pointer(s))
	C.hw_log(s)
	return len(p), nil
}

// guard turns f's error or panic into the ABI's error string.
func guard(f func() error) (out *C.char) {
	defer func() {
		if r := recover(); r != nil {
			out = C.CString(fmt.Sprint("panic: ", r))
		}
	}()
	if err := f(); err != nil {
		return C.CString(err.Error())
	}
	return nil
}

// hostProtect is the session's VpnService.protect, set while a handle holds
// the session. The read lock spans the call into the host, so HeadwireStop
// returns only after every such call has finished.
var hostProtect struct {
	sync.RWMutex
	f       C.HWProtect
	context unsafe.Pointer
}

func init() {
	netns.SetAndroidProtectFunc(func(fd int) error {
		hostProtect.RLock()
		defer hostProtect.RUnlock()
		// An unprotected socket would loop back into the tunnel.
		if hostProtect.f == nil {
			return errors.New("no session to protect the socket")
		}
		if C.hw_protect(hostProtect.f, hostProtect.context, C.int32_t(fd)) == 0 {
			return errors.New("VpnService.protect refused the socket")
		}
		return nil
	})
}

func setProtect(f C.HWProtect, context unsafe.Pointer) {
	hostProtect.Lock()
	defer hostProtect.Unlock()
	hostProtect.f, hostProtect.context = f, context
}

//export HeadwirePrepareConfig
func HeadwirePrepareConfig(text *C.char, handle *C.int32_t, settings **C.char) *C.char {
	return guard(func() error {
		cfg, err := config.Parse([]byte(C.GoString(text)))
		if err != nil {
			return err
		}
		// The header requires this call before establish(), so the
		// lookups still use the underlay's DNS.
		if err := provider.Resolve(cfg); err != nil {
			return err
		}
		h, s, err := provider.Prepare(cfg)
		if err != nil {
			return err
		}
		js, err := json.Marshal(s)
		if err != nil {
			return err
		}
		*handle, *settings = C.int32_t(h), C.CString(string(js))
		return nil
	})
}

//export HeadwireStart
func HeadwireStart(handle, fd C.int32_t, protect C.HWProtect, context unsafe.Pointer) *C.char {
	return guard(func() error {
		dev, err := provider.OpenTun(int(fd))
		if err != nil {
			return err
		}
		if protect == nil {
			dev.Close()
			return errors.New("protect callback is required")
		}
		// The callback stays until Stop, as a failed start keeps the
		// handle.
		return provider.Start(int32(handle), dev, logf, func() { setProtect(protect, context) })
	})
}

//export HeadwireStatus
func HeadwireStatus(handle C.int32_t, field *C.char, out **C.char) *C.char {
	return guard(func() error {
		s, err := provider.Status(int32(handle), C.GoString(field))
		if err != nil {
			return err
		}
		*out = C.CString(s)
		return nil
	})
}

//export HeadwireNetworkChanged
func HeadwireNetworkChanged(handle C.int32_t, ifname, interfaces *C.char) *C.char {
	return guard(func() error {
		// Both caches are process-wide, so a prepared handle records them
		// too: the engine reads them when Start binds its first socket.
		return provider.NetworkChanged(int32(handle), func() error {
			if err := provider.UpdateInterfaces([]byte(C.GoString(interfaces))); err != nil {
				return err
			}
			netmon.UpdateLastKnownDefaultRouteInterface(C.GoString(ifname))
			return nil
		})
	})
}

//export HeadwireStop
func HeadwireStop(handle C.int32_t) {
	guard(func() error {
		// A late stop from an earlier service instance must not disarm the
		// session that replaced it.
		provider.Stop(int32(handle), func() {
			setProtect(nil, nil)
			provider.ClearInterfaces()
		})
		return nil
	})
}

//export HeadwireFree
func HeadwireFree(p *C.char) { C.free(unsafe.Pointer(p)) }

func main() {}
