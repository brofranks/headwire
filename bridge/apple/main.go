//go:build darwin

// The C ABI an Apple NetworkExtension provider links, built with
// -buildmode=c-archive by build.sh. include/headwire_bridge.h is the contract.
// Every function returns NULL or an error string the caller frees with
// HeadwireFree. Panics are contained because they would take the provider down.
package main

/*
#include <stdint.h>
#include <stdlib.h>
#include <os/log.h>

// Callback strings are allocated by the host with malloc/strdup.
typedef char *(*HWRequest)(void *, const char *, char **);
static char *hw_request(HWRequest request, void *context, const char *line, char **out) {
	return request(context, line, out);
}

static void hw_log(const char *s) {
	static os_log_t l;
	if (!l) l = os_log_create("dev.brof.headwire", "engine");
	os_log(l, "%{public}s", s);
}
*/
import "C"

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"unsafe"

	"brof.dev/headwire/internal/apple"
	"brof.dev/headwire/internal/cli"
	"brof.dev/headwire/internal/config"
	"tailscale.com/net/netmon"
)

// logf applies the CLI's LOG_LEVEL filter before os_log: the extension sets
// no LOG_LEVEL, so the engine's [v1]/[v2] lines, including magicsock's
// per-message disco traffic with peer endpoints, stay out of the unified log.
var logf = log.New(cli.LogWriter(osLog{}), "", 0).Printf

type osLog struct{}

func (osLog) Write(p []byte) (int, error) {
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

// prepare is the HeadwirePrepare* entry point of this platform, given its
// loaded configuration.
func prepare(cfg *config.Config, handle *C.int32_t, settings **C.char) error {
	h, s, err := apple.Prepare(cfg)
	if err != nil {
		return err
	}
	js, err := json.Marshal(s)
	if err != nil {
		return err
	}
	*handle, *settings = C.int32_t(h), C.CString(string(js))
	return nil
}

//export HeadwireStart
func HeadwireStart(handle, fd C.int32_t) *C.char {
	return guard(func() error {
		dev, err := apple.OpenTun(int(fd))
		if err != nil {
			return err
		}
		return apple.Start(int32(handle), dev, logf)
	})
}

//export HeadwireStatus
func HeadwireStatus(handle C.int32_t, field *C.char, out **C.char) *C.char {
	return guard(func() error {
		s, err := apple.Status(int32(handle), C.GoString(field))
		if err != nil {
			return err
		}
		*out = C.CString(s)
		return nil
	})
}

//export HeadwireNetworkChanged
func HeadwireNetworkChanged(handle C.int32_t, ifname *C.char) {
	guard(func() error {
		// NetworkExtension sets the delegate interface once, at tunnel
		// creation, so netns would keep binding to the one that went away.
		// The name is process-wide, so a prepared handle records it too.
		netmon.UpdateLastKnownDefaultRouteInterface(C.GoString(ifname))
		apple.NetworkChanged(int32(handle))
		return nil
	})
}

//export HeadwireStop
func HeadwireStop(handle C.int32_t) {
	guard(func() error { apple.Stop(int32(handle)); return nil })
}

// appProgram holds the tunnel verbs Headwire.app dispatches itself. They
// reach HeadwireCLI only for help or when malformed.
var appProgram = cli.Program{
	Usage: `  list                   profiles in /etc/headwire and their state
  up [NAME]              start /etc/headwire/NAME.conf (root-owned, mode 0600)
  down                   stop the current tunnel
  rungui                 open the menu bar item
`,
	Commands: map[string]cli.Command{
		"list":   {},
		"up":     {Args: " [NAME]"},
		"down":   {},
		"rungui": {},
	},
}

//export HeadwireCLI
func HeadwireCLI(
	argc C.int32_t,
	argv **C.char,
	request C.HWRequest,
	context unsafe.Pointer,
) C.int32_t {
	args := make([]string, argc)
	for i, arg := range unsafe.Slice(argv, argc) {
		args[i] = C.GoString(arg)
	}
	program := appProgram
	program.Request = func(line string) (string, error) {
		if request == nil {
			return "", errors.New("not connected to the running node")
		}
		input := C.CString(line)
		defer C.free(unsafe.Pointer(input))
		var output *C.char
		failure := C.hw_request(request, context, input, &output)
		defer C.free(unsafe.Pointer(output))
		if failure != nil {
			defer C.free(unsafe.Pointer(failure))
			return "", fmt.Errorf("%s", C.GoString(failure))
		}
		return C.GoString(output), nil
	}
	return C.int32_t(cli.Run(args, os.Stdin, os.Stdout, os.Stderr, program))
}

//export HeadwireFree
func HeadwireFree(p *C.char) { C.free(unsafe.Pointer(p)) }

func main() {}
