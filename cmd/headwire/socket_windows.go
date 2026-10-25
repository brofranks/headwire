package main

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"

	"github.com/tailscale/go-winio"
)

// socketPath is the named pipe a running node serves its status on. Only
// an administrator can create a pipe under ProtectedPrefix, so a client that
// connects is talking to an elevated node.
var socketPath = `\\.\pipe\ProtectedPrefix\Administrators\Headwire\headwire`

// pipeACL grants the pipe to SYSTEM and Administrators alone.
const pipeACL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"

// dialStatus connects to the running node's status pipe.
func dialStatus() (net.Conn, error) {
	return winio.DialPipe(socketPath, &statusTimeout)
}

// listenStatus claims the status pipe. Any pipe at the path belongs to
// another node, including one that is busy or refuses this user, so a single
// open that finds anything but no pipe reports it in use. Windows removes a
// pipe with its last handle, so there is no stale pipe to replace.
func listenStatus() (net.Listener, error) {
	f, err := os.OpenFile(socketPath, os.O_RDWR, 0)
	if err == nil {
		f.Close()
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: socket in use", socketPath)
	}
	return winio.ListenPipe(socketPath, &winio.PipeConfig{SecurityDescriptor: pipeACL})
}
