package main

import (
	"net"

	"github.com/Microsoft/go-winio"
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

// listenStatus claims the status pipe exclusively. Windows removes a pipe
// with its last handle, so there is no stale pipe to replace.
func listenStatus() (net.Listener, error) {
	return winio.ListenPipe(socketPath, &winio.PipeConfig{SecurityDescriptor: pipeACL})
}
