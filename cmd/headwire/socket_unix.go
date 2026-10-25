//go:build unix

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
)

// socketPath is where a running node serves its status to `show`.
var socketPath = func() string {
	if runtime.GOOS == "darwin" {
		return "/var/run/headwire/headwire.sock"
	}
	return "/run/headwire/headwire.sock"
}()

// dialStatus connects to the running node's status socket.
func dialStatus() (net.Conn, error) {
	return net.DialTimeout("unix", socketPath, statusTimeout)
}

// listenStatus claims the status socket. A socket something still answers
// on belongs to another node, and a stale one is replaced. The directory and
// socket are private to the daemon's user.
func listenStatus() (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return nil, err
	}
	if c, err := net.Dial("unix", socketPath); err == nil {
		c.Close()
		return nil, fmt.Errorf("%s: socket in use", socketPath)
	}
	os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}
