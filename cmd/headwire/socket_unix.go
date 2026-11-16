//go:build unix

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	"github.com/tailscale/peercred"
)

// socketPath is where a running node serves its status to `show`.
var socketPath = func() string {
	if runtime.GOOS == "darwin" {
		return "/var/run/headwire/headwire.sock"
	}
	return "/run/headwire/headwire.sock"
}()

// geteuid is replaced by tests: only root can serve as another user.
var geteuid = os.Geteuid

// dialStatus connects to the running node's status socket. The peer must run
// as root or the current user, so no other user's process answers for the
// node, whoever controls the socket's path.
func dialStatus() (net.Conn, error) {
	c, err := net.DialTimeout("unix", socketPath, statusTimeout)
	if err != nil {
		return nil, err
	}
	creds, err := peercred.Get(c)
	if err != nil {
		c.Close()
		return nil, err
	}
	if uid, _ := creds.UserID(); uid != "0" && uid != strconv.Itoa(geteuid()) {
		c.Close()
		return nil, fmt.Errorf("%s: served by uid %s, not root or the current user", socketPath, uid)
	}
	return c, nil
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
	// The umask makes the socket private from creation. A chmod by path
	// afterwards would follow a symlink put in its place.
	old := syscall.Umask(0o177)
	ln, err := net.Listen("unix", socketPath)
	syscall.Umask(old)
	return ln, err
}
