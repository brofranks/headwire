//go:build unix

package config

import (
	"fmt"
	"os"
	"syscall"
)

// Dir holds NAME.conf files.
var Dir = "/etc/headwire"

// Private reports a mode fit for key material: nothing for group or other.
func Private(m os.FileMode) bool { return m.Perm()&0o077 == 0 }

// geteuid is replaced by tests: only root can create a file another user owns.
var geteuid = os.Geteuid

// checkDir requires Dir to be owned by root or the effective user and
// writable by no one else.
func checkDir(fi os.FileInfo) error {
	if uid := fi.Sys().(*syscall.Stat_t).Uid; !fi.IsDir() || fi.Mode().Perm()&0o022 != 0 ||
		uid != 0 && int(uid) != geteuid() {
		return fmt.Errorf("%s: must be a directory owned by root or the "+
			"current user and not writable by group or other", Dir)
	}
	return nil
}

// warnAccess emits Load's warnings for a regular file.
func warnAccess(path string, fi os.FileInfo, warn func(string)) {
	if !fi.Mode().IsRegular() {
		return
	}
	if !Private(fi.Mode()) {
		warn(fmt.Sprintf("%s: mode %04o lets other users read the file, so "+
			"run chmod 600 on it", path, fi.Mode().Perm()))
	}
	if uid := fi.Sys().(*syscall.Stat_t).Uid; uid != 0 && int(uid) != geteuid() {
		warn(fmt.Sprintf("%s: owned by uid %d, so chown it to root or to the "+
			"user running headwire", path, uid))
	}
}
