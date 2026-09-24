package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

// Dir holds NAME.conf files.
var Dir = "/etc/headwire"

var validName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Path resolves the NAME | FILE argument: a bare NAME selects Dir/NAME.conf
// and anything else is a file path.
func Path(arg string) string {
	if validName.MatchString(arg) {
		return filepath.Join(Dir, arg+".conf")
	}
	return arg
}

// LoadName loads the file a bare NAME selects and refuses a path. The Apple
// provider loads it as root for an unprivileged app, so Dir must be owned by
// root or the effective user and writable by no one else, and Load's warnings
// are errors.
func LoadName(name string) (*Config, error) {
	if !validName.MatchString(name) {
		return nil, fmt.Errorf("invalid configuration name %q", name)
	}
	fi, err := os.Stat(Dir)
	if err != nil {
		return nil, err
	}
	if uid := fi.Sys().(*syscall.Stat_t).Uid; !fi.IsDir() || fi.Mode().Perm()&0o022 != 0 ||
		uid != 0 && int(uid) != geteuid() {
		return nil, fmt.Errorf("%s: must be a directory owned by root or the "+
			"current user and not writable by group or other", Dir)
	}
	var problems []string
	cfg, err := Load(Path(name), func(m string) { problems = append(problems, m) })
	if err != nil {
		return nil, err
	}
	if len(problems) > 0 {
		return nil, errors.New(strings.Join(problems, "; "))
	}
	return cfg, nil
}

// Private reports a mode fit for key material: nothing for group or other.
func Private(m os.FileMode) bool { return m.Perm()&0o077 == 0 }

// geteuid is replaced by tests: only root can create a file another user owns.
var geteuid = os.Geteuid

// Load parses the file at path. It reports through warn a regular file that
// other users can access or that someone other than root or the effective
// user owns.
func Load(path string, warn func(string)) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Mode().IsRegular() && !Private(fi.Mode()) {
		warn(fmt.Sprintf("%s: mode %04o lets other users read the file, so "+
			"run chmod 600 on it", path, fi.Mode().Perm()))
	}
	if uid := fi.Sys().(*syscall.Stat_t).Uid; fi.Mode().IsRegular() && uid != 0 &&
		int(uid) != geteuid() {
		warn(fmt.Sprintf("%s: owned by uid %d, so chown it to root or to the "+
			"user running headwire", path, uid))
	}
	src, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	cfg, err := Parse(src)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}
