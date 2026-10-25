package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

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
// provider loads it as root for an unprivileged app, so Dir must pass
// checkDir and Load's warnings are errors.
func LoadName(name string) (*Config, error) {
	if !validName.MatchString(name) {
		return nil, fmt.Errorf("invalid configuration name %q", name)
	}
	fi, err := os.Stat(Dir)
	if err != nil {
		return nil, err
	}
	if err := checkDir(fi); err != nil {
		return nil, err
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

// Load parses the file at path. It reports through warn a regular file that
// other users can access or that someone other than root or the effective
// user owns, where the OS exposes that.
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
	warnAccess(path, fi, warn)
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
