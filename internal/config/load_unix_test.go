//go:build unix

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestLoadDirectory(t *testing.T) {
	if _, err := Load(t.TempDir(), noWarning(t)); !errors.Is(err, syscall.EISDIR) {
		t.Fatalf("directory: %v", err)
	}
}

func TestLoadMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "main.conf")
	if err := os.WriteFile(path, []byte(iface), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o600, 0o400, 0o640, 0o644, 0o666} {
		// Chmod, as WriteFile's mode is subject to the umask.
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		var warnings []string
		cfg, err := Load(path, func(m string) { warnings = append(warnings, m) })
		if err != nil || cfg.Interface.Addresses[0].String() != "100.64.0.1/32" {
			t.Fatalf("%04o: %+v, %v", mode, cfg, err)
		}
		if mode&0o077 == 0 {
			if len(warnings) != 0 {
				t.Fatalf("%04o: %q", mode, warnings)
			}
			continue
		}
		if len(warnings) != 1 || !strings.Contains(warnings[0], path) || !strings.Contains(warnings[0], "chmod 600") {
			t.Fatalf("%04o: %q", mode, warnings)
		}
	}
}

func TestLoadForeignOwner(t *testing.T) {
	t.Cleanup(func() { geteuid = os.Geteuid })
	path := filepath.Join(t.TempDir(), "main.conf")
	if err := os.WriteFile(path, []byte(iface), 0o600); err != nil {
		t.Fatal(err)
	}
	geteuid = func() int { return os.Geteuid() + 1 }
	var warnings []string
	cfg, err := Load(path, func(m string) { warnings = append(warnings, m) })
	if err != nil || cfg == nil {
		t.Fatalf("foreign owner: %+v, %v", cfg, err)
	}
	// Root-owned files are always accepted, and the test runs as root in
	// some environments.
	if os.Geteuid() != 0 && (len(warnings) != 1 || !strings.Contains(warnings[0], "owned by uid")) {
		t.Fatalf("foreign owner: %q", warnings)
	}
}

func TestLoadNameAccess(t *testing.T) {
	t.Cleanup(func() { geteuid = os.Geteuid })
	useDir(t)
	if err := os.Mkdir(Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(Dir, "main.conf")
	if err := os.WriteFile(path, []byte(iface), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o640, 0o644} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadName("main"); err == nil || !strings.Contains(err.Error(), "chmod 600") {
			t.Fatalf("file mode %04o: %v", mode, err)
		}
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o775, 0o777} {
		if err := os.Chmod(Dir, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadName("main"); err == nil || !strings.Contains(err.Error(), Dir+": must be a directory") {
			t.Fatalf("directory mode %04o: %v", mode, err)
		}
	}
	if err := os.Chmod(Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Root-owned files and directories are always accepted, and the test
	// runs as root in some environments.
	if os.Geteuid() == 0 {
		return
	}
	geteuid = func() int { return os.Geteuid() + 1 }
	if _, err := LoadName("main"); err == nil || !strings.Contains(err.Error(), "must be a directory") {
		t.Fatalf("foreign directory owner: %v", err)
	}
}
