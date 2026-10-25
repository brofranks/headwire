package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// noWarning fails the test on any loader warning.
func noWarning(t *testing.T) func(string) {
	t.Helper()
	return func(m string) {
		t.Helper()
		t.Errorf("unexpected warning: %s", m)
	}
}

// useDir points Dir at a path in a fresh temporary directory, without
// creating it.
func useDir(t *testing.T) {
	t.Helper()
	old := Dir
	t.Cleanup(func() { Dir = old })
	Dir = filepath.Join(t.TempDir(), "headwire")
}

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "main.conf")
	if _, err := Load(path, noWarning(t)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	if err := os.WriteFile(path, []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, noWarning(t)); err == nil || !strings.HasPrefix(err.Error(), path+": line 1") {
		t.Fatalf("invalid content: %v", err)
	}
	if err := os.WriteFile(path, []byte(iface), 0o600); err != nil {
		t.Fatal(err)
	}
	if cfg, err := Load(path, noWarning(t)); err != nil || cfg.Interface.Addresses[0].String() != "100.64.0.1/32" {
		t.Fatalf("private file: %+v, %v", cfg, err)
	}
}

func TestPath(t *testing.T) {
	for arg, want := range map[string]string{
		"main":          filepath.Join(Dir, "main.conf"),
		"work-2_a":      filepath.Join(Dir, "work-2_a.conf"),
		"main.conf":     "main.conf",
		"./main":        "./main",
		"/tmp/x.conf":   "/tmp/x.conf",
		"../etc/passwd": "../etc/passwd",
	} {
		if got := Path(arg); got != want {
			t.Errorf("Path(%q) = %q, want %q", arg, got, want)
		}
	}
}

func TestLoadName(t *testing.T) {
	useDir(t)
	if _, err := LoadName("../x"); err == nil || !strings.Contains(err.Error(), "invalid configuration name") {
		t.Fatalf("path as name: %v", err)
	}
	if _, err := LoadName("main"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing directory: %v", err)
	}
	if err := os.WriteFile(Dir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadName("main"); err == nil || !strings.Contains(err.Error(), Dir+": must be a directory") {
		t.Fatalf("file as directory: %v", err)
	}
	if err := os.Remove(Dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(Dir, "main.conf"), []byte(iface), 0o600); err != nil {
		t.Fatal(err)
	}
	if cfg, err := LoadName("main"); err != nil || cfg.Interface.Addresses[0].String() != "100.64.0.1/32" {
		t.Fatalf("private file in private directory: %+v, %v", cfg, err)
	}
}
