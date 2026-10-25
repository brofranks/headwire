//go:build unix

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// useSocket points the status client and server at a socket under a temporary
// directory for the test's duration.
func useSocket(t *testing.T, timeout time.Duration) {
	t.Helper()
	oldPath, oldTimeout := socketPath, statusTimeout
	t.Cleanup(func() { socketPath, statusTimeout = oldPath, oldTimeout })
	socketPath = filepath.Join(t.TempDir(), "run", "s.sock")
	statusTimeout = timeout
}

func TestStatusSocketMode(t *testing.T) {
	useSocket(t, statusTimeout)
	ln, err := listenStatus()
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	for path, want := range map[string]os.FileMode{socketPath: 0o600, filepath.Dir(socketPath): 0o700} {
		fi, err := os.Stat(path)
		if err != nil || fi.Mode().Perm() != want {
			t.Fatalf("%s: mode = %v, %v; want %04o", path, fi.Mode().Perm(), err, want)
		}
	}
}
