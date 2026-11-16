//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
	if _, err := listenStatus(); err == nil || !strings.Contains(err.Error(), "socket in use") {
		t.Fatalf("second node: %v", err)
	}
}

func TestStatusSocketUmask(t *testing.T) {
	for _, tc := range []struct {
		name    string
		wantErr bool
	}{
		{"success", false},
		{"bind failure", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useSocket(t, statusTimeout)
			if tc.wantErr {
				socketPath = filepath.Join(filepath.Dir(socketPath), strings.Repeat("s", 200))
			}
			old := syscall.Umask(0o027)
			t.Cleanup(func() { syscall.Umask(old) })
			ln, err := listenStatus()
			if ln != nil {
				defer ln.Close()
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("listenStatus: %v, want error = %v", err, tc.wantErr)
			}
			if got := syscall.Umask(0o027); got != 0o027 {
				t.Fatalf("umask = %04o, want 0027", got)
			}
		})
	}
}

func TestStatusSocketPeer(t *testing.T) {
	t.Cleanup(func() { geteuid = os.Geteuid })
	useSocket(t, statusTimeout)
	ln, err := listenStatus()
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := dialStatus()
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	t.Run("foreign peer", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root's own socket is always accepted")
		}
		geteuid = func() int { return os.Geteuid() + 1 }
		if _, err := dialStatus(); err == nil || !strings.Contains(err.Error(), "served by uid") {
			t.Fatalf("foreign peer: %v", err)
		}
	})
}
