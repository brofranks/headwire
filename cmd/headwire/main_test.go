package main

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"brof.dev/headwire/internal/config"
	"brof.dev/headwire/internal/engine"
)

type forbiddenInput struct{ t *testing.T }

func (r forbiddenInput) Read([]byte) (int, error) {
	r.t.Fatal("unexpected stdin read")
	return 0, io.EOF
}

func TestCommandArguments(t *testing.T) {
	for _, cmd := range []string{"genkey", "genpsk", "pubkey", "discokey", "version", "-v", "--version", "help", "-h", "--help"} {
		t.Run(cmd, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := realMain([]string{cmd, "extra"}, forbiddenInput{t}, &out, &errOut); code != 2 || out.Len() != 0 || !strings.Contains(errOut.String(), "usage:") {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, &out, &errOut)
			}
		})
	}
	for _, cmd := range []string{"run", "check", "netcheck"} {
		var out, errOut bytes.Buffer
		if code := realMain([]string{cmd, "missing", "junk"}, forbiddenInput{t}, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "usage: headwire "+cmd) {
			t.Fatalf("%s: code=%d stdout=%q stderr=%q", cmd, code, &out, &errOut)
		}
	}
}

// TestCommandHelp covers run, the binary's own command. internal/cli tests
// the shared ones.
func TestCommandHelp(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := realMain([]string{"run", "--help"}, forbiddenInput{t}, &out, &errOut); code != 0 || !strings.Contains(out.String(), "usage: headwire run") || errOut.Len() != 0 {
		t.Fatalf("run --help: code=%d stdout=%q stderr=%q", code, &out, &errOut)
	}
}

func TestLocalDiagnostics(t *testing.T) {
	t.Setenv("LOG_LEVEL", "silent")
	for _, args := range [][]string{{"show", "not-a-field"}, {"run", filepath.Join(t.TempDir(), "missing")}} {
		var out, errOut bytes.Buffer
		if code := realMain(args, forbiddenInput{t}, &out, &errOut); code != 2 || errOut.Len() == 0 || out.Len() != 0 {
			t.Fatalf("%v: code=%d stdout=%q stderr=%q", args, code, &out, &errOut)
		}
		if strings.Contains(errOut.String(), "connect") {
			t.Fatal("invalid field contacted daemon")
		}
	}
}

// useSocket points the status client and server at a socket under a temporary
// directory for the test's duration.
func useSocket(t *testing.T, timeout time.Duration) {
	t.Helper()
	oldPath, oldTimeout := socketPath, statusTimeout
	t.Cleanup(func() { socketPath, statusTimeout = oldPath, oldTimeout })
	socketPath = filepath.Join(t.TempDir(), "run", "s.sock")
	statusTimeout = timeout
}

func TestStatusSocket(t *testing.T) {
	useSocket(t, 200*time.Millisecond)

	ln, err := listenStatus()
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveStatus(ln, func(field string) (string, error) {
		if field == "ping 10.0.0.9" {
			return "", errors.New("10.0.0.9 is not in AllowedIPs")
		}
		return "field=" + field + "\n", nil
	})
	if _, err := listenStatus(); err == nil || !strings.Contains(err.Error(), "socket in use") {
		t.Fatalf("second node: %v", err)
	}
	for path, want := range map[string]os.FileMode{socketPath: 0o600, filepath.Dir(socketPath): 0o700} {
		fi, err := os.Stat(path)
		if err != nil || fi.Mode().Perm() != want {
			t.Fatalf("%s: mode = %v, %v; want %04o", path, fi.Mode().Perm(), err, want)
		}
	}
	request := func(t *testing.T) {
		t.Helper()
		var out, errOut bytes.Buffer
		if code := realMain([]string{"show", "peers"}, forbiddenInput{t}, &out, &errOut); code != 0 || out.String() != "field=peers\n" {
			t.Fatalf("code=%d, out=%q, err=%q", code, &out, &errOut)
		}
	}
	request(t)
	var pong, pingErr bytes.Buffer
	if code := realMain([]string{"ping", "10.0.0.2"}, forbiddenInput{t}, &pong, &pingErr); code != 0 || pong.String() != "field=ping 10.0.0.2\n" {
		t.Fatalf("ping: code=%d, out=%q, err=%q", code, &pong, &pingErr)
	}
	pong.Reset()
	pingErr.Reset()
	if code := realMain([]string{"ping", "10.0.0.9"}, forbiddenInput{t}, &pong, &pingErr); code != 1 || pong.Len() != 0 || !strings.Contains(pingErr.String(), "10.0.0.9 is not in AllowedIPs") {
		t.Fatalf("refused ping: code=%d, out=%q, err=%q", code, &pong, &pingErr)
	}

	// A client that never writes is cut off, and the service carries on.
	silent, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	silent.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadAll(silent); err != nil {
		t.Fatalf("silent client was not closed by the server: %v", err)
	}
	request(t)

	// So is one that never ends its line.
	long, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer long.Close()
	long.Write(bytes.Repeat([]byte{'x'}, 4096))
	request(t)
}

func TestReloadOutcomes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "main.conf")
	const conf = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=\nAddress = 100.64.0.1/32\n"
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		err   error
		fatal bool
	}{
		{"applied", nil, false},
		{"rejected", errors.New("restart required"), false},
		{"fatal", &engine.ReloadApplyError{Err: errors.New("router failure")}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			err := reloadNode(path, func(*config.Config) error { return tc.err }, log.New(&output, "", 0))
			if (err != nil) != tc.fatal || !strings.Contains(output.String(), "reload "+tc.name) {
				t.Fatalf("err=%v, log=%s", err, &output)
			}
		})
	}
	if err := os.WriteFile(path, []byte("invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reloadNode(path, func(*config.Config) error { t.Fatal("applied invalid config"); return nil }, log.New(io.Discard, "", 0)); err != nil {
		t.Fatal(err)
	}
}

func TestShowDeadline(t *testing.T) {
	useSocket(t, 50*time.Millisecond)
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); done <- c }()
	var out, errOut bytes.Buffer
	if code := realMain([]string{"show", "peers"}, forbiddenInput{t}, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "timeout") {
		t.Fatalf("code=%d: %s", code, &errOut)
	}
	if c := <-done; c != nil {
		c.Close()
	}
}

func TestIPCommand(t *testing.T) {
	// The argument matrix lives in internal/cli. This covers the Unix
	// transport.
	useSocket(t, statusTimeout)
	var out, errOut bytes.Buffer
	if code := realMain([]string{"ip"}, forbiddenInput{t}, &out, &errOut); code != 1 || out.Len() != 0 || errOut.Len() == 0 {
		t.Fatalf("disconnected: code=%d stdout=%q stderr=%q", code, &out, &errOut)
	}
	ln, err := listenStatus()
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveStatus(ln, func(request string) (string, error) { return request + "\n", nil })
	out.Reset()
	errOut.Reset()
	if code := realMain([]string{"ip", "-4"}, forbiddenInput{t}, &out, &errOut); code != 0 || out.String() != "ip -4\n" || errOut.Len() != 0 {
		t.Fatalf("ip -4: code=%d stdout=%q stderr=%q", code, &out, &errOut)
	}
}
