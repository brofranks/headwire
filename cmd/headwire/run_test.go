package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"brof.dev/headwire/internal/config"
	"brof.dev/headwire/internal/engine"
)

type fakeNode struct{ reloads []error }

func (n *fakeNode) Reload(*config.Config) error {
	err := n.reloads[0]
	n.reloads = n.reloads[1:]
	return err
}
func (*fakeNode) Status(string) (string, error) { return "", nil }
func (*fakeNode) Close()                        {}

// logLines hands each log line to the test, so it signals only once runNode
// has registered for the signal.
type logLines struct {
	mu  sync.Mutex
	buf bytes.Buffer
	c   chan string
}

func (l *logLines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf.Write(p)
	l.c <- string(p)
	return len(p), nil
}

func (l *logLines) await(want string) {
	for line := range l.c {
		if strings.Contains(line, want) {
			return
		}
	}
}

// TestRunNode drives the run loop with a fake engine: a real one needs root
// and a TUN.
func TestRunNode(t *testing.T) {
	t.Setenv("LOG_LEVEL", "")
	useSocket(t, statusTimeout)
	oldStart := startNode
	t.Cleanup(func() { startNode = oldStart })
	path := filepath.Join(t.TempDir(), "main.conf")
	const conf = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=\nAddress = 100.64.0.1/32\n"
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(n node, startErr error, signals ...syscall.Signal) (int, string) {
		startNode = func(*config.Config, func(string, ...any)) (node, error) { return n, startErr }
		out := &logLines{c: make(chan string, 64)}
		done := make(chan int)
		go func() { done <- runNode([]string{path}, out, out, nil) }()
		if len(signals) > 0 {
			out.await("started")
		}
		for _, sig := range signals {
			syscall.Kill(os.Getpid(), sig)
			if sig == syscall.SIGHUP {
				out.await("reload")
			}
		}
		code := <-done
		out.mu.Lock()
		defer out.mu.Unlock()
		return code, out.buf.String()
	}

	if code, log := run(nil, errors.New("no tun")); code != 1 || !strings.Contains(log, "no tun") {
		t.Fatalf("start failure: %d %s", code, log)
	}
	fatal := &engine.ReloadApplyError{Err: errors.New("router failure")}
	if code, log := run(&fakeNode{reloads: []error{nil, fatal}}, nil, syscall.SIGHUP, syscall.SIGHUP); code != 1 ||
		!strings.Contains(log, "reload applied") || !strings.Contains(log, "reload fatal") {
		t.Fatalf("reload: %d %s", code, log)
	}
	if code, _ := run(&fakeNode{}, nil, syscall.SIGTERM); code != 0 {
		t.Fatalf("SIGTERM: %d", code)
	}
	// A socket another node answers refuses the run before the engine starts.
	ln, err := listenStatus()
	if err != nil {
		t.Fatal(err)
	}
	startNode = func(*config.Config, func(string, ...any)) (node, error) {
		t.Error("engine started with the socket in use")
		return &fakeNode{}, nil
	}
	out := &logLines{c: make(chan string, 64)}
	if code := runNode([]string{path}, out, out, nil); code != 1 || !strings.Contains(out.buf.String(), "socket in use") {
		t.Fatalf("socket in use: %d %s", code, &out.buf)
	}
	ln.Close()
	socketPath = filepath.Join(path, "s.sock") // a directory under a file
	if code, _ := run(&fakeNode{}, nil); code != 1 {
		t.Fatalf("status socket failure: %d", code)
	}
}
