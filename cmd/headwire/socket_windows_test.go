package main

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// useSocket points the status client and server at a pipe of the test's own
// for its duration, outside ProtectedPrefix. The pipe keeps pipeACL, so the
// tests need an elevated console.
func useSocket(t *testing.T, timeout time.Duration) {
	t.Helper()
	oldPath, oldTimeout := socketPath, statusTimeout
	t.Cleanup(func() { socketPath, statusTimeout = oldPath, oldTimeout })
	socketPath = fmt.Sprintf(`\\.\pipe\headwire-test-%d-%s`, os.Getpid(), t.Name())
	statusTimeout = timeout
}
