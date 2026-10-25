//go:build unix

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWorldReadable covers the two warnings about a file others can read:
// genkey and genpsk writing to one, and check reading one. The mode rules
// themselves are tested with config.Load.
func TestWorldReadable(t *testing.T) {
	var out, errOut bytes.Buffer
	for _, command := range []string{"genkey", "genpsk"} {
		file, err := os.OpenFile(filepath.Join(t.TempDir(), "key"), os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		errOut.Reset()
		if code := Run([]string{command}, strings.NewReader(""), file, &errOut, Program{}); code != 0 || !strings.Contains(errOut.String(), "group or other can access") {
			t.Fatalf("%s to file: code=%d, err=%s", command, code, &errOut)
		}
	}
	path := writeMain(t)
	// Chmod, as WriteFile's mode is subject to the umask.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	errOut.Reset()
	if code := realMain([]string{"check", path}, strings.NewReader(""), &out, &errOut); code != 0 || !strings.HasPrefix(errOut.String(), "Warning: "+path) || !strings.Contains(errOut.String(), "chmod 600") {
		t.Fatalf("code=%d, err=%s", code, &errOut)
	}
}
