package cli

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	"brof.dev/headwire/internal/config"
)

func realMain(args []string, stdin *strings.Reader, stdout, stderr *bytes.Buffer) int {
	return Run(args, stdin, stdout, stderr, Program{})
}

func TestPubkeyDecodedLength(t *testing.T) {
	for _, size := range []int{31, 32, 33} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			encoded := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, size))
			var out, errOut bytes.Buffer
			code := realMain([]string{"pubkey"}, strings.NewReader(encoded), &out, &errOut)
			if size == 32 {
				if code != 0 || len(out.String()) != 45 || !strings.HasSuffix(out.String(), "=\n") {
					t.Fatalf("code=%d, out=%s, err=%s", code, &out, &errOut)
				}
				return
			}
			if code != 2 || out.Len() != 0 || !strings.Contains(errOut.String(), "32 bytes") {
				t.Fatalf("code=%d, out=%s, err=%s", code, &out, &errOut)
			}
		})
	}
}

// TestGenerateKeys covers genkey and genpsk: each prints one fresh decodable
// key, warns when stdout is a file others can read, and takes no arguments.
func TestGenerateKeys(t *testing.T) {
	for _, command := range []string{"genkey", "genpsk"} {
		var first, second, errOut bytes.Buffer
		if realMain([]string{command}, strings.NewReader(""), &first, &errOut) != 0 || realMain([]string{command}, strings.NewReader(""), &second, &errOut) != 0 {
			t.Fatalf("%s: %s", command, &errOut)
		}
		if _, err := config.DecodeKey(strings.TrimSpace(first.String())); err != nil || first.String() == second.String() {
			t.Fatalf("%s: %q, %q: %v", command, &first, &second, err)
		}
		if code := realMain([]string{command, "extra"}, strings.NewReader(""), &first, &errOut); code != 2 || !strings.Contains(errOut.String(), "usage: headwire "+command) {
			t.Fatalf("%s extra: code=%d, err=%s", command, code, &errOut)
		}

		file, err := os.OpenFile(filepath.Join(t.TempDir(), "key"), os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		errOut.Reset()
		if code := Run([]string{command}, strings.NewReader(""), file, &errOut, Program{}); code != 0 || !strings.Contains(errOut.String(), "group or other can access") {
			t.Fatalf("%s to file: code=%d, err=%s", command, code, &errOut)
		}
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		defer w.Close()
		errOut.Reset()
		if code := Run([]string{command}, strings.NewReader(""), w, &errOut, Program{}); code != 0 || errOut.Len() != 0 {
			t.Fatalf("%s to pipe: code=%d, err=%s", command, code, &errOut)
		}
	}
}

func TestPublicKeyCommands(t *testing.T) {
	// Each input is a private key, each want the public key derived from it.
	for _, tc := range []struct{ command, input, want string }{
		// The all-zero key, which X25519 clamps into a valid scalar.
		{"pubkey", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q="},
		// The bytes 0x00 through 0x1f, giving the standard X25519 public key.
		{"pubkey", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", "j0DFrbaPJWJK5bIU6nZ6bslNgp09e14a0bpvPiE4KF8="},
		// The same key's discovery public key.
		{"discokey", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", "phNrDsbm+Rt4arIT/+oCphNKurLkk7BhQHUCkbjqsGM="},
	} {
		var out, errOut bytes.Buffer
		if code := realMain([]string{tc.command}, strings.NewReader(tc.input+"\n"), &out, &errOut); code != 0 || out.String() != tc.want+"\n" || errOut.Len() != 0 {
			t.Fatalf("%s: code=%d stdout=%q stderr=%q", tc.command, code, &out, &errOut)
		}
	}
	for _, input := range []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="} {
		var out, errOut bytes.Buffer
		if code := realMain([]string{"discokey"}, strings.NewReader(input), &out, &errOut); code != 0 || len(out.String()) != 45 || strings.Contains(out.String(), "DiscoKey") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, &out, &errOut)
		}
		if _, err := config.DecodeKey(strings.TrimSpace(out.String())); err != nil {
			t.Fatal(err)
		}
	}
	var out, errOut bytes.Buffer
	if code := Run([]string{"pubkey"}, iotest.ErrReader(errors.New("broken stdin")), &out, &errOut, Program{}); code != 2 || out.Len() != 0 || !strings.Contains(errOut.String(), "broken stdin") {
		t.Fatalf("unreadable stdin: code=%d stdout=%q stderr=%q", code, &out, &errOut)
	}
}

func TestVersion(t *testing.T) {
	original := version
	version = "v1.2.3"
	t.Cleanup(func() { version = original })
	for _, arg := range []string{"version", "-v", "--version"} {
		var out, errOut bytes.Buffer
		if code := realMain([]string{arg}, strings.NewReader(""), &out, &errOut); code != 0 || out.String() != "headwire v1.2.3\n" || errOut.Len() != 0 {
			t.Fatalf("%s: stdout=%q, stderr=%q, exit=%d", arg, &out, &errOut, code)
		}
	}
}

// TestReadConfigPermissions shows check selecting a NAME or FILE and
// surfacing config.Load's refusal. The mode rules themselves are tested
// with config.Load.
func TestReadConfigPermissions(t *testing.T) {
	t.Cleanup(func() { config.Dir = "/etc/headwire" })
	config.Dir = t.TempDir()
	path := filepath.Join(config.Dir, "main.conf")
	if err := os.WriteFile(path, []byte("[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=\nAddress = 100.64.0.1/32\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	for _, args := range [][]string{{"check"}, {"check", "main"}, {"check", path}} {
		if code := realMain(args, strings.NewReader(""), &out, &errOut); code != 0 {
			t.Fatalf("%v: code=%d, err=%s", args, code, &errOut)
		}
	}
	if code := realMain([]string{"check", "other"}, strings.NewReader(""), &out, &errOut); code != 2 || !strings.Contains(errOut.String(), filepath.Join(config.Dir, "other.conf")) {
		t.Fatalf("other: code=%d, err=%s", code, &errOut)
	}
	// Chmod, as WriteFile's mode is subject to the umask.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	errOut.Reset()
	if code := realMain([]string{"check", path}, strings.NewReader(""), &out, &errOut); code != 0 || !strings.HasPrefix(errOut.String(), "Warning: "+path) || !strings.Contains(errOut.String(), "chmod 600") {
		t.Fatalf("code=%d, err=%s", code, &errOut)
	}
}

func TestProgramCommands(t *testing.T) {
	p := Program{Usage: "  up [NAME]\n", Commands: map[string]Command{
		"up": {Args: " [NAME]"},
		"echo": {Run: func(args []string, stdout, _ io.Writer, _ func(io.Writer)) int {
			fmt.Fprintln(stdout, args)
			return 7
		}},
	}}
	for _, tc := range []struct {
		args        []string
		code        int
		out, errOut string
	}{
		{[]string{"help"}, 0, "  version                print the build version\n  up [NAME]\n", ""},
		{[]string{"unknown-command"}, 2, "", "unknown command"},
		{[]string{"up", "--help"}, 0, "usage: headwire up [NAME]\n", ""},
		// The program dispatches up itself, so it arrives only when malformed.
		{[]string{"up"}, 2, "", "usage: headwire up [NAME]\n"},
		{[]string{"echo", "a", "b"}, 7, "[a b]\n", ""},
		{[]string{"down"}, 2, "", `unknown command "down"`},
	} {
		var out, errOut bytes.Buffer
		if code := Run(tc.args, strings.NewReader(""), &out, &errOut, p); code != tc.code || !strings.Contains(out.String(), tc.out) || !strings.Contains(errOut.String(), tc.errOut) || (tc.out == "") != (out.Len() == 0) {
			t.Errorf("%v: code=%d stdout=%q stderr=%q", tc.args, code, &out, &errOut)
		}
	}
}

// TestConfigHelp checks that a command's help is its usage line alone, and that
// the general usage is the one place the NAME rule and its default are stated.
func TestConfigHelp(t *testing.T) {
	for args, want := range map[string]string{
		"--help":          "NAME selects /etc/headwire/NAME.conf",
		"check --help":    "usage: headwire check [NAME | FILE]\n",
		"netcheck --help": "usage: headwire netcheck [NAME | FILE]\n",
	} {
		var out, errOut bytes.Buffer
		if code := Run(strings.Fields(args), strings.NewReader(""), &out, &errOut, Program{}); code != 0 {
			t.Fatalf("%v: code=%d stderr=%s", args, code, &errOut)
		}
		if !strings.Contains(out.String(), want) {
			t.Errorf("%v: %q missing from %s", args, want, &out)
		}
	}
	var checkHelp bytes.Buffer
	Run([]string{"check", "--help"}, strings.NewReader(""), &checkHelp, io.Discard, Program{})
	if strings.Count(checkHelp.String(), "\n") != 1 {
		t.Errorf("check --help is more than a usage line: %s", &checkHelp)
	}
	var out, errOut bytes.Buffer
	if code := Run([]string{"check", "-h", "extra"}, strings.NewReader(""), &out, &errOut, Program{}); code != 2 || out.Len() != 0 || !strings.Contains(errOut.String(), "usage: headwire check") {
		t.Fatalf("help with arguments: code=%d stdout=%q stderr=%q", code, &out, &errOut)
	}
}

func TestLogWriter(t *testing.T) {
	const verbose, plain = "magicsock: [v1] derp\n", "headwire: started\n"
	for level, want := range map[string]string{"": plain, "verbose": verbose + plain, "debug": verbose + plain, "silent": ""} {
		t.Setenv("LOG_LEVEL", level)
		var out bytes.Buffer
		w := LogWriter(&out)
		for _, line := range []string{verbose, plain} {
			if n, err := w.Write([]byte(line)); n != len(line) || err != nil {
				t.Fatalf("%q: Write = %d, %v", level, n, err)
			}
		}
		if out.String() != want {
			t.Errorf("LOG_LEVEL=%q: %q, want %q", level, &out, want)
		}
	}
}

func TestHelpCommand(t *testing.T) {
	p := Program{
		Request: func(string) (string, error) { t.Fatal("help contacted node"); return "", nil },
		Commands: map[string]Command{
			"up": {Args: " [NAME]"},
			"run": ConfigCommand(func([]string, io.Writer, io.Writer, func(io.Writer)) int {
				t.Fatal("help ran native command")
				return 0
			}),
		},
	}
	for _, cmd := range []string{"show", "ip", "ping", "check", "netcheck", "genkey", "pubkey", "discokey", "genpsk", "version", "up", "run"} {
		var want, wantErr bytes.Buffer
		if code := Run([]string{cmd, "--help"}, nil, &want, &wantErr, p); code != 0 {
			t.Fatal(code)
		}
		for _, alias := range []string{"help", "-h", "--help"} {
			var out, errOut bytes.Buffer
			if code := Run([]string{alias, cmd}, nil, &out, &errOut, p); code != 0 || out.String() != want.String() || errOut.Len() != 0 {
				t.Errorf("%s %s: %d %q %q", alias, cmd, code, &out, &errOut)
			}
		}
	}
	// No arguments is a request for general usage, not for status.
	var general, generalErr bytes.Buffer
	if code := Run(nil, nil, &general, &generalErr, p); code != 0 ||
		!strings.Contains(general.String(), "usage: headwire <command>") || generalErr.Len() != 0 {
		t.Fatalf("no arguments: %d %q %q", code, &general, &generalErr)
	}
	for _, alias := range []string{"help", "-h", "--help"} {
		var out, errOut bytes.Buffer
		if code := Run([]string{alias, "help"}, nil, &out, &errOut, p); code != 0 || out.String() != general.String() || errOut.Len() != 0 {
			t.Fatalf("help help: %d %q %q", code, &out, &errOut)
		}
		for _, args := range [][]string{{alias, "unknown"}, {alias, "show", "extra"}} {
			out.Reset()
			errOut.Reset()
			if code := Run(args, nil, &out, &errOut, p); code != 2 || out.Len() != 0 || errOut.Len() == 0 {
				t.Fatalf("%v: %d %q %q", args, code, &out, &errOut)
			}
		}
	}
}
