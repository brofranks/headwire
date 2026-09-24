// Package cli is the headwire command line shared by every program: the
// headwire binary adds run, and Headwire.app adds its profile and GUI verbs.
package cli

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
	"maps"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"brof.dev/headwire/internal/config"
	"brof.dev/headwire/internal/discokey"
	"brof.dev/headwire/internal/status"
	"go4.org/mem"
	"tailscale.com/types/key"
)

// version is set by the release build, local builds default to dev.
var version = "dev"

// ConfigCommand is a command that loads its configuration with LoadConfig.
func ConfigCommand(run RunFunc) Command {
	return Command{Args: " [NAME | FILE]", Run: run}
}

// Command is one entry of the command table. A nil Run is a command the program
// dispatches itself before calling Run, so reaching it is a usage error.
type Command struct {
	Args string // after the name in its usage line, holding the whole argument vocabulary
	Run  RunFunc
}

// RunFunc runs a command with the arguments after its name. usage prints the
// command's own usage.
type RunFunc func(args []string, stdout, stderr io.Writer, usage func(io.Writer)) int

// Program adds its own commands and request transport to the shared ones.
type Program struct {
	Usage    string // lines listing the program's commands after the shared ones
	Commands map[string]Command
	Request  func(string) (string, error) // one request to the running node
}

func (p Program) usage(w io.Writer) {
	fmt.Fprint(w, `usage: headwire <command>

Commands:
  show [FIELD]           status of the running node, --help lists fields
  ip [-1|-4|-6]          local addresses of the running node
  ping IP                disco-ping up to 10 times, stopping at a direct response
  check [NAME | FILE]    validate the configuration (default: main)
  genkey                 print a new private key
  pubkey                 read a private key on stdin, print its WireGuard public key
  discokey               read a private key on stdin, print its discovery public key
  genpsk                 print a new preshared key
  netcheck [NAME | FILE] probe connectivity to configured relay regions
  version                print the build version
`+p.Usage+`
NAME selects `+config.Path("NAME")+`, any other argument is a file.
Use help COMMAND or COMMAND --help for command-specific help.
`)
}

// commands is the whole command table: the shared commands, then the program's.
func (p Program) commands(stdin io.Reader) map[string]Command {
	request := func(cmd string) RunFunc {
		return func(args []string, stdout, stderr io.Writer, usage func(io.Writer)) int {
			return runRequest(cmd, args, stdout, stderr, usage, p.Request, time.Sleep)
		}
	}
	cmds := map[string]Command{
		"show": {Args: " [" + strings.Join(status.Fields, " | ") + "]", Run: request("show")},
		"ip":   {Args: " [-1 | -4 | -6]", Run: request("ip")},
		"ping": {Args: " IP", Run: request("ping")},
		"check": ConfigCommand(func(args []string, _, stderr io.Writer, usage func(io.Writer)) int {
			_, _, code := LoadConfig(args, stderr, usage)
			return code
		}),
		"netcheck": ConfigCommand(runNetcheck),
		"genkey": {Run: noArgs(func(stdout, stderr io.Writer) int {
			warnWorldReadable(stdout, stderr)
			fmt.Fprintln(stdout, config.EncodeKey(key.NewNode().Raw32()))
			return 0
		})},
		"genpsk": {Run: noArgs(func(stdout, stderr io.Writer) int {
			warnWorldReadable(stdout, stderr)
			var psk [32]byte
			rand.Read(psk[:])
			fmt.Fprintln(stdout, config.EncodeKey(psk))
			return 0
		})},
		"pubkey":   {Run: noArgs(func(stdout, stderr io.Writer) int { return publicKey("pubkey", stdin, stdout, stderr) })},
		"discokey": {Run: noArgs(func(stdout, stderr io.Writer) int { return publicKey("discokey", stdin, stdout, stderr) })},
		"version": {Run: noArgs(func(stdout, _ io.Writer) int {
			fmt.Fprintln(stdout, "headwire", buildVersion())
			return 0
		})},
		"help": {Run: noArgs(func(stdout, _ io.Writer) int {
			p.usage(stdout)
			return 0
		})},
	}
	maps.Copy(cmds, p.Commands)
	return cmds
}

// noArgs is the Run of a command that takes no arguments.
func noArgs(run func(stdout, stderr io.Writer) int) RunFunc {
	return func(args []string, stdout, stderr io.Writer, usage func(io.Writer)) int {
		if len(args) != 0 {
			usage(stderr)
			return 2
		}
		return run(stdout, stderr)
	}
}

func isHelp(arg string) bool { return arg == "help" || arg == "-h" || arg == "--help" }

// Run executes args and returns the exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer, p Program) int {
	if len(args) == 0 {
		args = []string{"help"}
	}
	if isHelp(args[0]) && len(args) == 2 {
		if isHelp(args[1]) {
			args = []string{"help"}
		} else {
			args = []string{args[1], "--help"}
		}
	}
	name := args[0]
	if isHelp(name) {
		name = "help"
	}
	if name == "-v" || name == "--version" {
		name = "version"
	}
	cmd, ok := p.commands(stdin)[name]
	if !ok {
		fmt.Fprintf(stderr, "headwire: unknown command %q\n", name)
		p.usage(stderr)
		return 2
	}
	usage := func(w io.Writer) { fmt.Fprintf(w, "usage: headwire %s%s\n", name, cmd.Args) }
	if len(args) == 2 && isHelp(args[1]) {
		usage(stdout)
		return 0
	}
	if cmd.Run == nil {
		usage(stderr)
		return 2
	}
	return cmd.Run(args[1:], stdout, stderr, usage)
}

// buildVersion prefers the release stamp, then the module version that
// `go install brof.dev/headwire/cmd/headwire@VERSION` records.
func buildVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok && version == "dev" && info.Main.Version != "" &&
		info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return version
}

// publicKey prints the value the selected command derives from the private
// key on stdin. Each command prints one bare key for use in a [Peer] section.
func publicKey(cmd string, stdin io.Reader, stdout, stderr io.Writer) int {
	src, err := io.ReadAll(stdin)
	if err != nil {
		fmt.Fprintln(stderr, "headwire:", err)
		return 2
	}
	raw, err := config.DecodeKey(strings.TrimSpace(string(src)))
	if err != nil {
		fmt.Fprintln(stderr, "headwire: stdin:", err)
		return 2
	}
	var pub [32]byte
	if cmd == "discokey" {
		//lint:ignore SA1019 raw keys; see config.EncodeKey.
		pub = discokey.PublicForNode(key.NodePrivateFromRaw32(mem.B(raw[:]))).Raw32()
	} else {
		// X25519 clamps an all-zero scalar rather than rejecting it.
		priv, err := ecdh.X25519().NewPrivateKey(raw[:])
		if err != nil {
			fmt.Fprintln(stderr, "headwire:", err)
			return 2
		}
		copy(pub[:], priv.PublicKey().Bytes())
	}
	fmt.Fprintln(stdout, config.EncodeKey(pub))
	return 0
}

// warnWorldReadable warns when keys are written straight to a file other
// users can read.
func warnWorldReadable(stdout, stderr io.Writer) {
	f, ok := stdout.(*os.File)
	if !ok {
		return
	}
	if fi, err := f.Stat(); err == nil && fi.Mode().IsRegular() && !config.Private(fi.Mode()) {
		fmt.Fprintln(stderr, "Warning: writing to a file that group or other can access")
	}
}

// LoadConfig loads the configuration a command's optional NAME or FILE
// argument selects. It returns a nil config with the exit code to use when
// the command should not run.
func LoadConfig(
	args []string,
	stderr io.Writer,
	usage func(io.Writer),
) (*config.Config, string, int) {
	if len(args) > 1 {
		usage(stderr)
		return nil, "", 2
	}
	name := "main"
	if len(args) == 1 {
		name = args[0]
	}
	path := config.Path(name)
	cfg, err := config.Load(path, func(m string) { fmt.Fprintln(stderr, "Warning:", m) })
	if err != nil {
		fmt.Fprintln(stderr, "headwire:", err)
		return nil, "", 2
	}
	return cfg, path, 0
}

// LogWriter applies LOG_LEVEL to the engine's output: the default hides
// tailscale's [v1]/[v2] verbose lines, verbose/debug keep them, silent
// drops everything. headwire's own lines carry no marker.
func LogWriter(stderr io.Writer) io.Writer {
	switch os.Getenv("LOG_LEVEL") {
	case "verbose", "debug":
		return stderr
	case "silent":
		return io.Discard
	}
	return quietWriter{stderr}
}

type quietWriter struct{ w io.Writer }

func (q quietWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("[v1] ")) || bytes.Contains(p, []byte("[v2] ")) {
		return len(p), nil
	}
	return q.w.Write(p)
}
