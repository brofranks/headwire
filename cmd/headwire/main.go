// Command headwire connects statically configured WireGuard peers, using
// tailscale.com's magicsock for DERP relaying and NAT traversal.
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"brof.dev/headwire/internal/cli"
	"brof.dev/headwire/internal/config"
	"brof.dev/headwire/internal/engine"

	// The OS router used in TUN mode. Embedders that are handed a device do
	// not link it.
	_ "tailscale.com/wgengine/router/osrouter"
)

// maxStatusRequest bounds a status request. The longest, a ping of an IPv6
// address, is 44 bytes.
const maxStatusRequest = 64

// statusTimeout bounds one status connection, so a client that never
// writes or never reads cannot hold the serial status service.
var statusTimeout = 5 * time.Second

// socketPath is where a running node serves its status to `show`.
var socketPath = func() string {
	if runtime.GOOS == "darwin" {
		return "/var/run/headwire/headwire.sock"
	}
	return "/run/headwire/headwire.sock"
}()

var program = cli.Program{
	Request: request,
	Usage: `  run [NAME | FILE]      run the node on a TUN interface (root, default: main)
`,
	Commands: map[string]cli.Command{
		"run": cli.ConfigCommand(runNode),
	},
}

func main() {
	os.Exit(realMain(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func realMain(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return cli.Run(args, stdin, stdout, stderr, program)
}

// request sends one line to the running node and returns its reply. A reply
// starting with "error: " is the node's refusal.
func request(line string) (string, error) {
	c, err := net.DialTimeout("unix", socketPath, statusTimeout)
	if err != nil {
		return "", fmt.Errorf("cannot connect to status socket: %w", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(statusTimeout))
	fmt.Fprintln(c, line)
	reply, err := io.ReadAll(c)
	if err != nil {
		return "", err
	}
	if msg, ok := bytes.CutPrefix(reply, []byte("error: ")); ok {
		return "", errors.New(strings.TrimSpace(string(msg)))
	}
	return string(reply), nil
}

// node is the running engine as the run loop uses it.
type node interface {
	Reload(*config.Config) error
	Status(field string) (string, error)
	Close()
}

// startNode is the seam tests replace: a real engine needs root and a TUN.
var startNode = func(cfg *config.Config, logf func(string, ...any)) (node, error) {
	return engine.Start(cfg, logf, engine.Options{})
}

func runNode(args []string, stdout, stderr io.Writer, usage func(io.Writer)) int {
	cfg, path, code := cli.LoadConfig(args, stderr, usage)
	if cfg == nil {
		return code
	}
	logger := log.New(cli.LogWriter(stderr), "headwire: ", log.LstdFlags)
	// The socket is claimed before the TUN, so a second node fails on the
	// socket another node answers rather than on a busy device.
	ln, err := listenStatus()
	if err != nil {
		logger.Print(err)
		return 1
	}
	e, err := startNode(cfg, logger.Printf)
	if err != nil {
		ln.Close()
		logger.Print(err)
		return 1
	}
	// Deferred last-in-first-out, so the listener closes first and
	// serveStatus stops querying the engine before the engine closes.
	defer e.Close()
	defer ln.Close()
	go serveStatus(ln, e.Status)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	logger.Print("started ", path)
	for {
		select {
		case <-ctx.Done():
			return 0
		case <-hup:
			// A bad file must not take the node down: log and keep the
			// running configuration. An apply failure requires teardown.
			if err := reloadNode(path, e.Reload, logger); err != nil {
				return 1
			}
		}
	}
}

// reloadNode separates safe refusals from errors after engine publication.
func reloadNode(path string, reload func(*config.Config) error, logger *log.Logger) error {
	cfg, err := config.Load(path, func(m string) { logger.Print("Warning: ", m) })
	if err == nil {
		err = reload(cfg)
	}
	if _, ok := errors.AsType[*engine.ReloadApplyError](err); ok {
		logger.Print("reload fatal, stopping for a clean restart: ", err)
		return err
	}
	if err != nil {
		logger.Print("reload rejected, running configuration retained: ", err)
		return nil
	}
	logger.Print("reload applied: ", path)
	return nil
}

// listenStatus claims the status socket. A socket something still answers
// on belongs to another node, and a stale one is replaced. Status names
// peers, endpoints and AllowedIPs, so the directory and socket are private
// to the daemon's user.
func listenStatus() (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return nil, err
	}
	if c, err := net.Dial("unix", socketPath); err == nil {
		c.Close()
		return nil, fmt.Errorf("%s: socket in use", socketPath)
	}
	os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// serveStatus answers on the socket until it closes: each connection sends
// one line naming the field it wants and reads the reply until EOF.
func serveStatus(ln net.Listener, status func(field string) (string, error)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.SetDeadline(time.Now().Add(statusTimeout))
		field, _ := bufio.NewReader(io.LimitReader(c, maxStatusRequest)).ReadString('\n')
		text, err := status(strings.TrimSpace(field))
		if err != nil {
			text = "error: " + err.Error() + "\n"
		}
		io.WriteString(c, text)
		c.Close()
	}
}
