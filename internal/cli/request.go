package cli

import (
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"brof.dev/headwire/internal/status"
)

// nodeRequest validates arguments before a program selects a running node.
// Exact arguments keep Unix line framing and Apple messages equivalent.
func nodeRequest(cmd string, args []string) (string, error) {
	for _, arg := range args {
		if arg == "" || strings.ContainsAny(arg, " \t\r\n\v\f\x00") {
			return "", fmt.Errorf("invalid argument for %s: %q", cmd, arg)
		}
	}
	switch cmd {
	case "show":
		if len(args) == 0 {
			return "", nil
		}
		if len(args) == 1 {
			return args[0], status.ValidateField(args[0])
		}
	case "ip":
		if len(args) == 0 {
			return "ip", nil
		}
		// -1, -4 and -6 also accept a double dash, as Go flags do.
		flag, ok := strings.CutPrefix(args[0], "-")
		flag = strings.TrimPrefix(flag, "-")
		if len(args) == 1 && ok && (flag == "1" || flag == "4" || flag == "6") {
			return "ip -" + flag, nil
		}
	case "ping":
		if len(args) == 1 {
			ip, err := netip.ParseAddr(args[0])
			if err != nil {
				return "", err
			}
			return "ping " + ip.String(), nil
		}
	}
	return "", fmt.Errorf("invalid arguments for %s", cmd)
}

func runRequest(
	cmd string,
	args []string,
	stdout, stderr io.Writer,
	usage func(io.Writer),
	request func(string) (string, error),
	wait func(time.Duration),
) int {
	line, err := nodeRequest(cmd, args)
	if err != nil {
		fmt.Fprintln(stderr, "headwire:", err)
		usage(stderr)
		return 2
	}
	if cmd == "ping" {
		return ping(line, stdout, stderr, request, wait)
	}
	reply, err := request(line)
	if err != nil {
		fmt.Fprintln(stderr, "headwire:", err)
		return 1
	}
	io.WriteString(stdout, reply)
	return 0
}

// ping sends up to ten disco pings a second apart, stopping at the first
// answered over a direct path. Programs only supply transport, and neither
// parses the response or runs another retry loop.
func ping(
	line string,
	stdout, stderr io.Writer,
	request func(string) (string, error),
	wait func(time.Duration),
) int {
	anyPong := false
	for i := range 10 {
		reply, err := request(line)
		if err != nil {
			fmt.Fprintln(stderr, "headwire:", err)
			return 1
		}
		io.WriteString(stdout, reply)
		if strings.HasSuffix(reply, status.PingTimedOut) {
			if i < 9 {
				continue
			}
			if anyPong {
				return 0
			}
			fmt.Fprintln(stderr, "headwire: no reply")
			return 1
		}
		anyPong = true
		if !strings.Contains(reply, status.PingViaRelay) {
			return 0
		}
		if i < 9 {
			wait(time.Second)
		}
	}
	fmt.Fprintln(stderr, "headwire: direct connection not established")
	return 1
}
