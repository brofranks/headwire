package cli

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestNodeCommandValidation(t *testing.T) {
	p := Program{Request: func(string) (string, error) { t.Fatal("local validation contacted the node"); return "", nil }}
	for _, cmd := range []string{"show", "ip", "ping"} {
		for _, help := range []string{"help", "-h", "--help"} {
			var out, errOut bytes.Buffer
			if code := Run([]string{cmd, help}, nil, &out, &errOut, p); code != 0 || !strings.Contains(out.String(), "usage: headwire "+cmd) || errOut.Len() != 0 {
				t.Fatalf("%s %s: %d %q %q", cmd, help, code, &out, &errOut)
			}
		}
	}
	for _, args := range [][]string{
		{"show", ""}, {"show", "bogus"}, {"show", "peers", "extra"}, {"show", "peers\nping 10.0.0.1"},
		{"ip", ""}, {"ip", "-4 -6"}, {"ip", "-4", "-6"}, {"ip", "-4", "-4"}, {"ip", "-4\n"}, {"ip", "---4"}, {"ip", "-"}, {"ip", "--"}, {"ip", "-14"}, {"ip", "4"}, {"ip", "-1", "-4"},
		{"ping"}, {"ping", ""}, {"ping", "hostname"}, {"ping", "fe80::1%zone\n"}, {"ping", "10.0.0.1\n"}, {"ping", "10.0.0.1", "extra"},
	} {
		var out, errOut bytes.Buffer
		if code := Run(args, nil, &out, &errOut, p); code != 2 || out.Len() != 0 || !strings.Contains(errOut.String(), "usage:") {
			t.Errorf("%v: %d %q %q", args, code, &out, &errOut)
		}
	}
	if _, err := nodeRequest("bogus", nil); err == nil {
		t.Fatal("nodeRequest accepted an unknown command")
	}
}

func TestNodeCommandTransport(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		request string
	}{
		{[]string{"show"}, ""}, {[]string{"show", "dump"}, "dump"},
		{[]string{"ip"}, "ip"}, {[]string{"ip", "-4"}, "ip -4"}, {[]string{"ip", "-6"}, "ip -6"}, {[]string{"ip", "-1"}, "ip -1"},
		{[]string{"ip", "--1"}, "ip -1"}, {[]string{"ip", "--4"}, "ip -4"}, {[]string{"ip", "--6"}, "ip -6"},
		{[]string{"ping", "2001:db8::7"}, "ping 2001:db8::7"},
		{[]string{"ping", "2001:0db8:0:0:0:0:0:7"}, "ping 2001:db8::7"},
	} {
		var out, errOut bytes.Buffer
		calls := 0
		p := Program{Request: func(line string) (string, error) {
			calls++
			if line != tc.request {
				t.Fatalf("got %q, want %q", line, tc.request)
			}
			return "result\n", nil
		}}
		if code := Run(tc.args, nil, &out, &errOut, p); code != 0 || out.String() != "result\n" || errOut.Len() != 0 || calls != 1 {
			t.Errorf("%v: %d %q %q calls=%d", tc.args, code, &out, &errOut, calls)
		}
	}
	for _, cmd := range []string{"show", "ip"} {
		var out, errOut bytes.Buffer
		p := Program{Request: func(string) (string, error) { return "", errors.New("not running") }}
		if code := Run([]string{cmd}, nil, &out, &errOut, p); code != 1 || out.Len() != 0 || !strings.Contains(errOut.String(), "not running") {
			t.Errorf("%s: %d %q %q", cmd, code, &out, &errOut)
		}
	}
}

func TestPingSequence(t *testing.T) {
	const direct = "pong from 10.0.0.2 via 192.0.2.1:1234 in 1ms\n"
	const relay = "pong from 10.0.0.2 via relay:1 in 2ms\n"
	const timeout = "ping 10.0.0.2 timed out\n"
	for _, tc := range []struct {
		name               string
		replies            []string
		failure            string
		calls, waits, code int
		stdout, stderr     string
	}{
		{"direct", []string{direct}, "", 1, 0, 0, direct, ""},
		{"relay then direct", []string{relay, direct}, "", 2, 1, 0, relay + direct, ""},
		{"timeout then direct", []string{timeout, direct}, "", 2, 0, 0, timeout + direct, ""},
		{"relay exhausted", []string{relay}, "", 10, 9, 1, strings.Repeat(relay, 10), "headwire: direct connection not established\n"},
		{"timeouts exhausted", []string{timeout}, "", 10, 0, 1, strings.Repeat(timeout, 10), "headwire: no reply\n"},
		{"relay then timeouts", []string{relay, timeout}, "", 10, 1, 0, relay + strings.Repeat(timeout, 9), ""},
		{"timeout then relays", []string{timeout, relay}, "", 10, 8, 1, timeout + strings.Repeat(relay, 9), "headwire: direct connection not established\n"},
		{"disconnected", nil, "no profile is connected", 1, 0, 1, "", "headwire: no profile is connected\n"},
		{"missing socket", nil, "cannot connect to status socket", 1, 0, 1, "", "headwire: cannot connect to status socket\n"},
		{"ordinary peer", nil, "peer has no DiscoKey, use ping(8)", 1, 0, 1, "", "headwire: peer has no DiscoKey, use ping(8)\n"},
		{"provider error", nil, "provider request timed out", 1, 0, 1, "", "headwire: provider request timed out\n"},
		{"relay then error", []string{relay}, "disconnected", 2, 1, 1, relay, "headwire: disconnected\n"},
		{"timeout then error", []string{timeout}, "disconnected", 2, 0, 1, timeout, "headwire: disconnected\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			calls, waits := 0, 0
			request := func(string) (string, error) {
				calls++
				if tc.failure != "" && calls > len(tc.replies) {
					return "", errors.New(tc.failure)
				}
				return tc.replies[min(calls-1, len(tc.replies)-1)], nil
			}
			wait := func(d time.Duration) {
				waits++
				if d != time.Second {
					t.Fatalf("interval %v", d)
				}
			}
			code := runRequest("ping", []string{"10.0.0.2"}, &out, &errOut, func(io.Writer) { t.Fatal("unexpected usage") }, request, wait)
			if code != tc.code || calls != tc.calls || waits != tc.waits || out.String() != tc.stdout || errOut.String() != tc.stderr {
				t.Fatalf("code=%d calls=%d waits=%d stdout=%q stderr=%q", code, calls, waits, &out, &errOut)
			}
		})
	}
}
