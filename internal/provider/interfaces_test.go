package provider

import (
	"fmt"
	"maps"
	"strings"
	"testing"
)

func TestParseInterfaces(t *testing.T) {
	ifs, err := parseInterfaces([]byte(`[
		{"name":"wlan0","index":3,"mtu":1500,"up":true,"addresses":["192.168.1.5/24","fe80::1/64"]},
		{"name":"rmnet0","index":5,"mtu":1400,"up":false,"addresses":["10.20.30.40/32"]},
		{"name":"dummy0","index":7,"mtu":1500,"up":true}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, i := range ifs {
		addrs, err := i.Addrs() // Addrs falls through to the OS, which Android refuses, on a nil AltAddrs.
		if err != nil || i.AltAddrs == nil {
			t.Fatalf("%s: Addrs = %v, %v", i.Name, addrs, err)
		}
		got[i.Name] = fmt.Sprint(i.IsUp(), " ", i.Index, " ", i.MTU, " ", addrs)
	}
	want := map[string]string{
		"wlan0":  "true 3 1500 [192.168.1.5/24 fe80::1/64]",
		"rmnet0": "false 5 1400 [10.20.30.40/32]",
		"dummy0": "true 7 1500 []",
	}
	if !maps.Equal(got, want) {
		t.Errorf("interfaces = %v, want %v", got, want)
	}
	if ifs, err := parseInterfaces([]byte(`[]`)); err != nil || ifs == nil || len(ifs) != 0 {
		t.Errorf("empty list = %v, %v", ifs, err)
	}
	for _, bad := range []string{
		`[{"index":3}]`,
		`[{"name":"wlan0","addresses":["192.168.1.5"]}]`,
		`{"name":"wlan0"}`,
	} {
		if _, err := parseInterfaces([]byte(bad)); err == nil || !strings.HasPrefix(err.Error(), "interfaces: ") {
			t.Errorf("%s: err = %v", bad, err)
		}
	}
	if _, err := parseInterfaces([]byte(`[{"name":"wlan0","addresses":["x/24"]}]`)); err == nil ||
		!strings.Contains(err.Error(), "wlan0") {
		t.Errorf("bad address error = %v", err)
	}
}
