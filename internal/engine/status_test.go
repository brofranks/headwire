package engine

import (
	"fmt"
	"math"
	"net/netip"
	"strings"
	"testing"
	"time"

	"brof.dev/headwire/internal/config"
	"brof.dev/headwire/internal/discokey"
	"brof.dev/headwire/internal/status"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
)

func TestStatusRendering(t *testing.T) {
	a, b, c, d := key.NewNode(), key.NewNode(), key.NewNode(), key.NewNode()
	cfg := &config.Config{
		Interface: config.Interface{PrivateKey: key.NewNode(), HomeDERP: 1},
		Regions:   map[int]config.Region{1: {ID: 1, Nodes: []string{"derp1.example"}}},
		Peers: []config.Peer{
			{PublicKey: a.Public(), Endpoint: "192.0.2.1:51820", PresharedKey: [32]byte{1}},
			{PublicKey: b.Public(), DiscoKey: discokey.PublicForNode(b), HomeDERP: 1, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}},
			{PublicKey: c.Public(), DiscoKey: discokey.PublicForNode(c), Endpoint: "[2001:db8::1]:51821", AllowedIPs: []netip.Prefix{netip.MustParsePrefix("fd00::3/128")}},
			{PublicKey: d.Public(), DiscoKey: discokey.PublicForNode(d), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.4/32")}}, // passive, never seen
		},
	}
	st, err := newState(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 100)
	runtime := &ipnstate.Status{Peer: map[key.NodePublic]*ipnstate.PeerStatus{
		b.Public(): {Relay: "1", LastHandshake: now.Add(-time.Minute), RxBytes: 1 << 50},
		c.Public(): {CurAddr: "[2001:db8::2]:51822", LastHandshake: now},
	}}
	v := statusView{
		cfg:   cfg,
		peers: peers(st, runtime),
		name:  "utun4",
		port:  54321,
		mark:  "0x80000",
		eps: []netip.AddrPort{
			netip.MustParseAddrPort("192.0.2.9:54321"),
			netip.MustParseAddrPort("[2001:db8::9]:54321"),
		},
	}
	//lint:ignore SA1019 raw keys; see config.EncodeKey.
	ap, bp, cp, dp := config.EncodeKey(a.Public().Raw32()), config.EncodeKey(b.Public().Raw32()), config.EncodeKey(c.Public().Raw32()), config.EncodeKey(d.Public().Raw32())
	want := map[string]string{
		//lint:ignore SA1019 raw keys; see config.EncodeKey.
		"public-key":  config.EncodeKey(cfg.Interface.PrivateKey.Public().Raw32()) + "\n",
		"private-key": "(hidden)\n", "listen-port": "54321\n", "fwmark": "0x80000\n",
		"peers":                ap + "\n" + bp + "\n" + cp + "\n" + dp + "\n",
		"preshared-keys":       ap + "\t(hidden)\n" + bp + "\t(none)\n" + cp + "\t(none)\n" + dp + "\t(none)\n",
		"endpoints":            ap + "\t192.0.2.1:51820\n" + bp + "\trelay:1\n" + cp + "\t[2001:db8::2]:51822\n" + dp + "\t(none)\n",
		"allowed-ips":          ap + "\t(none)\n" + bp + "\t10.0.0.2/32\n" + cp + "\tfd00::3/128\n" + dp + "\t10.0.0.4/32\n",
		"latest-handshakes":    fmt.Sprintf("%s\t0\n%s\t%d\n%s\t%d\n%s\t0\n", ap, bp, now.Unix()-60, cp, now.Unix(), dp),
		"transfer":             fmt.Sprintf("%s\t0\t0\n%s\t%d\t0\n%s\t0\t0\n%s\t0\t0\n", ap, bp, 1<<50, cp, dp),
		"persistent-keepalive": ap + "\toff\n" + bp + "\toff\n" + cp + "\toff\n" + dp + "\toff\n",
	}
	pretty := v.render("", now)
	for _, part := range []string{"interface: utun4\n", "  home derp: 1 (derp1.example)\n", "  fwmark: 0x80000\n", "  endpoints: 192.0.2.9:54321, [2001:db8::9]:54321\n", "endpoint: 192.0.2.1:51820 (configured)", "relay: 1 (derp1.example)\n", "latest handshake: Now", "latest handshake: 1 minute ago", "1024.00 TiB", "allowed ips: (none)"} {
		if !strings.Contains(pretty, part) {
			t.Errorf("missing %q in:\n%s", part, pretty)
		}
	}
	// Past REJECT_AFTER_TIME the relay is only the configured fallback.
	if stale := v.render("", now.Add(3*time.Minute)); !strings.Contains(stale, "relay: 1 (derp1.example) (configured)") {
		t.Errorf("stale session:\n%s", stale)
	}
	if strings.Index(pretty, "peer: "+cp) > strings.Index(pretty, "peer: "+bp) || strings.Index(pretty, "peer: "+bp) > strings.Index(pretty, "peer: "+ap) {
		t.Fatal("pretty peer order")
	}
	if strings.Contains(pretty[strings.Index(pretty, "peer: "+ap):strings.Index(pretty, "peer: "+dp)], "disco key:") {
		t.Fatal("ordinary peer displayed a disco key")
	}
	if unseen := pretty[strings.Index(pretty, "peer: "+dp):]; strings.Contains(unseen, "endpoint:") || strings.Contains(unseen, "relay:") {
		t.Fatalf("passive peer without a session showed a path:\n%s", unseen)
	}
	if len(statusFields) != len(status.Fields) {
		t.Fatalf("%d renderers for %d fields", len(statusFields), len(status.Fields))
	}
	for _, field := range status.Fields {
		if _, ok := statusFields[field]; !ok {
			t.Fatalf("no renderer for %s", field)
		}
		if field == "dump" {
			continue
		}
		if got := v.render(field, now); got != want[field] {
			t.Errorf("%s: got %q, want %q", field, got, want[field])
		}
	}
	dump := strings.Split(strings.TrimSpace(v.render("dump", now)), "\n")
	if dump[0] != fmt.Sprintf("(hidden)\t%s\t54321\t0x80000", strings.TrimSpace(want["public-key"])) ||
		dump[1] != ap+"\t(hidden)\t192.0.2.1:51820\t(none)\t0\t0\t0\toff" || len(dump) != 5 {
		t.Fatalf("dump: %v", dump)
	}
	for _, secret := range []string{config.EncodeKey(cfg.Interface.PrivateKey.Raw32()), config.EncodeKey(cfg.Peers[0].PresharedKey)} {
		if strings.Contains(pretty+v.render("dump", now), secret) {
			t.Fatal("status disclosed secret")
		}
	}
}

func TestStatusFormattingEdges(t *testing.T) {
	now := time.Unix(1000, 900_000_000)
	for _, tc := range []struct {
		hs   time.Time
		want string
	}{
		{time.Unix(1000, 0), "Now"},
		{time.Unix(999, 950_000_000), "1 second ago"},
		{time.Unix(939, 0), "1 minute, 1 second ago"},
		{time.Unix(1001, 0), "(System clock wound backward; connection problems may ensue.)"},
	} {
		if got := handshakeAge(tc.hs, now); got != tc.want {
			t.Errorf("got %q want %q", got, tc.want)
		}
	}
	for _, tc := range []struct {
		bytes int64
		want  string
	}{
		{0, "0 B"}, {1023, "1023 B"}, {1024, "1.00 KiB"}, {1 << 40, "1.00 TiB"}, {1 << 50, "1024.00 TiB"}, {math.MaxInt64, "8388608.00 TiB"},
	} {
		if got := prettyBytes(tc.bytes); got != tc.want {
			t.Errorf("got %q want %q", got, tc.want)
		}
	}
}

func TestInterfaceIPs(t *testing.T) {
	cfg := &config.Config{Interface: config.Interface{Addresses: []netip.Prefix{
		netip.MustParsePrefix("fd12::7/64"),
		netip.MustParsePrefix("10.0.0.7/24"),
		netip.MustParsePrefix("192.168.1.9/16"),
		netip.MustParsePrefix("2001:db8::9/48"),
	}}, Peers: []config.Peer{{
		AllowedIPs:  []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		Endpoint:    "192.0.2.1:51820",
		Masquerade4: netip.MustParseAddr("172.16.0.1"),
	}}}
	e := &Engine{}
	e.state.Store(&state{cfg: cfg})
	for request, want := range map[string]string{
		"ip":    "fd12::7\n10.0.0.7\n192.168.1.9\n2001:db8::9\n",
		"ip -4": "10.0.0.7\n192.168.1.9\n",
		"ip -6": "fd12::7\n2001:db8::9\n",
		"ip -1": "fd12::7\n",
	} {
		if got, err := e.Status(request); err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", request, got, err, want)
		}
	}
	for _, request := range []string{"ip -4 -6", "ip -4 -4", "ip -46", "ip peer", "ip -config file", "ip ", "ip -1 -4"} {
		if got, err := e.Status(request); err == nil || got != "" {
			t.Errorf("%q: got %q, %v; want error without output", request, got, err)
		}
	}
	for _, tc := range []struct{ address, request string }{{"10.0.0.7/24", "ip -6"}, {"fd12::7/64", "ip -4"}} {
		e.state.Store(&state{cfg: &config.Config{
			Interface: config.Interface{Addresses: []netip.Prefix{netip.MustParsePrefix(tc.address)}},
		}})
		if got, err := e.Status(tc.request); err == nil || got != "" {
			t.Errorf("%q: got %q, %v; want missing-family error", tc.request, got, err)
		}
	}
}

// TestRejectedStateKeepsIDs checks that a candidate that fails endpoint
// resolution does not hand out node IDs.
func TestRejectedStateKeepsIDs(t *testing.T) {
	a, b := key.NewNode(), key.NewNode()
	cfg := &config.Config{
		Interface: config.Interface{PrivateKey: key.NewNode()},
		Peers:     []config.Peer{{PublicKey: a.Public(), Endpoint: "192.0.2.1:51820"}},
	}
	st, err := newState(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Peers = append(
		cfg.Peers,
		config.Peer{PublicKey: b.Public(), Endpoint: "192.0.2.2:51820"},
		config.Peer{PublicKey: key.NewNode().Public(), Endpoint: "192.0.2.3:bad"},
	)
	if _, err := newState(cfg, st.ids); err == nil {
		t.Fatal("bad endpoint accepted")
	}
	if len(st.ids) != 1 || st.ids[a.Public()] != 2 {
		t.Fatalf("ids = %v", st.ids)
	}
	// Prefixes the parser would refuse still fail closed in ownership.
	for _, cfg := range []*config.Config{
		{Interface: config.Interface{Addresses: []netip.Prefix{{}}}, Peers: []config.Peer{{PublicKey: a.Public(), AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}}},
		{Peers: []config.Peer{{PublicKey: a.Public(), AllowedIPs: []netip.Prefix{{}}}}},
	} {
		if _, err := newState(cfg, nil); err == nil {
			t.Fatalf("invalid prefixes accepted: %+v", cfg)
		}
	}
}
