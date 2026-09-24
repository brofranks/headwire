package cli

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"brof.dev/headwire/internal/config"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/net/stun/stuntest"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/types/opt"
)

func TestNetcheckReport(t *testing.T) {
	cfg := &config.Config{Regions: map[int]config.Region{
		1: {ID: 1, Nodes: []string{"derp1a.example", "derp1b.example"}},
		2: {ID: 2, Nodes: []string{"derp2.example"}},
		3: {ID: 3, Nodes: []string{"derp3.example"}},
		4: {ID: 4, Nodes: []string{"derp4.example"}},
	}}
	r := &netcheck.Report{
		UDP: true, IPv4: true, GlobalV4: netip.MustParseAddrPort("203.0.113.1:1234"),
		UPnP: opt.Bool("false"), PCP: opt.Bool("true"),
		PreferredDERP: 3,
		RegionLatency: netcheck.RegionLatency{
			1: 20 * time.Millisecond,
			3: 10 * time.Millisecond,
			4: 10 * time.Millisecond,
		},
	}
	var out bytes.Buffer
	printNetcheck(&out, cfg, r)
	want := `UDP: true
IPv4: yes, 203.0.113.1:1234
IPv6: no, unavailable in OS
Mapping varies by destination IP: unknown
Port mapping: PCP
Nearest DERP: 3 (derp3.example)
DERP latency:
  3: 10ms (derp3.example)
  4: 10ms (derp4.example)
  1: 20ms (derp1a.example, derp1b.example)
  2: no response (derp2.example)
`
	if out.String() != want {
		t.Fatalf("report:\n%s\nwant:\n%s", &out, want)
	}
	// The IPv6 and port-mapping lines separate what was found, checked and
	// supported.
	for _, tc := range []struct {
		report *netcheck.Report
		want   string
	}{
		{&netcheck.Report{IPv6: true}, "IPv6: (no addr found)\n"},
		{&netcheck.Report{IPv6: true, GlobalV6: netip.MustParseAddrPort("[2001:db8::1]:1234")},
			"IPv6: yes, [2001:db8::1]:1234\n"},
		{&netcheck.Report{OSHasIPv6: true}, "IPv6: no, but OS has support\n"},
		{&netcheck.Report{UPnP: opt.Bool("false")}, "Port mapping: none\n"},
		{&netcheck.Report{UPnP: opt.Bool("true"), PMP: opt.Bool("true")}, "Port mapping: UPnP, NAT-PMP\n"},
	} {
		out.Reset()
		printNetcheck(&out, cfg, tc.report)
		if !strings.Contains(out.String(), tc.want) {
			t.Errorf("missing %q in:\n%s", tc.want, &out)
		}
	}
	// An empty report measures no region and prefers none.
	out.Reset()
	printNetcheck(&out, cfg, &netcheck.Report{})
	if strings.Count(out.String(), "no response") != 4 ||
		!strings.Contains(out.String(), "UDP: false") ||
		!strings.Contains(out.String(), "IPv4: (no addr found)\n") ||
		!strings.Contains(out.String(), "Port mapping: not checked\n") ||
		!strings.Contains(out.String(), "Nearest DERP: unknown\n") {
		t.Fatalf("empty report: %s", &out)
	}
}

func TestNetcheckUsage(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "main.conf")
	// The placeholder PrivateKey is the bytes 0x00 through 0x1f in base64.
	if err := os.WriteFile(cfg, []byte("[Interface]\nPrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\nAddress = 10.0.0.1/32\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"netcheck", cfg, "extra"}, "usage: headwire netcheck"},
		{[]string{"netcheck", cfg + ".missing"}, "no such file"},
		{[]string{"netcheck", cfg}, "requires at least one configured DERPRegion"},
	} {
		var out, errOut bytes.Buffer
		if code := realMain(tc.args, strings.NewReader(""), &out, &errOut); code != 2 || out.Len() != 0 || !strings.Contains(errOut.String(), tc.want) {
			t.Errorf("%v: code=%d out=%s err=%s", tc.args, code, &out, &errOut)
		}
	}

	// With a region, the command reports what the probe returns.
	if err := os.WriteFile(cfg, []byte("[Interface]\nPrivateKey = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\nAddress = 10.0.0.1/32\nHomeDERP = 1\n[DERPRegion]\nID = 1\nNodes = derp.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	original := probeRegions
	t.Cleanup(func() { probeRegions = original })
	probeRegions = func(context.Context, *tailcfg.DERPMap, logger.Logf) (*netcheck.Report, error) {
		return nil, errors.New("probe failed")
	}
	var out, errOut bytes.Buffer
	if code := realMain([]string{"netcheck", cfg}, strings.NewReader(""), &out, &errOut); code != 1 || out.Len() != 0 || !strings.Contains(errOut.String(), "netcheck: probe failed") {
		t.Fatalf("failed probe: code=%d out=%s err=%s", code, &out, &errOut)
	}
	probeRegions = func(_ context.Context, dm *tailcfg.DERPMap, _ logger.Logf) (*netcheck.Report, error) {
		return &netcheck.Report{UDP: true, RegionLatency: netcheck.RegionLatency{1: time.Millisecond}}, nil
	}
	out.Reset()
	errOut.Reset()
	if code := realMain([]string{"netcheck", cfg}, strings.NewReader(""), &out, &errOut); code != 0 || errOut.Len() != 0 || !strings.Contains(out.String(), "1: 1ms") {
		t.Fatalf("report: code=%d out=%s err=%s", code, &out, &errOut)
	}
}

func TestProbe(t *testing.T) {
	// Production probes bind to the underlay, but this fixture is on loopback.
	netns.SetEnabled(false)
	defer netns.SetEnabled(true)
	addr, closeServer := stuntest.Serve(t)
	defer closeServer()
	mon := netmon.NewStatic()
	defer mon.Close()
	client := &netcheck.Client{NetMon: mon, Logf: t.Logf, SkipExternalNetwork: true}
	dm := stuntest.DERPMapOf(addr.String())
	report, err := probe(t.Context(), client, dm)
	if err != nil {
		t.Fatal(err)
	}
	if !report.UDP || !report.IPv4 || !report.GlobalV4.IsValid() || len(report.RegionLatency) != 1 {
		t.Fatalf("incomplete local STUN report: %+v", report)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := probe(ctx, client, dm); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled probe: %v", err)
	}
	// The command's own fixture (a live network monitor and port mapper)
	// builds and tears down without sending anything.
	if _, err := netcheckReport(ctx, dm, t.Logf); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled report: %v", err)
	}
}
