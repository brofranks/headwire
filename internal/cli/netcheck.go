package cli

import (
	"context"
	"fmt"
	"io"
	"log"
	"maps"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"brof.dev/headwire/internal/config"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/netmon"
	"tailscale.com/net/portmapper"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/util/eventbus"
)

func runNetcheck(args []string, stdout, stderr io.Writer, usage func(io.Writer)) int {
	cfg, _, code := LoadConfig(args, stderr, usage)
	if cfg == nil {
		return code
	}
	if len(cfg.Regions) == 0 {
		fmt.Fprintln(stderr, "headwire: netcheck requires at least one configured DERPRegion")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	dm := cfg.DERPMap()
	report, err := probeRegions(ctx, dm, log.New(LogWriter(stderr), "headwire: ", log.LstdFlags).Printf)
	if err != nil {
		fmt.Fprintln(stderr, "headwire: netcheck:", err)
		return 1
	}
	printNetcheck(stdout, cfg, report)
	return 0
}

// probeRegions is netcheckReport, replaced by tests that exercise the command.
var probeRegions = netcheckReport

// netcheckReport probes dm from fresh sockets, independently of any tunnel.
func netcheckReport(
	ctx context.Context,
	dm *tailcfg.DERPMap,
	logf logger.Logf,
) (*netcheck.Report, error) {
	bus := eventbus.New()
	defer bus.Close()
	mon, err := netmon.New(bus, logf)
	if err != nil {
		return nil, err
	}
	defer mon.Close()
	pm := portmapper.NewClient(portmapper.Config{EventBus: bus, NetMon: mon, Logf: logf})
	defer pm.Close()
	return probe(ctx, &netcheck.Client{NetMon: mon, PortMapper: pm, Logf: logf}, dm)
}

func probe(
	ctx context.Context,
	client *netcheck.Client,
	dm *tailcfg.DERPMap,
) (*netcheck.Report, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := client.Standalone(ctx, ""); err != nil {
		return nil, err
	}
	report, err := client.GetReport(ctx, dm, nil)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return report, err
}

func printNetcheck(w io.Writer, cfg *config.Config, r *netcheck.Report) {
	ipv4 := "(no addr found)"
	if r.GlobalV4.IsValid() {
		ipv4 = "yes, " + r.GlobalV4.String()
	}
	mapping := "unknown"
	if v, ok := r.MappingVariesByDestIP.Get(); ok {
		mapping = fmt.Sprint(v)
	}
	nearest := "unknown"
	if r.PreferredDERP != 0 {
		nearest = cfg.Regions[int(r.PreferredDERP)].Label()
	}
	fmt.Fprintf(w, "UDP: %t\n", r.UDP)
	fmt.Fprintf(w, "IPv4: %s\n", ipv4)
	fmt.Fprintf(w, "IPv6: %s\n", observedIPv6(r))
	fmt.Fprintf(w, "Mapping varies by destination IP: %s\n", mapping)
	fmt.Fprintf(w, "Port mapping: %s\n", portMapping(r))
	fmt.Fprintf(w, "Nearest DERP: %s\n", nearest)
	fmt.Fprintln(w, "DERP latency:")
	for _, id := range slices.SortedFunc(maps.Keys(cfg.Regions), func(a, b int) int {
		return r.RegionLatency.Compare(tailcfg.DERPRegionID(a), tailcfg.DERPRegionID(b))
	}) {
		latency := "no response"
		if d, ok := r.RegionLatency[tailcfg.DERPRegionID(id)]; ok {
			latency = d.Round(time.Millisecond / 10).String()
		}
		fmt.Fprintf(w, "  %d: %s (%s)\n", id, latency, strings.Join(cfg.Regions[id].Nodes, ", "))
	}
}

// observedIPv6 reports the public IPv6 endpoint, distinguishing a host whose
// OS supports IPv6 from one where it is unavailable.
func observedIPv6(r *netcheck.Report) string {
	switch {
	case r.GlobalV6.IsValid():
		return "yes, " + r.GlobalV6.String()
	case r.IPv6:
		return "(no addr found)"
	case r.OSHasIPv6:
		return "no, but OS has support"
	}
	return "no, unavailable in OS"
}

// portMapping lists the port-mapping protocols the gateway offered.
func portMapping(r *netcheck.Report) string {
	if !r.AnyPortMappingChecked() {
		return "not checked"
	}
	var got []string
	if r.UPnP.EqualBool(true) {
		got = append(got, "UPnP")
	}
	if r.PMP.EqualBool(true) {
		got = append(got, "NAT-PMP")
	}
	if r.PCP.EqualBool(true) {
		got = append(got, "PCP")
	}
	if len(got) == 0 {
		return "none"
	}
	return strings.Join(got, ", ")
}
