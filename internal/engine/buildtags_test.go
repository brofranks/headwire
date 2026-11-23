package engine

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"tailscale.com/feature/featuretags"
)

func TestBuildTags(t *testing.T) {
	// keptFeatures names the Tailscale features the engine reaches.
	// scripts/goflags.sh omits every other one, so a feature added upstream
	// fails this test until it is reviewed.
	keptFeatures := []featuretags.FeatureTag{
		"gro",            // TUN segmentation offload, which links netstack
		"osrouter",       // routes and addresses on the kernel TUN
		"dns",            // [Interface] DNS
		"resolved",       // the systemd-resolved DNS backend
		"networkmanager", // the NetworkManager DNS backend
		"portmapper",     // UPnP, NAT-PMP and PCP, with NAT traversal
		"cloud",          // AWS public IPs as candidates, cloud DNS fallback
		"useproxy",       // relays reached through a configured HTTP proxy
		"bakedroots",     // DERP TLS roots if the system store fails
		"debug",          // logging and dropping flows a peer rejects
	}
	b, err := os.ReadFile("../../scripts/goflags.sh")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`-tags=(\S+)'`).FindSubmatch(b)
	if m == nil {
		t.Fatal("scripts/goflags.sh sets no -tags")
	}
	want := strings.Join(featuretags.MinTags(keptFeatures...), ",")
	if got := string(m[1]); got != want {
		t.Errorf("scripts/goflags.sh tags differ from keptFeatures, want:\n%s", want)
	}
}
