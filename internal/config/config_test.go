package config

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"go4.org/mem"
	"tailscale.com/types/key"
)

const (
	keyA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=" // 31 zero bytes then 1
	keyB = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI="
	keyC = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM="
	keyD = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ="
	keyE = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAU="
	zero = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

	iface  = "[Interface]\nPrivateKey = " + keyA + "\nAddress = 100.64.0.1/32\n"
	region = "[DERPRegion]\nID = 1\nNodes = derp1.example.com, derp2.example.com\n"
	peer   = "[Peer]\nPublicKey = " + keyB + "\nDiscoKey = " + keyC + "\nAllowedIPs = 100.64.0.2/32, 10.0.0.0/8\n"
	peer2  = "[Peer]\nPublicKey = " + keyD + "\nDiscoKey = " + keyE + "\nAllowedIPs = 100.64.0.3/32\n"
)

// selfPub is the public key of iface's PrivateKey.
func selfPub(t *testing.T) string {
	t.Helper()
	raw, err := DecodeKey(keyA)
	if err != nil {
		t.Fatal(err)
	}
	//lint:ignore SA1019 raw keys; see EncodeKey.
	return EncodeKey(key.NodePrivateFromRaw32(mem.B(raw[:])).Public().Raw32())
}

func TestParseTwoPeers(t *testing.T) {
	cfg, err := Parse([]byte(iface + peer + peer2))
	if err != nil || len(cfg.Peers) != 2 {
		t.Fatalf("Parse = %+v, %v; want two peers", cfg, err)
	}
}

func TestParseModes(t *testing.T) {
	tests := []struct {
		name     string
		src      string
		endpoint string
		homeDERP int
	}{
		{"passive", iface + peer, "", 0},
		{"endpoint", iface + peer + "Endpoint = 203.0.113.1:51820\n", "203.0.113.1:51820", 0},
		{"derp", iface + "HomeDERP = 1\n" + region + peer + "HomeDERP = 1\n", "", 1},
		{"endpoint and derp", iface + "HomeDERP = 1\n" + region + peer + "Endpoint = 203.0.113.1:51820\nHomeDERP = 1\n", "203.0.113.1:51820", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Parse([]byte(tt.src))
			if err != nil {
				t.Fatal(err)
			}
			if p := cfg.Peers[0]; p.Endpoint != tt.endpoint || p.HomeDERP != tt.homeDERP {
				t.Fatalf("Endpoint, HomeDERP = %q, %d; want %q, %d", p.Endpoint, p.HomeDERP, tt.endpoint, tt.homeDERP)
			}
		})
	}
}

func TestParseFields(t *testing.T) {
	cfg, err := Parse([]byte("# comment\n" + iface + "HomeDERP = 1 # inline\nListenPort = 51821\nMTU = 1420\n" +
		"DNS = 100.64.0.53, corp.example\nDNS = fd00::53\n" + region +
		"# New York\n" + peer + "PresharedKey = " + keyC + "\nhomederp = 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Interface.HomeDERP != 1 || cfg.Interface.ListenPort != 51821 || cfg.Interface.MTU != 1420 ||
		cfg.Regions[1].ID != 1 || len(cfg.Regions[1].Nodes) != 2 {
		t.Fatalf("unexpected interface/region: %+v", cfg)
	}
	if fmt.Sprint(cfg.Interface.DNS) != "[100.64.0.53 fd00::53]" || fmt.Sprint(cfg.Interface.DNSSearch) != "[corp.example.]" {
		t.Fatalf("unexpected DNS: %v %v", cfg.Interface.DNS, cfg.Interface.DNSSearch)
	}
	p := cfg.Peers[0]
	if p.HomeDERP != 1 || len(p.AllowedIPs) != 2 || p.AllowedIPs[1].String() != "10.0.0.0/8" || p.PresharedKey[31] != 3 {
		t.Fatalf("unexpected peer: %+v", p)
	}
	//lint:ignore SA1019 raw keys; see EncodeKey.
	if EncodeKey(p.PublicKey.Raw32()) != keyB || EncodeKey(p.DiscoKey.Raw32()) != keyC {
		t.Fatalf("keys did not round-trip: %+v", p)
	}
}

func TestParseMasqueradeAddress(t *testing.T) {
	cfg, err := Parse([]byte(iface + "Address = fd77::1/128\n" + peer + "MasqueradeAddress = 10.69.0.5, fc00::5\n" + peer2))
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Peers[0]
	if p.Masquerade4.String() != "10.69.0.5" || p.Masquerade6.String() != "fc00::5" || cfg.Peers[1].Masquerade4.IsValid() {
		t.Fatalf("masquerade = %v, %v; second peer %v", p.Masquerade4, p.Masquerade6, cfg.Peers[1].Masquerade4)
	}
}

func TestDecodeKeyRoundTrip(t *testing.T) {
	raw, err := DecodeKey(keyB)
	if err != nil || EncodeKey(raw) != keyB {
		t.Fatalf("DecodeKey(%s) = %x, %v", keyB, raw, err)
	}
	if _, err := DecodeKey(keyB[:43]); err == nil {
		t.Fatal("DecodeKey accepted a truncated key")
	}
	if _, err := DecodeKey(keyB[:42] + "J="); err == nil {
		t.Fatal("DecodeKey accepted dirty trailing bits")
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name, src, want string
	}{
		{"no interface", peer, "missing [Interface]"},
		{"key outside section", "PrivateKey = x\n", "line 1: key \"PrivateKey\" outside"},
		{"unknown section", iface + "[Foo]\n", "unknown section [Foo]"},
		{"unknown peer key", iface + peer + "Unknown = true\n", "unknown key \"Unknown\""},
		{"unsupported wireguard key", iface + peer + "PersistentKeepalive = 25\n", "unknown key \"PersistentKeepalive\""},
		{"bad key length", strings.Replace(iface, keyA, "AAAA", 1), "PrivateKey: key must be 44 base64"},
		{"non-canonical key", strings.Replace(iface, keyA, keyA[:42]+"F=", 1), "PrivateKey: key must be 44 base64"},
		{"bad port", iface + "ListenPort = 70000\n", "ListenPort: port must be 0-65535"},
		{"bad mtu", iface + "MTU = 0\n", "MTU: must be 1-"},
		{"dns empty entry", iface + "DNS = 192.0.2.1,\n", "DNS: invalid search domain \"\""},
		{"dns zone", iface + "DNS = fe80::1%eth0\n", "DNS: zone is only valid"},
		{"zero private", strings.Replace(iface, keyA, zero, 1), "PrivateKey: must not be zero"},
		{"missing disco", iface + "[Peer]\nPublicKey = " + keyB + "\nAllowedIPs = 100.64.0.2/32\n", "without DiscoKey requires Endpoint"},
		{"disco equals public", strings.Replace(iface+peer, keyC, keyB, 1), "DiscoKey: must differ from PublicKey"},
		{"zero psk", iface + peer + "PresharedKey = " + zero + "\n", "PresharedKey: must not be zero"},
		{"duplicate peer public key", iface + peer + strings.Replace(peer2, keyD, keyB, 1), "line 8: duplicate [Peer] PublicKey (also used by the [Peer] at line 4)"},
		{"duplicate peer disco key", iface + peer + strings.Replace(peer2, keyE, keyC, 1), "duplicate [Peer] DiscoKey"},
		{"peer is self", iface + strings.Replace(peer, keyB, selfPub(t), 1), "own public key"},
		{"bad psk", iface + peer + "PresharedKey = nope!\n", "PresharedKey: key must be 44 base64"},
		{"bad port", iface + peer + "Endpoint = 203.0.113.1:70000\n", "invalid port"},
		{"peer derp without interface derp", iface + region + peer + "HomeDERP = 1\n", "[Peer] HomeDERP requires [Interface] HomeDERP"},
		{"unknown interface region", iface + "HomeDERP = 2\n" + region + peer + "HomeDERP = 1\n", "HomeDERP = 2 does not match"},
		{"unknown peer region", iface + "HomeDERP = 1\n" + region + peer + "HomeDERP = 2\n", "HomeDERP = 2 does not match"},
		{"unknown region key", iface + "HomeDERP = 1\n" + region + "Unknown = value\n", "unknown key"},
		{"unknown interface key", iface + "Unknown = value\n", "unknown key"},
		{"duplicate region id", iface + "HomeDERP = 1\n" + region + region + peer, "duplicate DERP region ID 1"},
		{"region without nodes", iface + "HomeDERP = 1\n[DERPRegion]\nID = 1\n" + peer, "[DERPRegion] missing Nodes"},
		{"bad masquerade", iface + peer + "MasqueradeAddress = 10.69.0.5/32\n", "line 8: MasqueradeAddress:"},
		{"masquerade zone", iface + peer + "MasqueradeAddress = fe80::1%eth0\n", "MasqueradeAddress: zone is only valid"},
		{"two masquerades in a family", iface + peer + "MasqueradeAddress = 10.69.0.5, fc00::5, 10.69.0.6\n", "more than one address per family"},
		{"masquerade without interface family", iface + peer + "MasqueradeAddress = fc00::5\n", "line 4: [Peer] MasqueradeAddress fc00::5 requires exactly one [Interface] Address of the same family, found 0"},
		{"masquerade with two interface addresses", iface + "Address = 100.64.0.9/32\n" + peer + "MasqueradeAddress = 10.69.0.5\n", "exactly one [Interface] Address of the same family, found 2"},
		{"bad region id", iface + "HomeDERP = 0\n", "region ID must be 1-65535"},
		{"peer region id", iface + "HomeDERP = 1\n" + region + peer + "HomeDERP = 65536\n", "region ID must be 1-65535"},
		{"region section id", iface + "HomeDERP = 1\n" + strings.Replace(region, "ID = 1", "ID = 4294967296", 1) + peer + "HomeDERP = 1\n", "region ID must be 1-65535"},
		{"key with 31 bytes", strings.Replace(iface, keyA, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 31)), 1), "PrivateKey: key must be 44 base64"},
		{"duplicate interface", iface + iface, "line 4: duplicate [Interface] section"},
		{"region without id", iface + "HomeDERP = 1\n[DERPRegion]\nNodes = derp.example\n" + peer, "[DERPRegion] missing ID"},
		{"empty hostname", iface + "HomeDERP = 1\n" + strings.Replace(region, "derp1.example.com,", "derp1.example.com,,", 1) + peer, "line 7: empty hostname in Nodes"},
		{"peer without public key", iface + "[Peer]\nAllowedIPs = 100.64.0.2/32\n", "[Peer] missing PublicKey"},
		{"zero public key", iface + strings.Replace(peer, keyB, zero, 1), "PublicKey: must not be zero"},
		{"endpoint without host", iface + peer + "Endpoint = :51820\n", "host in \":51820\" must not be empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.src))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestWireGuardConfiguration(t *testing.T) {
	plain := "[Peer]\nPublicKey = " + keyB + "\nEndpoint = 127.0.0.1:53\n"
	for _, port := range []string{"", "ListenPort = 0\n", "ListenPort = 65535\n"} {
		cfg, err := Parse([]byte(iface + port + plain + "AllowedIPs = 192.0.2.1, fd00::1\nAllowedIPs = 10.0.0.1/8\n" + strings.Replace(plain, keyB, keyD, 1)))
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.Peers[0].WireGuardOnly() || !cfg.Peers[1].WireGuardOnly() || len(cfg.Peers[1].AllowedIPs) != 0 {
			t.Fatalf("ordinary peers: %+v", cfg.Peers)
		}
		if got := fmt.Sprint(cfg.Peers[0].AllowedIPs); got != "[192.0.2.1/32 fd00::1/128 10.0.0.0/8]" {
			t.Fatal(got)
		}
		want := uint16(0)
		if strings.Contains(port, "65535") {
			want = 65535
		}
		if cfg.Interface.ListenPort != want {
			t.Fatalf("port=%d, want %d", cfg.Interface.ListenPort, want)
		}
	}
	for name, extra := range map[string]string{
		"zero disco":             "DiscoKey = " + zero + "\n",
		"empty disco":            "DiscoKey = \n",
		"derp":                   "HomeDERP = 1\n",
		"empty allowed":          "AllowedIPs = \n",
		"empty repeated allowed": "AllowedIPs = 10.0.0.1\nAllowedIPs = \n",
		"malformed allowed":      "AllowedIPs = fd00::1/129\n",
		"duplicate endpoint":     "Endpoint = 127.0.0.1:10\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(iface + plain + extra)); err == nil {
				t.Fatal("accepted invalid ordinary peer")
			}
		})
	}
	for _, endpoint := range []string{"127.0.0.1:", "127.0.0.1:-1", "127.0.0.1:nonexistent-headwire-service"} {
		if _, err := Parse([]byte(iface + strings.Replace(plain, "127.0.0.1:53", endpoint, 1))); err == nil {
			t.Fatalf("accepted %q", endpoint)
		}
	}
}

func TestAddressFamilies(t *testing.T) {
	src := strings.Replace(iface, "100.64.0.1/32", "100.64.0.1/24, fd00::1/64", 1) + "Address = 192.0.2.1, fd01::1\n" + strings.Replace(peer, "100.64.0.2/32, 10.0.0.0/8", "0.0.0.0/0, ::/0, fd02::2", 1) + "Endpoint = [::1]:51820\n"
	cfg, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"100.64.0.1/24", "fd00::1/64", "192.0.2.1/32", "fd01::1/128"}
	for i, prefix := range cfg.Interface.Addresses {
		if prefix.String() != want[i] {
			t.Fatalf("address: %s", prefix)
		}
	}
	if len(cfg.Interface.Addresses) != len(want) || cfg.Peers[0].AllowedIPs[2].String() != "fd02::2/128" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	// HasAddress matches the addresses, not the subnets around them.
	if !cfg.Interface.HasAddress(netip.MustParseAddr("fd00::1")) || cfg.Interface.HasAddress(netip.MustParseAddr("100.64.0.2")) {
		t.Fatal("HasAddress does not match exact interface addresses")
	}
	for _, bad := range []string{
		iface + "PrivateKey = " + keyA + "\n",
		iface + "Address = \n",
		strings.Replace(iface, "Address = 100.64.0.1/32\n", "", 1),
		iface + "Address = fd00::1/129\n",
		iface + "Address = fe80::1%eth0\n",
		iface + peer + "Endpoint = ::1:51820\n",
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Fatalf("accepted invalid config: %s", bad)
		}
	}
}

func TestParseAllowIn(t *testing.T) {
	cfg, err := Parse([]byte(iface + "AllowIn = none\n" + peer + "AllowIn = tcp/22, udp/5000-5010\nAllowIn = icmp, 47, sctp\n" + peer2))
	if err != nil {
		t.Fatal(err)
	}
	want := []AllowRule{
		{Protos: []uint8{6}, First: 22, Last: 22},
		{Protos: []uint8{17}, First: 5000, Last: 5010},
		{Protos: []uint8{1, 58}, Last: 65535},
		{Protos: []uint8{47}, Last: 65535},
		{Protos: []uint8{132}, Last: 65535},
	}
	if !reflect.DeepEqual(cfg.Peers[0].AllowIn, want) {
		t.Errorf("AllowIn = %v, want %v", cfg.Peers[0].AllowIn, want)
	}
	if cfg.Interface.AllowIn == nil || len(cfg.Interface.AllowIn) != 0 || cfg.Peers[1].AllowIn != nil {
		t.Errorf("none = %v, unset = %v", cfg.Interface.AllowIn, cfg.Peers[1].AllowIn)
	}
	for _, bad := range []string{"", "any, tcp/22", "tcp/22, none", "none, none", "icmp/8", "47/1", "tcp/", "tcp/9-1", "tcp/65536", "256", "0", "99", "255", "TCP"} {
		if _, err := Parse([]byte(iface + "AllowIn = any\n" + peer + "AllowIn = " + bad + "\n")); err == nil {
			t.Errorf("AllowIn = %q parsed", bad)
		}
	}
}

func TestAllowInRequiresInterfaceDefault(t *testing.T) {
	_, err := Parse([]byte(iface + peer + "AllowIn = tcp/22\n"))
	if err == nil || !strings.Contains(err.Error(), "line 4: [Peer] AllowIn requires [Interface] AllowIn") {
		t.Fatalf("peer AllowIn without interface AllowIn: %v", err)
	}
	for _, ok := range []string{iface + "AllowIn = any\n" + peer + "AllowIn = tcp/22\n", iface + "AllowIn = none\n" + peer, iface + peer} {
		if _, err := Parse([]byte(ok)); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
}

func TestAllowInDestinations(t *testing.T) {
	cfg, err := Parse([]byte(iface + "AllowIn = tcp/22 to self\n" + peer +
		"AllowIn = any to 192.168.1.7/24, udp/53 to fd00::53\nAllowIn = icmp to any\n" + peer2))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Interface.AllowIn[0].Destination.Kind != DestinationSelf || cfg.Peers[1].AllowIn != nil {
		t.Fatal("lost self selector or unset peer policy")
	}
	for i, want := range []string{"192.168.1.0/24", "fd00::53/128"} {
		dst := cfg.Peers[0].AllowIn[i].Destination
		if dst.Kind != DestinationPrefix || dst.Prefix.String() != want {
			t.Errorf("destination %d = %v, want %s", i, dst, want)
		}
	}
	if cfg.Peers[0].AllowIn[2].Destination.Kind != DestinationAny {
		t.Fatal("explicit any destination not preserved")
	}
	for _, bad := range []string{
		"none/22", "none to self", "none to any", "any/22", "tcp/22 to", "tcp/22 self",
		"tcp/22 to self extra", "tcp/22 to example.com", "tcp/22 to fe80::1%eth0",
		"tcp/22 to 192.0.2.1/33", "tcp/22 to ::1/129", "tcp/22 to SELF",
		"any to any, tcp/22", "tcp/22, any to any", "any to self, none",
		"none\nAllowIn = tcp/22", "tcp/22\nAllowIn = any to any",
	} {
		t.Run(bad, func(t *testing.T) {
			_, err := Parse([]byte(iface + "AllowIn = any\n" + peer + "AllowIn = " + bad + "\n"))
			if err == nil || !strings.Contains(err.Error(), "line ") {
				t.Fatalf("expected line-numbered error for %q, got %v", bad, err)
			}
		})
	}
}
