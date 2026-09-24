package discokey

import (
	"testing"

	"go4.org/mem"
	"tailscale.com/types/key"
)

func TestDiscoDerivationIsStable(t *testing.T) {
	var raw [32]byte
	for i := range raw {
		raw[i] = byte(i)
	}
	//lint:ignore SA1019 raw keys; see config.EncodeKey.
	got := PublicForNode(key.NodePrivateFromRaw32(mem.B(raw[:]))).String()
	const want = "discokey:a6136b0ec6e6f91b786ab213ffea02a6134abab2e493b06140750291b8eab063"
	if got != want {
		t.Fatalf("disco public = %s, want %s", got, want)
	}
}
