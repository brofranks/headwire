package main

import (
	"testing"

	"tailscale.com/tstest/deptest"
)

func TestDeps(t *testing.T) {
	bad := map[string]string{
		"tailscale.com/wgengine/netstack":     "no userspace TCP/IP stack",
		"tailscale.com/ipn/ipnlocal":          "no Tailscale local backend",
		"tailscale.com/control/controlclient": "no control-plane client",
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for _, goarch := range []string{"amd64", "arm64"} {
			t.Run(goos+"/"+goarch, func(t *testing.T) {
				deptest.DepChecker{
					GOOS:    goos,
					GOARCH:  goarch,
					BadDeps: bad,
				}.Check(t)
			})
		}
	}
}
