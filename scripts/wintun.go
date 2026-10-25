//go:build ignore

// Command wintun prints the download URL and SHA-256 of the Wintun release
// that tailscale.com pins, so release.sh bundles the DLL go.mod's tailscale.com
// requirement names.
package main

import (
	"fmt"

	"tailscale.com/tsconst/wintun"
)

func main() {
	fmt.Println(wintun.URL, wintun.SHA256)
}
