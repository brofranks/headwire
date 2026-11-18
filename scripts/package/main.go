// Command package builds one Linux package from contrib/nfpm.yaml. Usage:
// package FORMAT TARGET, where FORMAT is deb or rpm.
package main

import (
	"log"
	"os"

	"github.com/goreleaser/nfpm/v2"
	_ "github.com/goreleaser/nfpm/v2/deb"
	_ "github.com/goreleaser/nfpm/v2/rpm"
)

func main() {
	format, target := os.Args[1], os.Args[2]
	// ParseFile expands the environment variables the configuration names.
	config, err := nfpm.ParseFile("contrib/nfpm.yaml")
	if err != nil {
		log.Fatal(err)
	}
	info, err := config.Get(format)
	if err != nil {
		log.Fatal(err)
	}
	info = nfpm.WithDefaults(info)
	packager, err := nfpm.Get(format)
	if err != nil {
		log.Fatal(err)
	}
	f, err := os.Create(target)
	if err != nil {
		log.Fatal(err)
	}
	if err := packager.Package(info, f); err != nil {
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}
}
