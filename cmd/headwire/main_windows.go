package main

import (
	"log"

	"github.com/dblohm7/wingoes/com"
)

func init() {
	// The router sets the adapter's network category to private through COM,
	// which must be initialized once per process. Without it the category
	// stays public and the inbound rules the router adds, which cover the
	// domain and private profiles only, do not apply to the tunnel.
	if err := com.StartRuntime(com.ConsoleApp); err != nil {
		log.Printf("com.StartRuntime: %v", err)
	}
}
