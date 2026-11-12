package engine

import (
	"sync"
	"testing"

	"tailscale.com/net/dns"
)

type gatedDNS struct {
	dns.OSConfigurator
	assertLocked func()
	entered      chan struct{}
	release      chan struct{}
	mu           sync.Mutex
	events       []string
}

func (d *gatedDNS) SetDNS(dns.OSConfig) error {
	d.assertLocked()
	close(d.entered)
	<-d.release
	d.mu.Lock()
	defer d.mu.Unlock()
	d.events = append(d.events, "set")
	return nil
}

func (d *gatedDNS) Close() error {
	d.assertLocked()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.events = append(d.events, "close")
	return nil
}

func TestDNSRestorationWaitsForUpdate(t *testing.T) {
	d := &gatedDNS{entered: make(chan struct{}), release: make(chan struct{})}
	e := &Engine{hostDNS: d, unwatch: func() {}}
	d.assertLocked = func() {
		t.Helper()
		if e.dnsMu.TryLock() {
			e.dnsMu.Unlock()
			t.Error("DNS configurator called without the lifecycle lock")
		}
	}
	updated, closed := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(updated)
		if err := e.setDNS(dns.OSConfig{}); err != nil {
			t.Error(err)
		}
	}()
	<-d.entered
	go func() { e.Close(); close(closed) }()
	close(d.release)
	<-updated
	<-closed
	if err := e.setDNS(dns.OSConfig{}); err != nil {
		t.Fatal(err)
	}
	if len(d.events) != 2 || d.events[0] != "set" || d.events[1] != "close" {
		t.Fatalf("resolver events: %v", d.events)
	}
}
