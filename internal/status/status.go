// Package status is the status socket's field vocabulary, shared by the
// client that builds a request and the engine that answers it.
package status

import (
	"fmt"
	"slices"
)

// Fields is the machine-readable field vocabulary, in help order. The engine
// renders each one, and a client offers them and rejects anything else.
var Fields = []string{
	"public-key",
	"private-key",
	"listen-port",
	"fwmark",
	"peers",
	"preshared-keys",
	"endpoints",
	"allowed-ips",
	"latest-handshakes",
	"transfer",
	"persistent-keepalive",
	"dump",
}

// PingTimedOut follows the echoed "ping IP" request in the reply to an
// unanswered probe, which the CLI retries.
const PingTimedOut = " timed out\n"

// PingViaRelay introduces the DERP region ID in the reply to a probe that no
// direct path answered, which the CLI retries.
const PingViaRelay = " via relay:"

// ValidateField accepts a name in Fields, or the empty name that asks for
// the whole status.
func ValidateField(field string) error {
	if field != "" && !slices.Contains(Fields, field) {
		return fmt.Errorf("invalid field %q", field)
	}
	return nil
}
