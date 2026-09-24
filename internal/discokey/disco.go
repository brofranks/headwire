// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause
//
// PrivateForNode is adapted from
// https://github.com/tailscale/tailcat/blob/15ab9e6/tailcat.go#L2507

// Package discokey derives a node's discovery key from its node private key.
package discokey

import (
	"crypto/hmac"
	"crypto/sha256"

	"go4.org/mem"
	"tailscale.com/types/key"
)

// PrivateForNode derives a node's disco private key from its node private
// key: HMAC-SHA256 under a headwire-specific domain, clamped as a Curve25519
// scalar. The disco public key is therefore a fixed function of the node
// identity and can be pasted into peers' configs next to the public key. Only
// that public half is exposed, but it travels in cleartext in every disco
// frame on direct paths and never changes, so it identifies the node to a
// passive observer.
func PrivateForNode(k key.NodePrivate) key.DiscoPrivate {
	raw := k.Raw32()
	mac := hmac.New(sha256.New, raw[:])
	mac.Write([]byte("brof.dev/headwire disco key v1"))
	discoRaw := mac.Sum(nil)
	discoRaw[0] &= 248
	discoRaw[31] &= 127
	discoRaw[31] |= 64
	return key.DiscoPrivateFromRaw32(mem.B(discoRaw))
}

// PublicForNode returns the disco public key peers must configure for
// the node with private key k.
func PublicForNode(k key.NodePrivate) key.DiscoPublic {
	return PrivateForNode(k).Public()
}
