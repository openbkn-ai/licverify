// Package keys is the single source of truth for OpenBKN's official license
// verification public keys. Products embed this table at compile time:
//
//	state, p := licverify.Eval(licText, keys.Official())
//
// Discipline (see the issuer's design docs):
//   - Public keys only. Private keys never leave the issuing server.
//   - Kids are zero-padded sequence names (key-01, key-02, …); rotation
//     appends a new entry and NEVER removes old ones — licenses signed by a
//     retired kid must keep verifying. An entry is removed only if its
//     private key is compromised, together with a coordinated re-issue.
//   - Rotation order: ship the new public key here first (products upgrade
//     this dependency), switch the issuer to the new kid only after the
//     fleet has caught up.
//   - Test issuers' keys never enter this table.
//   - Any change to this file requires two-person review.
package keys

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// official maps kid → Ed25519 public key of the OpenBKN issuing service.
var official = map[string]ed25519.PublicKey{
	// key-01: issued 2026-07, current signing key.
	"key-01": mustKey("eXf7L6cbfaSkRW956IL0Uq4fxqkWzNIH/3ButSEPLYc="),
}

// Official returns the official verification key table (kid → public key).
// The returned map is a copy; mutating it does not affect the embedded table.
func Official() map[string]ed25519.PublicKey {
	out := make(map[string]ed25519.PublicKey, len(official))
	for k, v := range official {
		out[k] = v
	}
	return out
}

func mustKey(b64 string) ed25519.PublicKey {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		panic(fmt.Sprintf("licverify/keys: bad key literal: %v", err))
	}
	if len(raw) != ed25519.PublicKeySize {
		panic(fmt.Sprintf("licverify/keys: bad key size %d", len(raw)))
	}
	return ed25519.PublicKey(raw)
}
