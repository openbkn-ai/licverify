// Package licverify is the product-side license verification library.
// It has no dependency on the license server; products embed the issuer's
// public keys and verify licenses fully offline.
package licverify

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Payload is the signed content of a license.
type Payload struct {
	LicID    string   `json:"lic_id"`
	Kid      string   `json:"kid"`
	Edition  Edition  `json:"edition"`
	Customer Customer `json:"customer"`
	IssuedAt int64    `json:"issued_at"`
	// ExpiresAt is the technical validity of this single license (the only
	// time the product enforces). 0 means never expires (community).
	ExpiresAt int64 `json:"expires_at"`
	// ContractExpiresAt is the contract end date, shown as "licensed until".
	// Renewal never extends past it. 0 means perpetual.
	ContractExpiresAt int64            `json:"contract_expires_at"`
	Features          []string         `json:"features"`
	Limits            map[string]int64 `json:"limits"`
	// HWFingerprint is the instance fingerprint bound at activation; empty
	// until the license has been activated and reissued.
	HWFingerprint string `json:"hw_fingerprint,omitempty"`
}

type Customer struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	// Project identifies the licensed project — licensing granularity is
	// per project (one project, one license).
	Project string `json:"project,omitempty"`
}

// HasFeature reports whether the license enables the named feature.
func (p *Payload) HasFeature(name string) bool {
	for _, f := range p.Features {
		if f == name {
			return true
		}
	}
	return false
}

// Limit returns the limit value for name. Missing means 0 (not allowed);
// -1 means unlimited.
func (p *Payload) Limit(name string) int64 {
	return p.Limits[name]
}

var (
	ErrMalformed  = errors.New("licverify: malformed license")
	ErrUnknownKey = errors.New("licverify: unknown signing key")
	ErrBadSig     = errors.New("licverify: signature verification failed")
	ErrExpired    = errors.New("licverify: license expired")
	ErrNotYet     = errors.New("licverify: license not yet valid")
)

const versionPrefix = "v1"

// GracePeriod is how long after expiry the product keeps features enabled
// (and the server still accepts renewal). Shared constant so offline
// product behavior and server renewal policy agree.
const GracePeriod = 30 * 24 * time.Hour

// Verify checks the license text against the given public keys and the
// current time. Returns the payload on success.
func Verify(text string, keys map[string]ed25519.PublicKey) (*Payload, error) {
	return VerifyAt(text, keys, time.Now())
}

// VerifyAt is Verify with an explicit clock, for testing and for callers
// that use a trusted time source.
func VerifyAt(text string, keys map[string]ed25519.PublicKey, now time.Time) (*Payload, error) {
	p, err := Parse(text, keys)
	if err != nil {
		return nil, err
	}
	// ExpiresAt == 0 means never expires (community licenses).
	if p.ExpiresAt != 0 && now.Unix() > p.ExpiresAt {
		return nil, fmt.Errorf("%w at %s", ErrExpired, time.Unix(p.ExpiresAt, 0).UTC().Format(time.RFC3339))
	}
	// Small tolerance for clock skew between issuer and product host.
	if now.Add(24*time.Hour).Unix() < p.IssuedAt {
		return nil, ErrNotYet
	}
	return p, nil
}

// State is the product-side judgement of a license file.
type State string

const (
	// StateValid: signature good, within validity — full feature set.
	StateValid State = "valid"
	// StateGrace: expired less than GracePeriod ago — features stay enabled,
	// product should prompt for renewal.
	StateGrace State = "grace"
	// StateFallback: a commercial license expired beyond grace but its
	// signature still verifies. That is proof the instance was once formally
	// licensed: the product automatically falls back to the community
	// feature set, keeping data readable and exportable.
	StateFallback State = "fallback_community"
	// StateInvalid: malformed, bad signature, unknown key, or not yet valid.
	// The product still runs on the community feature set — a bad file is no
	// reason to withhold what is free anyway — but should say the license file
	// could not be verified rather than nag for activation.
	StateInvalid State = "invalid"
	// StateTrial: no license imported yet, within TrialPeriod of first run.
	// Community feature set, quietly; the product may show days remaining.
	StateTrial State = "trial"
	// StateUnlicensed: no license, trial window elapsed. Still the community
	// feature set — nothing is ever withheld — with a persistent prompt to
	// activate.
	StateUnlicensed State = "unlicensed"
)

// TrialPeriod is how long a fresh, never-licensed deployment runs before the
// activation prompt turns persistent. Nothing is disabled when it elapses.
const TrialPeriod = 30 * 24 * time.Hour

// TrialAt judges a deployment that holds no license, from the first-run
// timestamp the product persisted (unix seconds; <= 0 means "starting now").
// Trial state is deliberately local and resettable: it exists to give new
// installs a quiet grace before nagging, not to gate anything. Nothing about
// the feature set depends on it, so there is nothing to defend.
func TrialAt(firstRun int64, now time.Time) State {
	if firstRun <= 0 || now.Sub(time.Unix(firstRun, 0)) < TrialPeriod {
		return StateTrial
	}
	return StateUnlicensed
}

// TrialRemaining is how much of the trial window is left (0 once elapsed).
func TrialRemaining(firstRun int64, now time.Time) time.Duration {
	if firstRun <= 0 {
		return TrialPeriod
	}
	if d := TrialPeriod - now.Sub(time.Unix(firstRun, 0)); d > 0 {
		return d
	}
	return 0
}

// Eval judges a license file for gating decisions: valid / grace /
// fallback-to-community / invalid. Unlike Verify it never returns an error
// for expiry — expiry is a state, not a failure.
func Eval(text string, keys map[string]ed25519.PublicKey) (State, *Payload) {
	return EvalAt(text, keys, time.Now())
}

// EvalAt is Eval with an explicit clock.
func EvalAt(text string, keys map[string]ed25519.PublicKey, now time.Time) (State, *Payload) {
	p, err := Parse(text, keys)
	if err != nil {
		return StateInvalid, nil
	}
	if now.Add(24*time.Hour).Unix() < p.IssuedAt {
		return StateInvalid, nil
	}
	if p.ExpiresAt == 0 || now.Unix() <= p.ExpiresAt {
		return StateValid, p
	}
	// Grace only holds within the contract period: at contract end a license
	// has ExpiresAt == ContractExpiresAt, so the day after expiry it must fall
	// straight to fallback, matching the server's license.DeriveState. A
	// perpetual/legacy license (ContractExpiresAt == 0) keeps the plain grace.
	inContract := p.ContractExpiresAt == 0 || now.Unix() <= p.ContractExpiresAt
	if inContract && now.Unix() <= time.Unix(p.ExpiresAt, 0).Add(GracePeriod).Unix() {
		return StateGrace, p
	}
	return StateFallback, p
}

// Parse verifies the signature only (no expiry check) and returns the payload.
// The signature is verified over the exact transmitted payload bytes, so no
// JSON canonicalization is involved.
func Parse(text string, keys map[string]ed25519.PublicKey) (*Payload, error) {
	parts := strings.Split(strings.TrimSpace(text), ".")
	if len(parts) != 3 || parts[0] != versionPrefix {
		return nil, ErrMalformed
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrMalformed
	}
	var p Payload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return nil, ErrMalformed
	}
	pub, ok := keys[p.Kid]
	if !ok {
		return nil, fmt.Errorf("%w: kid=%q", ErrUnknownKey, p.Kid)
	}
	if !ed25519.Verify(pub, payloadBytes, sig) {
		return nil, ErrBadSig
	}
	return &p, nil
}

// ParsePublicKey decodes a base64 (std, raw or padded) Ed25519 public key,
// as served by the issuer's /api/keys endpoint.
func ParsePublicKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("licverify: bad public key encoding: %w", err)
		}
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("licverify: bad public key size %d", len(raw))
	}
	return ed25519.PublicKey(raw), nil
}
