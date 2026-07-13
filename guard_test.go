package licverify

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type licBox struct {
	mu   sync.Mutex
	text string
}

func (b *licBox) load() (string, error) { b.mu.Lock(); defer b.mu.Unlock(); return b.text, nil }
func (b *licBox) store(t string) error  { b.mu.Lock(); defer b.mu.Unlock(); b.text = t; return nil }

func guardFixture(t *testing.T, issuedAgo, validFor time.Duration, fp string) (map[string]ed25519.PublicKey, ed25519.PrivateKey, *licBox) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	text := makeLicense(t, priv, &Payload{
		LicID: "g1", Kid: "k1", Edition: "professional",
		IssuedAt: now.Add(-issuedAgo).Unix(), ExpiresAt: now.Add(validFor).Unix(),
		HWFingerprint: fp,
	})
	return map[string]ed25519.PublicKey{"k1": pub}, priv, &licBox{text: text}
}

func TestGuardStateAndBinding(t *testing.T) {
	keys, _, box := guardFixture(t, time.Hour, 90*24*time.Hour, "fp_me")

	g, err := NewGuard(GuardConfig{Keys: keys, Load: box.load, InstanceFP: "fp_me"})
	if err != nil {
		t.Fatal(err)
	}
	if s := g.State(); s.State != StateValid {
		t.Fatalf("want valid, got %s (%v)", s.State, s.Err)
	}

	// Same license copied to another machine: invalid, offline.
	g2, err := NewGuard(GuardConfig{Keys: keys, Load: box.load, InstanceFP: "fp_other"})
	if err != nil {
		t.Fatal(err)
	}
	if s := g2.State(); s.State != StateInvalid || !errors.Is(s.Err, ErrFingerprintMismatch) {
		t.Fatalf("copied license must be invalid: %s (%v)", s.State, s.Err)
	}
}

func TestGuardAutoRenews(t *testing.T) {
	// 65 of 90 days used up → inside the last third → must renew.
	keys, priv, box := guardFixture(t, 65*24*time.Hour, 25*24*time.Hour, "fp_me")

	var gotFP string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct{ License, InstanceFP string }
		var raw map[string]string
		_ = json.NewDecoder(r.Body).Decode(&raw)
		in.License, in.InstanceFP = raw["license"], raw["instance_fp"]
		gotFP = in.InstanceFP
		now := time.Now()
		fresh := makeLicense(t, priv, &Payload{
			LicID: "g2", Kid: "k1", Edition: "professional",
			IssuedAt: now.Unix(), ExpiresAt: now.Add(90 * 24 * time.Hour).Unix(),
			HWFingerprint: "fp_me",
		})
		_ = json.NewEncoder(w).Encode(map[string]string{"license": fresh})
	}))
	defer srv.Close()

	var transitions int
	g, err := NewGuard(GuardConfig{
		Keys: keys, Load: box.load, Store: box.store,
		RenewURL: srv.URL, InstanceFP: "fp_me",
		OnChange: func(_, _ Snapshot) { transitions++ },
	})
	if err != nil {
		t.Fatal(err)
	}
	// Renewal happens on the loop / RenewNow, not in the constructor (which
	// must never block on the network).
	s := g.RenewNow()
	if s.State != StateValid || s.Payload.LicID != "g2" {
		t.Fatalf("expected renewed license g2, got %s / %+v (%v)", s.State, s.Payload, s.Err)
	}
	if gotFP != "fp_me" {
		t.Errorf("renew must carry the instance fingerprint, got %q", gotFP)
	}
	// Renewed text persisted: a fresh guard sees the new license without renewing.
	g2, err := NewGuard(GuardConfig{Keys: keys, Load: box.load, InstanceFP: "fp_me"})
	if err != nil {
		t.Fatal(err)
	}
	if s := g2.State(); s.Payload.LicID != "g2" {
		t.Errorf("renewed license was not persisted: %+v", s.Payload)
	}
}

func TestGuardRenewRefusedKeepsState(t *testing.T) {
	// Expired 1 day ago → grace; server refuses (e.g. revoked upstream).
	keys, _, box := guardFixture(t, 91*24*time.Hour, -24*time.Hour, "fp_me")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "license revoked"})
	}))
	defer srv.Close()

	g, err := NewGuard(GuardConfig{
		Keys: keys, Load: box.load, Store: box.store,
		RenewURL: srv.URL, InstanceFP: "fp_me",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := g.RenewNow()
	// Refused renewal never degrades below what the license justifies:
	// grace keeps gating as grace until it runs out naturally.
	if s.State != StateGrace {
		t.Fatalf("want grace, got %s", s.State)
	}
	// The failure surfaces in RenewErr (not Err), so a caller gating on Err
	// does not disable a still-valid license over a renew blip.
	if s.RenewErr == nil {
		t.Error("renew refusal must surface in RenewErr")
	}
	if s.Err != nil {
		t.Errorf("Err must stay nil for a still-valid license: %v", s.Err)
	}
}

func TestGuardNoRenewForPerpetual(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	keys := map[string]ed25519.PublicKey{"k1": pub}
	box := &licBox{text: makeLicense(t, priv, &Payload{
		LicID: "c1", Kid: "k1", Edition: "community",
		IssuedAt: time.Now().Add(-1000 * 24 * time.Hour).Unix(), ExpiresAt: 0,
	})}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("perpetual license must never hit the renew endpoint")
	}))
	defer srv.Close()

	g, err := NewGuard(GuardConfig{Keys: keys, Load: box.load, Store: box.store, RenewURL: srv.URL, InstanceFP: "fp_x"})
	if err != nil {
		t.Fatal(err)
	}
	if s := g.State(); s.State != StateValid {
		t.Fatalf("perpetual community license must be valid: %s", s.State)
	}
}
