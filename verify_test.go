package licverify

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func makeLicense(t *testing.T, priv ed25519.PrivateKey, p *Payload) string {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, b)
	return "v1." + base64.RawURLEncoding.EncodeToString(b) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestVerifyRoundtrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	p := &Payload{
		LicID: "abc", Kid: "k1", Edition: "pro",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
		Features: []string{"sso"}, Limits: map[string]int64{"max_users": 5},
	}
	text := makeLicense(t, priv, p)
	keys := map[string]ed25519.PublicKey{"k1": pub}

	got, err := VerifyAt(text, keys, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !got.HasFeature("sso") || got.HasFeature("audit") {
		t.Error("feature check wrong")
	}
	if got.Limit("max_users") != 5 || got.Limit("missing") != 0 {
		t.Error("limit check wrong")
	}
}

func TestVerifyRejects(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	base := &Payload{LicID: "x", Kid: "k1", IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix()}
	keys := map[string]ed25519.PublicKey{"k1": pub}

	cases := []struct {
		name string
		text string
		want error
	}{
		{"garbage", "not-a-license", ErrMalformed},
		{"wrong key", makeLicense(t, otherPriv, base), ErrBadSig},
		{"unknown kid", makeLicense(t, priv, &Payload{LicID: "x", Kid: "nope", ExpiresAt: base.ExpiresAt}), ErrUnknownKey},
	}
	for _, c := range cases {
		if _, err := VerifyAt(c.text, keys, now); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}

	expired := makeLicense(t, priv, &Payload{LicID: "x", Kid: "k1", IssuedAt: now.Add(-2 * time.Hour).Unix(), ExpiresAt: now.Add(-time.Hour).Unix()})
	if _, err := VerifyAt(expired, keys, now); !errors.Is(err, ErrExpired) {
		t.Errorf("expired: got %v", err)
	}
	// Tampered payload: flip edition inside a validly structured license.
	tampered := makeLicense(t, priv, base)
	parts := []byte(tampered)
	_ = parts
	bad := "v1." + base64.RawURLEncoding.EncodeToString([]byte(`{"lic_id":"x","kid":"k1","edition":"enterprise"}`)) + "." + splitSig(tampered)
	if _, err := VerifyAt(bad, keys, now); !errors.Is(err, ErrBadSig) {
		t.Errorf("tampered: got %v", err)
	}
}

func TestPerpetualLicenseNeverExpires(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	// Community convention: expires_at = 0 means never expires.
	p := &Payload{LicID: "c", Kid: "k1", Edition: "community", IssuedAt: now.Unix(), ExpiresAt: 0}
	text := makeLicense(t, priv, p)
	keys := map[string]ed25519.PublicKey{"k1": pub}

	if _, err := VerifyAt(text, keys, now.Add(100*365*24*time.Hour)); err != nil {
		t.Fatalf("perpetual license must verify far in the future: %v", err)
	}
	if state, _ := EvalAt(text, keys, now.Add(100*365*24*time.Hour)); state != StateValid {
		t.Errorf("perpetual eval = %s", state)
	}
}

func TestEvalGraceCappedByContract(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	keys := map[string]ed25519.PublicKey{"k1": pub}
	// Contract-end shape: the last license has ExpiresAt == ContractExpiresAt.
	exp := now.Add(-24 * time.Hour).Unix()
	text := makeLicense(t, priv, &Payload{
		LicID: "e", Kid: "k1", Edition: "professional",
		IssuedAt: now.Add(-90 * 24 * time.Hour).Unix(), ExpiresAt: exp, ContractExpiresAt: exp,
	})
	// One day past a contract-end expiry: NO grace — straight to fallback,
	// matching the server's DeriveState (this is the #5 divergence fix).
	if state, _ := EvalAt(text, keys, now); state != StateFallback {
		t.Errorf("past contract end must be fallback, got %s", state)
	}
	// A mid-contract expiry (contract still ahead) keeps the grace window.
	text2 := makeLicense(t, priv, &Payload{
		LicID: "e2", Kid: "k1", Edition: "professional",
		IssuedAt: now.Add(-90 * 24 * time.Hour).Unix(), ExpiresAt: exp,
		ContractExpiresAt: now.Add(200 * 24 * time.Hour).Unix(),
	})
	if state, _ := EvalAt(text2, keys, now); state != StateGrace {
		t.Errorf("mid-contract expiry must be grace, got %s", state)
	}
}

func TestEvalStates(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	keys := map[string]ed25519.PublicKey{"k1": pub}
	commercial := makeLicense(t, priv, &Payload{
		LicID: "e", Kid: "k1", Edition: "professional",
		IssuedAt: now.Add(-48 * time.Hour).Unix(), ExpiresAt: now.Add(-24 * time.Hour).Unix(),
	})

	// Expired yesterday: inside the 30-day grace window, features stay on.
	if state, _ := EvalAt(commercial, keys, now); state != StateGrace {
		t.Errorf("in grace: got %s", state)
	}
	// Beyond grace: signature still proves the instance was once licensed,
	// so the product falls back to the community capability set.
	if state, p := EvalAt(commercial, keys, now.Add(GracePeriod+24*time.Hour)); state != StateFallback || p == nil {
		t.Errorf("beyond grace: got %s", state)
	}
	// Garbage never falls back — only a valid signature earns it.
	if state, _ := EvalAt("v1.bogus.bogus", keys, now); state != StateInvalid {
		t.Errorf("garbage: got %s", state)
	}
}

func splitSig(text string) string {
	for i := len(text) - 1; i >= 0; i-- {
		if text[i] == '.' {
			return text[i+1:]
		}
	}
	return ""
}
