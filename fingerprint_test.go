package licverify

import (
	"errors"
	"regexp"
	"testing"
)

func TestFingerprintFromDeterministic(t *testing.T) {
	a := FingerprintFrom("cluster-uid-123")
	b := FingerprintFrom("cluster-uid-123")
	c := FingerprintFrom("cluster-uid-456")
	if a != b {
		t.Error("same identity must yield same fingerprint")
	}
	if a == c {
		t.Error("different identities must yield different fingerprints")
	}
	if !regexp.MustCompile(`^fp_[0-9a-f]{16}$`).MatchString(a) {
		t.Errorf("bad format: %s", a)
	}
}

func TestFingerprintEnvOverride(t *testing.T) {
	t.Setenv(EnvInstanceID, "k8s-ns-uid-999")
	got, err := Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if got != FingerprintFrom("env:k8s-ns-uid-999") {
		t.Error("env identity must take precedence")
	}
}

func TestFingerprintLocalMachine(t *testing.T) {
	t.Setenv(EnvInstanceID, "")
	fp, err := Fingerprint()
	if err != nil {
		// Minimal environments may expose no stable identity at all.
		if !errors.Is(err, ErrNoFingerprint) {
			t.Fatal(err)
		}
		t.Skip("no stable identity on this host")
	}
	again, err := Fingerprint()
	if err != nil || fp != again {
		t.Errorf("fingerprint must be stable: %s vs %s (%v)", fp, again, err)
	}
}

func TestVerifyBound(t *testing.T) {
	if err := VerifyBound(&Payload{HWFingerprint: ""}, "fp_local"); err != nil {
		t.Error("unbound license must pass")
	}
	if err := VerifyBound(&Payload{HWFingerprint: "fp_local"}, "fp_local"); err != nil {
		t.Error("matching binding must pass")
	}
	if err := VerifyBound(&Payload{HWFingerprint: "fp_other"}, "fp_local"); !errors.Is(err, ErrFingerprintMismatch) {
		t.Error("copied license must be rejected")
	}
}
