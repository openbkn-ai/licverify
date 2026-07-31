package licverify

import (
	"errors"
	"net"
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

// A Pod's eth0 carries a locally administered address minted at Pod start, so
// a fingerprint derived from it changes on every Pod rebuild and silently
// invalidates an activated license.
func TestDurableMACRejectsEphemeral(t *testing.T) {
	cases := []struct {
		name string
		mac  string
		want bool
	}{
		{"eth0", "c2:2f:a3:86:52:c4", false}, // Kubernetes Pod interface
		{"eth0", "52:54:00:12:34:56", false}, // KVM/QEMU virtio
		{"vethabc123", "aa:bb:cc:dd:ee:ff", false},
		{"docker0", "02:42:ac:11:00:02", false},
		{"eth0", "00:00:00:00:00:00", false},
		{"eno1", "00:1a:2b:3c:4d:5e", true}, // OUI-assigned, burned in
		{"eth0", "3c:22:fb:01:02:03", true}, // minimal container on bare metal
	}
	for _, c := range cases {
		hw, err := net.ParseMAC(c.mac)
		if err != nil {
			t.Fatal(err)
		}
		if got := durableMAC(c.name, hw); got != c.want {
			t.Errorf("durableMAC(%q, %s) = %v, want %v", c.name, c.mac, got, c.want)
		}
	}
	if durableMAC("eth0", nil) {
		t.Error("interface without an address must be refused")
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
