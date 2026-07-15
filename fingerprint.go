package licverify

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

// Instance fingerprinting (设备指纹) for one-shot activation binding.
//
// The algorithm is deliberately public: anti-copy enforcement does not rest
// on its secrecy but on the server side (first-wins activation, renewal
// binding check) and on the Ed25519 signature over the fingerprint embedded
// in the license. Raw hardware identifiers never leave the machine — only a
// salted hash does.
//
// Source precedence:
//  1. OPENBKN_INSTANCE_ID env — for clusters/containers, inject a stable
//     identity (e.g. the kube-system namespace UID) via deployment config.
//  2. OS machine id — /etc/machine-id (Linux), IOPlatformUUID (macOS),
//     MachineGuid (Windows). Stable across reboots and reinstalls of the
//     product; survives NIC/disk changes.
//  3. Physical MAC addresses (sorted) — last resort when no machine id
//     exists (minimal containers). Legitimate hardware changes that shift
//     the fingerprint are handled by the admin unbind flow, not by fuzzy
//     matching.

// EnvInstanceID overrides all hardware sources when set.
const EnvInstanceID = "OPENBKN_INSTANCE_ID"

const fpSalt = "openbkn-license-fp-v1"

var (
	ErrNoFingerprint       = errors.New("licverify: no stable instance identity found; set " + EnvInstanceID)
	ErrFingerprintMismatch = errors.New("licverify: license is bound to a different instance")
)

// Fingerprint computes this machine's instance fingerprint (fp_ + 16 hex).
// Deterministic per machine; different across machines and products with a
// different salt version.
func Fingerprint() (string, error) {
	if id := strings.TrimSpace(os.Getenv(EnvInstanceID)); id != "" {
		return FingerprintFrom("env:" + id), nil
	}
	if id, err := machineID(); err == nil && id != "" {
		return FingerprintFrom("mid:" + id), nil
	}
	if macs := physicalMACs(); len(macs) > 0 {
		return FingerprintFrom("mac:" + strings.Join(macs, ",")), nil
	}
	return "", ErrNoFingerprint
}

// FingerprintFrom derives a fingerprint from a caller-supplied stable
// identity (e.g. a cluster UID a product resolved itself).
func FingerprintFrom(identity string) string {
	sum := sha256.Sum256([]byte(fpSalt + "\x00" + identity))
	return "fp_" + hex.EncodeToString(sum[:8])
}

// VerifyBound checks an activated license against the local fingerprint.
// Licenses not yet bound (empty hw_fingerprint) pass — binding happens at
// activation. Returns ErrFingerprintMismatch for a copied license.
func VerifyBound(p *Payload, localFP string) error {
	if p.HWFingerprint == "" || p.HWFingerprint == localFP {
		return nil
	}
	return ErrFingerprintMismatch
}

// The base64 "activation code" wrapper (ActivationCode) was retired
// 2026-07-15: the offline flow pastes the raw device fingerprint from
// Fingerprint() into the license portal directly, and the portal no longer
// accepts the wrapped form.

func machineID() (string, error) {
	switch runtime.GOOS {
	case "linux":
		for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
			if b, err := os.ReadFile(p); err == nil {
				if id := strings.TrimSpace(string(b)); id != "" {
					return id, nil
				}
			}
		}
		return "", errors.New("no machine-id")
	case "darwin":
		out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
		if err != nil {
			return "", err
		}
		m := regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]+)"`).FindSubmatch(out)
		if m == nil {
			return "", errors.New("no IOPlatformUUID")
		}
		return string(m[1]), nil
	case "windows":
		out, err := exec.Command("reg", "query",
			`HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid").Output()
		if err != nil {
			return "", err
		}
		fields := strings.Fields(string(out))
		if len(fields) == 0 {
			return "", errors.New("no MachineGuid")
		}
		return fields[len(fields)-1], nil
	default:
		return "", fmt.Errorf("unsupported OS %s", runtime.GOOS)
	}
}

// physicalMACs returns non-loopback, non-virtual hardware addresses, sorted
// for determinism.
func physicalMACs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var macs []string
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 || len(i.HardwareAddr) == 0 {
			continue
		}
		name := strings.ToLower(i.Name)
		// Skip common virtual/ephemeral interfaces.
		if strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "docker") ||
			strings.HasPrefix(name, "br-") || strings.HasPrefix(name, "virbr") ||
			strings.HasPrefix(name, "utun") || strings.HasPrefix(name, "awdl") {
			continue
		}
		macs = append(macs, i.HardwareAddr.String())
	}
	sort.Strings(macs)
	return macs
}
