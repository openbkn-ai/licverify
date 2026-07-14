package keys

import (
	"crypto/ed25519"
	"testing"
)

func TestOfficialTable(t *testing.T) {
	tbl := Official()
	if len(tbl) == 0 {
		t.Fatal("official key table is empty")
	}
	for kid, pub := range tbl {
		if kid == "" {
			t.Error("empty kid in table")
		}
		if len(pub) != ed25519.PublicKeySize {
			t.Errorf("kid %s: bad key size %d", kid, len(pub))
		}
	}
	if _, ok := tbl["key-01"]; !ok {
		t.Error("key-01 missing from official table")
	}
}

func TestOfficialReturnsCopy(t *testing.T) {
	a := Official()
	a["evil"] = make(ed25519.PublicKey, ed25519.PublicKeySize)
	if _, ok := Official()["evil"]; ok {
		t.Fatal("Official() must return a copy, not the shared map")
	}
}
