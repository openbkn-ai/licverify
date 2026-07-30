// Copyright openbkn.ai
//
// Licensed under the OpenBKN License. See LICENSE-OPENBKN.txt in the project root.

package licverify

import (
	"encoding/json"
	"testing"
)

func TestEditionLadderContainsLowerTiers(t *testing.T) {
	// Every tier satisfies itself and everything below it. This is the whole
	// point of AtLeast: the customer who paid more never loses a capability.
	all := []Edition{EditionCommunity, EditionProfessional, EditionEnterprise, EditionIndustry}
	for i, have := range all {
		for j, min := range all {
			want := i >= j
			if got := have.AtLeast(min); got != want {
				t.Errorf("%s.AtLeast(%s) = %v, want %v", have, min, got, want)
			}
		}
	}
}

func TestUnknownEditionBehavesAsCommunity(t *testing.T) {
	// A binary that predates a newly-issued tier must not hand out paid
	// capability on a value it cannot interpret.
	future := Edition("galactic")

	if !future.AtLeast(EditionCommunity) {
		t.Error("an unknown tier should still clear the community bar")
	}
	for _, paid := range []Edition{EditionProfessional, EditionEnterprise, EditionIndustry} {
		if future.AtLeast(paid) {
			t.Errorf("an unknown tier must not satisfy %s", paid)
		}
	}
	if future.Known() {
		t.Error("Known() should report that this build does not recognise the tier")
	}
	// The raw value survives, so an operator sees what the license says rather
	// than a silently normalised "community".
	if string(future) != "galactic" {
		t.Error("the unrecognised value must not be rewritten")
	}
}

func TestEmptyEditionIsCommunity(t *testing.T) {
	// A license with no edition field, or a zero-value Payload, must not
	// accidentally clear a paid bar.
	var missing Edition
	if !missing.AtLeast(EditionCommunity) {
		t.Error("the zero value should behave as community")
	}
	if missing.AtLeast(EditionProfessional) {
		t.Error("the zero value must not satisfy a paid tier")
	}
}

func TestEditionRoundTripsThroughJSON(t *testing.T) {
	// Payload.Edition changed from string to Edition; the wire format must not
	// change, or every already-signed license would stop parsing.
	const raw = `{"lic_id":"a","kid":"k1","edition":"enterprise"}`

	var p Payload
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.Edition != EditionEnterprise {
		t.Fatalf("Edition = %q, want %q", p.Edition, EditionEnterprise)
	}

	out, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	if back["edition"] != "enterprise" {
		t.Fatalf("edition serialised as %v, want the bare string", back["edition"])
	}
}
