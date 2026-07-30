// Copyright openbkn.ai
//
// Licensed under the OpenBKN License. See LICENSE-OPENBKN.txt in the project root.

package licverify

// Edition is the licensed tier. It is the single thing products gate on:
// a paid capability declares the lowest tier that may use it, and the check is
// always "is the current edition at least that tier".
//
// The tiers are ordered and each contains the ones below it:
//
//	community ⊂ professional ⊂ enterprise ⊂ industry
//
// The authoritative dictionary is license-server docs/design/license-service.md
// §1.5; the constants here mirror it. A value that has been signed into a
// customer's license is a permanent API — removing one makes an existing
// customer's capability vanish.
//
// The vocabulary and its ordering live here rather than in the product because
// a license is what defines them. Products import this type; nobody redefines
// the ladder locally, where two services could disagree about whether industry
// outranks enterprise.
type Edition string

const (
	EditionCommunity    Edition = "community"
	EditionProfessional Edition = "professional"
	EditionEnterprise   Edition = "enterprise"
	EditionIndustry     Edition = "industry"
)

// rank orders the tiers. Anything unrecognised ranks with community: a binary
// that predates a newly-issued tier must not hand out paid capability on a
// value it cannot interpret, and refusing to parse the license instead would
// take the whole deployment down over a vocabulary it does not know yet.
//
// This is deliberately not an error: Verify keeps the raw string in the
// Payload, so an operator still sees what the license actually says.
func (e Edition) rank() int {
	switch e {
	case EditionProfessional:
		return 1
	case EditionEnterprise:
		return 2
	case EditionIndustry:
		return 3
	default:
		return 0
	}
}

// AtLeast reports whether e is min or a tier above it. This is the comparison
// every gated call site makes.
//
// It is AtLeast rather than equality because equality strands the customer who
// paid the most: an industry-tier license would fail `== enterprise` and lose
// the enterprise capabilities it contains. It also keeps each new tier from
// forcing an edit of every existing check.
func (e Edition) AtLeast(min Edition) bool { return e.rank() >= min.rank() }

// Known reports whether e is one of the tiers this build understands. Gating
// never needs it — unknown already behaves as community — but an operator
// surface can use it to say "this license names a tier this version predates"
// instead of silently showing community.
func (e Edition) Known() bool {
	switch e {
	case EditionCommunity, EditionProfessional, EditionEnterprise, EditionIndustry:
		return true
	default:
		return false
	}
}
