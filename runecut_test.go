package authstore

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// The fixtures below are chosen so that the cut lands INSIDE a rune. A fixture
// whose rune widths happen to divide the budget lands the cut on a boundary and
// passes against the very code it was written to condemn, so each straddling
// case asserts a value the byte cut cannot produce.

// The fixture is 16 bytes: "sk" + U+20AC (3 bytes) + "middle" + U+1F600
// (4 bytes) + "z". Byte 4 — where the 4-byte prefix cut falls — is a
// continuation byte of U+20AC, and byte len-4 is a continuation byte of
// U+1F600, so the unrepaired MaskSecret splits a rune at BOTH ends. The two
// guards below fail loudly if a later edit lands either cut on a boundary.
func TestMaskSecretNeverSplitsARuneAtEitherCut(t *testing.T) {
	const secret = "sk€middle\U0001F600z"

	if len(secret) <= 12 {
		t.Fatalf("fixture is only %d bytes, so MaskSecret returns all-stars and the cut is never reached", len(secret))
	}
	if utf8.RuneStart(secret[4]) {
		t.Fatalf("fixture does not straddle the PREFIX cut: byte 4 (%#x) starts a rune, so this test would pass against the byte cut", secret[4])
	}
	if utf8.RuneStart(secret[len(secret)-4]) {
		t.Fatalf("fixture does not straddle the SUFFIX cut: byte len-4 (%#x) starts a rune, so this test would pass against the byte cut", secret[len(secret)-4])
	}

	got := MaskSecret(secret)

	if !utf8.ValidString(got) {
		t.Errorf("MaskSecret(%q) = %q, which is not valid UTF-8", secret, got)
	}
	if strings.ContainsRune(got, utf8.RuneError) {
		t.Errorf("MaskSecret(%q) = %q, which carries U+FFFD", secret, got)
	}
	// The byte cut would return "sk\xe2\x82...\x9f\x98\x80z". Dropping the two
	// partial runes leaves the prefix and suffix short of their budgets, which
	// is the intended trade: a shorter hint over an invalid one.
	if want := "sk...z"; got != want {
		t.Errorf("MaskSecret(%q) = %q, want %q", secret, got, want)
	}
}

// TestMaskSecretIsUnchangedWhenTheCutsAreAlreadyAligned is the known-negative
// control. Every provider key format on this box is ASCII, so this is the case
// that actually runs in production, and the repair must not move it.
func TestMaskSecretIsUnchangedWhenTheCutsAreAlreadyAligned(t *testing.T) {
	const secret = "sk-ant-api03-abcdefgh"

	if got, want := MaskSecret(secret), "sk-a...efgh"; got != want {
		t.Errorf("MaskSecret(%q) = %q, want %q", secret, got, want)
	}
}

func TestMaskSecretStarsOutAShortSecretWithoutCutting(t *testing.T) {
	for _, secret := range []string{"", "short", "€€€€"} {
		got := MaskSecret(secret)
		if got != strings.Repeat("*", len(secret)) {
			t.Errorf("MaskSecret(%q) = %q, want %d stars", secret, got, len(secret))
		}
	}
}

// TestMaskSecretSlidesAFourByteRuneAcrossThePrefixCut walks a 4-byte rune
// through every offset around the prefix budget. At the offsets where it
// straddles, the byte cut yields invalid UTF-8; at the offsets where it does
// not, both implementations agree. Sliding is what proves the guard is the
// boundary walk and not one lucky fixture.
func TestMaskSecretSlidesAFourByteRuneAcrossThePrefixCut(t *testing.T) {
	straddled := 0
	for lead := 0; lead < 8; lead++ {
		secret := strings.Repeat("a", lead) + "\U0001F600" + strings.Repeat("b", 16)
		got := MaskSecret(secret)

		if !utf8.ValidString(got) {
			t.Errorf("lead=%d: MaskSecret(%q) = %q, which is not valid UTF-8", lead, secret, got)
		}
		if !utf8.RuneStart(secret[4]) {
			straddled++
		}
	}
	// Offsets 1, 2 and 3 put a continuation byte at index 4.
	if straddled != 3 {
		t.Fatalf("the slide straddled the prefix cut %d times, want 3 — the fixture no longer exercises the defect", straddled)
	}
}

func TestSuffixAtRuneBoundaryDropsThePartialRuneRatherThanOverrunTheBudget(t *testing.T) {
	cases := []struct {
		in       string
		maxBytes int
		want     string
	}{
		{"abc\U0001F600", 4, "\U0001F600"}, // aligned: the whole rune fits exactly
		{"abc\U0001F600", 3, ""},           // straddles: no whole rune fits in 3 bytes
		{"ab\U0001F600cd", 4, "cd"},        // walks forward past 3 continuation bytes
		{"abcdef", 0, ""},
		{"abcdef", -1, ""},
		{"ab", 9, "ab"}, // budget longer than the string
	}
	for _, c := range cases {
		if got := SuffixAtRuneBoundary(c.in, c.maxBytes); got != c.want {
			t.Errorf("SuffixAtRuneBoundary(%q, %d) = %q, want %q", c.in, c.maxBytes, got, c.want)
		}
	}
}

func TestTruncateAtRuneBoundaryDropsThePartialRune(t *testing.T) {
	cases := []struct {
		in       string
		maxBytes int
		want     string
	}{
		{"\U0001F600abc", 4, "\U0001F600"},
		{"\U0001F600abc", 3, ""},
		{"ab\U0001F600", 4, "ab"},
		{"abcdef", 0, ""},
		{"abcdef", -1, ""},
		{"ab", 9, "ab"},
	}
	for _, c := range cases {
		if got := TruncateAtRuneBoundary(c.in, c.maxBytes); got != c.want {
			t.Errorf("TruncateAtRuneBoundary(%q, %d) = %q, want %q", c.in, c.maxBytes, got, c.want)
		}
	}
}
