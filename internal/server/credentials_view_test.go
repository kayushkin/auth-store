package server

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	authstore "github.com/kayushkin/auth-store"
)

// jsonEscapedReplacementChar is what encoding/json actually writes for an
// invalid UTF-8 byte: the six ASCII characters of the \ufffd escape, NOT the
// encoded U+FFFD rune. Spelled here as a raw literal so the distinction
// survives an editor that would otherwise normalise one into the other.
const jsonEscapedReplacementChar = `\u` + `fffd`

// This is the CALL-SITE test, and it exists because a test of MaskSecret alone
// would pass against the byte cut for any input whose masked halves are never
// marshalled. toView is what puts the masked value on the wire: encoding/json
// substitutes U+FFFD for invalid UTF-8 rather than returning an error, so a
// split rune leaves :8303 serving a replacement character with nothing failing
// anywhere along the path. The assertion is on the marshalled bytes, not on the
// helper's return value.
func TestToViewServesMaskedSecretsAsValidUTF8OverTheWire(t *testing.T) {
	// Both fields straddle: byte 4 falls inside U+20AC and byte len-4 falls
	// inside U+1F600.
	const straddling = "sk€middle\U0001F600z"

	if utf8.RuneStart(straddling[4]) || utf8.RuneStart(straddling[len(straddling)-4]) {
		t.Fatalf("fixture no longer straddles both cuts, so this test would pass against the byte cut")
	}

	view := toView(&authstore.Credentials{
		ID:       "cred-1",
		Provider: "anthropic",
		AuthType: "api_key",
		APIKey:   straddling,
		Token:    straddling,
	})

	if view.APIKey == straddling || view.Token == straddling {
		t.Fatalf("toView served the secret unmasked: APIKey=%q Token=%q", view.APIKey, view.Token)
	}

	body, err := json.Marshal(view)
	if err != nil {
		t.Fatalf("json.Marshal(view): %v", err)
	}
	// ⚠️ Assert on the ESCAPE, not on the rune. encoding/json emits invalid
	// UTF-8 as the six-character sequence \ufffd rather than as the encoded
	// U+FFFD, so `strings.ContainsRune(body, utf8.RuneError)` is an assertion
	// that cannot fail here — it reads as coverage and is not. Measured against
	// the unrepaired byte cut: the body really is {"api_key":"sk\ufffd\ufffd..."}.
	if strings.Contains(string(body), jsonEscapedReplacementChar) {
		t.Errorf("the credential view carries U+FFFD on the wire: %s", body)
	}

	var round credentialView
	if err := json.Unmarshal(body, &round); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if round.APIKey != view.APIKey {
		t.Errorf("api_key did not survive the round trip: sent %q, read back %q", view.APIKey, round.APIKey)
	}
	if round.Token != view.Token {
		t.Errorf("token did not survive the round trip: sent %q, read back %q", view.Token, round.Token)
	}
}

// The known-negative control: every provider key format on this box is ASCII,
// so this is the path that actually runs, and the repair must leave it alone.
func TestToViewLeavesAnASCIIKeyMaskedExactlyAsBefore(t *testing.T) {
	view := toView(&authstore.Credentials{
		APIKey: "sk-ant-api03-abcdefgh",
		Token:  "ya29.a0AfH6SMBxxxxxxxxyyyy",
	})

	if got, want := view.APIKey, "sk-a...efgh"; got != want {
		t.Errorf("api_key = %q, want %q", got, want)
	}
	if got, want := view.Token, "ya29...yyyy"; got != want {
		t.Errorf("token = %q, want %q", got, want)
	}
}
