package authstore

import "unicode/utf8"

// Cutting a Go string at a fixed byte offset splits whatever rune straddles
// that offset, and the result is not valid UTF-8. Nothing reports it:
// encoding/json substitutes U+FFFD rather than returning an error, so a reader
// of :8303 sees a replacement character and no error is raised anywhere along
// the path.
//
// These two functions carry the semantics settled on for the fleet unicode
// byte-cut sweep. The canonical pair is tool-store's schema.TruncateAtRuneBoundary
// and schema.SuffixAtRuneBoundary; auth-store keeps a local copy rather than
// importing tool-store, because a shared 20-line helper is not worth a module
// dependency from the credential vault to the tool registry. The names and the
// behaviour are the canonical ones so the two copies cannot drift apart
// silently.
//
// The walk costs at most three byte comparisons and allocates nothing, which is
// why it is preferred here over converting to []rune.

// TruncateAtRuneBoundary returns the longest prefix of s that is no longer than
// maxBytes and does not end part-way through a multi-byte UTF-8 sequence.
func TruncateAtRuneBoundary(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	// s[cut] is the first byte past the prefix. While it is a continuation
	// byte, a rune straddles the cut, so move the cut earlier.
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// SuffixAtRuneBoundary returns the longest suffix of s that is no longer than
// maxBytes and does not begin part-way through a multi-byte UTF-8 sequence.
//
// This is the other half of the defect and it walks the opposite way. A prefix
// cut leaves the leading bytes of a straddling rune at the end of the result;
// a suffix cut leaves its trailing continuation bytes at the start. Walking
// back would lengthen the suffix past its budget, so the cut moves forward and
// drops the partial rune.
func SuffixAtRuneBoundary(s string, maxBytes int) string {
	if maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	// s[cut] is the first byte of the suffix. While it is a continuation
	// byte, a rune straddles the cut, so move the cut later.
	cut := len(s) - maxBytes
	for cut < len(s) && !utf8.RuneStart(s[cut]) {
		cut++
	}
	return s[cut:]
}
