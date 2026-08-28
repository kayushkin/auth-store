package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	authstore "github.com/kayushkin/auth-store"
)

// auth-store is the credential vault every other service on this box reads from, and
// `toView` is the single funnel between a stored credential and the JSON the HTTP API
// serves. It masks `api_key` and `token`, and it answers `has_refresh_token`,
// `has_client_secret` and `has_password` instead of carrying those three at all.
//
// Nothing pinned any of that. Dropping either `authstore.MaskSecret(...)` call, or
// adding one more secret-bearing field to `credentialView`, served a live API key over
// HTTP and reddened nothing — the package had no test file.
//
// The assertions below are deliberately about the RESPONSE BODY rather than about
// `toView`'s return value. Four routes reach that funnel and a fifth deliberately does
// not mask; testing the function alone would leave every route unheld, which is the
// defect one level up. Scored by scripts/sabotage-credential-masking.py.

const (
	rawAPIKey       = "sk-live-APIKEYMATERIAL-eK4t"
	rawToken        = "ya29-ACCESSTOKENMATERIAL-7Qw2"
	rawRefreshToken = "1//REFRESHTOKENMATERIAL-mN8b"
	rawClientSecret = "GOCSPX-CLIENTSECRETMATERIAL-p3Xd"
	rawPassword     = "imap-PASSWORDMATERIAL-vR6s"
)

// everySecret is every field of authstore.Credentials that holds credential material.
// A response body containing any of these verbatim is a leak.
func everySecret() map[string]string {
	return map[string]string{
		"api_key":       rawAPIKey,
		"token":         rawToken,
		"refresh_token": rawRefreshToken,
		"client_secret": rawClientSecret,
		"password":      rawPassword,
	}
}

const testBearer = "test-bearer-token"

func newTestServer(t *testing.T) (*Server, *authstore.Store) {
	t.Helper()
	st, err := authstore.Open(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return New(Config{Store: st, AuthToken: testBearer}), st
}

func seedCredential(t *testing.T, st *authstore.Store, id string) {
	t.Helper()
	err := st.Set(authstore.Credentials{
		ID:           id,
		Provider:     "google",
		Owner:        "nightly-test",
		Account:      "default",
		AuthType:     authstore.AuthTypeOAuth,
		APIKey:       rawAPIKey,
		Token:        rawToken,
		RefreshToken: rawRefreshToken,
		ClientID:     "client-id-is-not-a-secret",
		ClientSecret: rawClientSecret,
		Username:     "someone@example.com",
		Password:     rawPassword,
		Enabled:      true,
		Priority:     100,
	})
	if err != nil {
		t.Fatalf("seed credential: %v", err)
	}
}

func do(t *testing.T, s *Server, method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set("Authorization", "Bearer "+testBearer)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

// The four routes that answer through toView must never put credential material on the
// wire, whichever verb reached it.
func TestCredentialRoutesNeverServeRawSecrets(t *testing.T) {
	createBody := `{"id":"cred_created","provider":"google","owner":"nightly-test",
		"auth_type":"oauth","api_key":"` + rawAPIKey + `","token":"` + rawToken + `",
		"refresh_token":"` + rawRefreshToken + `","client_secret":"` + rawClientSecret + `",
		"username":"someone@example.com","password":"` + rawPassword + `"}`
	updateBody := `{"api_key":"` + rawAPIKey + `","token":"` + rawToken + `",
		"refresh_token":"` + rawRefreshToken + `","client_secret":"` + rawClientSecret + `",
		"password":"` + rawPassword + `"}`

	routes := []struct {
		name, method, path, body string
		wantStatus               int
	}{
		{"list", "GET", "/api/credentials", "", http.StatusOK},
		{"get one", "GET", "/api/credentials/cred_seeded", "", http.StatusOK},
		{"create", "POST", "/api/credentials", createBody, http.StatusCreated},
		{"update", "PUT", "/api/credentials/cred_seeded", updateBody, http.StatusOK},
	}

	for _, rt := range routes {
		t.Run(rt.name, func(t *testing.T) {
			s, st := newTestServer(t)
			seedCredential(t, st, "cred_seeded")

			w := do(t, s, rt.method, rt.path, rt.body, nil)
			if w.Code != rt.wantStatus {
				t.Fatalf("%s %s: status %d, want %d\n%s",
					rt.method, rt.path, w.Code, rt.wantStatus, w.Body.String())
			}
			got := w.Body.String()

			for field, secret := range everySecret() {
				if strings.Contains(got, secret) {
					t.Errorf("%s %s served the raw %s.\nsecret: %q\nbody:\n%s",
						rt.method, rt.path, field, secret, got)
				}
			}

			// Absence alone is satisfied by an empty body, so the response has to
			// carry the masked form of the two fields that are meant to be shown.
			for _, want := range []string{
				authstore.MaskSecret(rawAPIKey),
				authstore.MaskSecret(rawToken),
			} {
				if !strings.Contains(got, want) {
					t.Errorf("%s %s did not carry the masked value %q.\nbody:\n%s",
						rt.method, rt.path, want, got)
				}
			}
		})
	}
}

// The three fields toView answers as booleans must stay booleans. A future field that
// carries one of them verbatim is the same leak arriving through the struct rather than
// through a dropped MaskSecret call, so assert the shape, not just the text.
func TestCredentialViewAnswersTheUnshownSecretsAsBooleans(t *testing.T) {
	s, st := newTestServer(t)
	seedCredential(t, st, "cred_seeded")

	w := do(t, s, "GET", "/api/credentials/cred_seeded", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var view map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// The wire names, which are not uniform: the struct fields are HasRefreshToken,
	// HasSecret and HasPassword, and their json tags are has_refresh_token,
	// has_client_secret and has_password. has_password additionally carries
	// `omitempty`, so it vanishes rather than reading false when unset — an
	// asymmetry noted here rather than pinned, because it is arguably the bug.
	for _, key := range []string{"has_refresh_token", "has_client_secret", "has_password"} {
		v, ok := view[key]
		if !ok {
			t.Errorf("%s missing from the view", key)
			continue
		}
		if b, isBool := v.(bool); !isBool {
			t.Errorf("%s is %T, want bool — a secret must not be reported by value", key, v)
		} else if !b {
			t.Errorf("%s is false, but the fixture set that secret — the view is answering "+
				"about the wrong field", key)
		}
	}
	for _, key := range []string{"refresh_token", "client_secret", "password"} {
		if _, present := view[key]; present {
			t.Errorf("%q is present in the view; these three are answered as has_* "+
				"booleans and must not be carried at all", key)
		}
	}
}

// The exception, stated rather than implied: /resolve exists to hand out the real
// secret, so masking everything is not the fix if the test above ever goes red.
func TestResolveDeliberatelyReturnsTheRealSecret(t *testing.T) {
	s, st := newTestServer(t)
	seedCredential(t, st, "cred_seeded")

	w := do(t, s, "GET", "/api/credentials/cred_seeded/resolve", "", map[string]string{
		"X-Auth-App":    "nightly-test",
		"X-Auth-Reason": "pinning the masking boundary",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if got := w.Body.String(); !strings.Contains(got, rawToken) {
		t.Errorf("/resolve did not return the real token; it is the one route that must.\nbody:\n%s", got)
	}
}

// The masking routes are behind bearer auth and the resolve route additionally behind
// app+reason. Without this, a mask that held would still not stop an unauthenticated
// reader reaching the endpoint at all.
func TestCredentialRoutesRefuseAnUnauthenticatedReader(t *testing.T) {
	s, st := newTestServer(t)
	seedCredential(t, st, "cred_seeded")

	for _, path := range []string{
		"/api/credentials",
		"/api/credentials/cred_seeded",
		"/api/credentials/cred_seeded/resolve",
	} {
		r := httptest.NewRequest("GET", path, nil) // no Authorization header
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("GET %s without a bearer token: status %d, want 401\n%s",
				path, w.Code, w.Body.String())
		}
	}
}
