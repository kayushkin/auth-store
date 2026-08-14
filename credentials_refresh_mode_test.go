package authstore

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kayushkin/auth-store/internal/oauth"
)

// These are the first tests for the credential store. They pin the one rule
// that decides whether a stored OAuth token is ever refreshed — refresh_mode —
// and the lease protocol that "client_lease" hands the job to. The lease
// protocol has a server half and no client on this box, so nothing else
// exercises any of it; see the write-up filed 2026-08-14 by the nightly worker.

// recordingOAuthProvider stands in for a real provider so a refresh can be
// observed without a network call. It counts calls, which is what makes
// "auth-store refreshed nothing" an assertion rather than an absence.
type recordingOAuthProvider struct {
	id           string
	refreshCalls int
	lastRefresh  string
	issue        oauth.TokenResult
}

func (p *recordingOAuthProvider) ID() string { return p.id }

func (p *recordingOAuthProvider) BeginLogin(context.Context, oauth.AppCredentials, string) (oauth.LoginResult, error) {
	return oauth.LoginResult{}, nil
}

func (p *recordingOAuthProvider) CompleteLogin(context.Context, oauth.AppCredentials, string, string, string) (oauth.TokenResult, error) {
	return p.issue, nil
}

func (p *recordingOAuthProvider) Refresh(_ context.Context, _ oauth.AppCredentials, refreshToken string) (oauth.TokenResult, error) {
	p.refreshCalls++
	p.lastRefresh = refreshToken
	return p.issue, nil
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func millisFromNow(d time.Duration) int64 {
	return time.Now().Add(d).UnixMilli()
}

// expiredOAuthCredential builds an OAuth credential whose access token expired
// an hour ago, in the given refresh mode.
func expiredOAuthCredential(id, refreshMode string) Credentials {
	return Credentials{
		ID:           id,
		Provider:     "anthropic",
		AuthType:     AuthTypeOAuth,
		RefreshMode:  refreshMode,
		Token:        "stale-access-token",
		RefreshToken: "the-refresh-token",
		ExpiresAt:    millisFromNow(-1 * time.Hour),
		Priority:     100,
		Enabled:      true,
	}
}

func mustSet(t *testing.T, store *Store, c Credentials) {
	t.Helper()
	if err := store.Set(c); err != nil {
		t.Fatalf("set %s: %v", c.ID, err)
	}
}

// The control: server mode is the only mode in which auth-store refreshes
// anything, and it does. Without this, every "nothing was refreshed" assertion
// below could pass because the refresh machinery is broken or unwired.
func TestServerModeRefreshesAnExpiredOAuthCredentialWhenItIsResolved(t *testing.T) {
	store := newTestStore(t)
	provider := &recordingOAuthProvider{
		id: "anthropic",
		issue: oauth.TokenResult{
			AccessToken:  "fresh-access-token",
			RefreshToken: "rotated-refresh-token",
			ExpiresAtMs:  millisFromNow(1 * time.Hour),
		},
	}
	store.RegisterOAuthProvider(provider)
	mustSet(t, store, expiredOAuthCredential("cred_server_mode", RefreshModeServer))

	resolved, err := store.ResolveByID("cred_server_mode")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if provider.refreshCalls != 1 {
		t.Fatalf("refresh calls = %d, want 1", provider.refreshCalls)
	}
	if provider.lastRefresh != "the-refresh-token" {
		t.Errorf("refreshed with %q, want the stored refresh token", provider.lastRefresh)
	}
	if resolved.Token != "fresh-access-token" {
		t.Errorf("resolved token = %q, want the freshly issued one", resolved.Token)
	}

	stored, err := store.Get("cred_server_mode")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if stored.Token != "fresh-access-token" || stored.RefreshToken != "rotated-refresh-token" {
		t.Errorf("stored token/%s refresh/%s, want both replaced by the refresh result", stored.Token, stored.RefreshToken)
	}
	if stored.LastRefreshedAt == 0 {
		t.Error("last_refreshed_at is 0, want the refresh stamped")
	}
}

// The finding. A client_lease credential is refreshed by auth-store never, by
// design — the lease holder is supposed to do it. No lease holder exists on
// this box, so the expired token is handed out as-is and no error says so.
func TestClientLeaseModeHandsOutTheExpiredTokenAndCallsNoProvider(t *testing.T) {
	store := newTestStore(t)
	provider := &recordingOAuthProvider{
		id:    "anthropic",
		issue: oauth.TokenResult{AccessToken: "fresh-access-token", ExpiresAtMs: millisFromNow(1 * time.Hour)},
	}
	store.RegisterOAuthProvider(provider)
	mustSet(t, store, expiredOAuthCredential("cred_client_lease", RefreshModeClientLease))

	resolved, err := store.ResolveByID("cred_client_lease")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if provider.refreshCalls != 0 {
		t.Fatalf("refresh calls = %d, want 0 — client_lease means auth-store must not refresh", provider.refreshCalls)
	}
	if resolved.Token != "stale-access-token" {
		t.Errorf("resolved token = %q, want the stale stored one", resolved.Token)
	}
	if !resolved.IsExpired() {
		t.Error("resolved credential reports itself unexpired, want expired")
	}
	// The one signal a caller could act on says nothing is wrong: leased is
	// false because no client ever acquired a lease.
	if resolved.IsLeased() {
		t.Error("credential reports leased, want not leased — nothing acquires leases on this box")
	}
}

// Resolve-by-provider takes the same path, so the gate is not something a
// caller can route around by asking for a provider instead of an id.
func TestClientLeaseModeIsAlsoNotRefreshedWhenResolvedByProvider(t *testing.T) {
	store := newTestStore(t)
	provider := &recordingOAuthProvider{
		id:    "anthropic",
		issue: oauth.TokenResult{AccessToken: "fresh-access-token", ExpiresAtMs: millisFromNow(1 * time.Hour)},
	}
	store.RegisterOAuthProvider(provider)
	mustSet(t, store, expiredOAuthCredential("cred_client_lease", RefreshModeClientLease))

	resolved, err := store.Resolve(ResolveQuery{Provider: "anthropic"})
	if err != nil {
		t.Fatalf("resolve by provider: %v", err)
	}
	if provider.refreshCalls != 0 {
		t.Fatalf("refresh calls = %d, want 0", provider.refreshCalls)
	}
	if resolved.Token != "stale-access-token" {
		t.Errorf("resolved token = %q, want the stale stored one", resolved.Token)
	}
}

// expires_at = 0 means "no stored expiry", and IsExpired reads that as fresh
// forever. The one client_lease credential in the live store is in exactly this
// state, so it cannot even be detected as stale, let alone refreshed.
func TestAnOAuthCredentialWithNoStoredExpiryIsNeverConsideredExpired(t *testing.T) {
	c := &Credentials{AuthType: AuthTypeOAuth, ExpiresAt: 0}
	if c.IsExpired() {
		t.Error("expires_at=0 reports expired, want not expired")
	}
	c.ExpiresAt = millisFromNow(-1 * time.Millisecond)
	if !c.IsExpired() {
		t.Error("a past expires_at reports unexpired, want expired")
	}
}

// Nothing in resolution prefers a credential auth-store can refresh. Ranking is
// priority then error_count, full stop — so a lower priority number on an
// un-refreshable client_lease credential beats a healthy API key. Callers that
// believe otherwise (llm-bridge-server's pickAnthropicKey says it prefers
// api_key creds, "no refresh dance") are believing something no code implements.
func TestResolveRanksByPriorityAloneAndNeverPrefersAnAPIKeyCredential(t *testing.T) {
	store := newTestStore(t)
	mustSet(t, store, Credentials{
		ID: "cred_api_key", Provider: "anthropic", AuthType: AuthTypeAPIKey,
		RefreshMode: RefreshModeNone, APIKey: "sk-ant-api-key", Priority: 100, Enabled: true,
	})
	leaseCred := expiredOAuthCredential("cred_client_lease", RefreshModeClientLease)
	leaseCred.Priority = 50
	mustSet(t, store, leaseCred)

	resolved, err := store.Resolve(ResolveQuery{Provider: "anthropic"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.ID != "cred_client_lease" {
		t.Fatalf("resolved %s, want cred_client_lease — a lower priority number wins whatever the auth type", resolved.ID)
	}

	// And error_count is the only other ranking input: tie the priorities and
	// the credential with recorded failures loses.
	leaseCred.Priority = 100
	mustSet(t, store, leaseCred)
	store.SetHealth("cred_client_lease", false, "boom")

	resolved, err = store.Resolve(ResolveQuery{Provider: "anthropic"})
	if err != nil {
		t.Fatalf("resolve after health failure: %v", err)
	}
	if resolved.ID != "cred_api_key" {
		t.Errorf("resolved %s, want cred_api_key — error_count breaks a priority tie", resolved.ID)
	}
}

// intended_app narrows a resolution but does not require a match: a credential
// that names no app stays eligible for every app.
func TestResolveAcceptsACredentialWhoseIntendedAppIsEmptyOrEqual(t *testing.T) {
	store := newTestStore(t)
	mustSet(t, store, Credentials{
		ID: "cred_unclaimed", Provider: "anthropic", AuthType: AuthTypeAPIKey,
		RefreshMode: RefreshModeNone, APIKey: "sk-unclaimed", Priority: 100, Enabled: true,
	})
	mustSet(t, store, Credentials{
		ID: "cred_for_bridge", Provider: "anthropic", AuthType: AuthTypeAPIKey,
		RefreshMode: RefreshModeNone, APIKey: "sk-bridge", IntendedApp: "llm-bridge-server",
		Priority: 50, Enabled: true,
	})

	resolved, err := store.Resolve(ResolveQuery{Provider: "anthropic", IntendedApp: "llm-bridge-server"})
	if err != nil {
		t.Fatalf("resolve for the named app: %v", err)
	}
	if resolved.ID != "cred_for_bridge" {
		t.Errorf("resolved %s, want cred_for_bridge", resolved.ID)
	}

	resolved, err = store.Resolve(ResolveQuery{Provider: "anthropic", IntendedApp: "some-other-app"})
	if err != nil {
		t.Fatalf("resolve for another app: %v", err)
	}
	if resolved.ID != "cred_unclaimed" {
		t.Errorf("resolved %s, want cred_unclaimed — a credential bound to another app is excluded", resolved.ID)
	}
}
