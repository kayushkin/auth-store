package authstore

import (
	"testing"
	"time"
)

// The lease protocol has a complete server half and no client anywhere on this
// box — measured 2026-08-14 across every repo and against the audit log, which
// holds 28,185 rows and not one lease action. Nothing else exercises any of
// this, so these tests are the only statement of what the protocol promises.
// They are deliberately a spec rather than a deletion: whether the design is
// superseded is the user's call, and an unwritten protocol cannot be judged.

func leasableCredential(id string) Credentials {
	return Credentials{
		ID:           id,
		Provider:     "anthropic",
		AuthType:     AuthTypeOAuth,
		RefreshMode:  RefreshModeClientLease,
		Token:        "leased-access-token",
		RefreshToken: "leased-refresh-token",
		ExpiresAt:    millisFromNow(1 * time.Hour),
		Priority:     100,
		Enabled:      true,
	}
}

func TestAcquireLeaseRefusesACredentialThatIsNotInClientLeaseMode(t *testing.T) {
	store := newTestStore(t)
	mustSet(t, store, expiredOAuthCredential("cred_server_mode", RefreshModeServer))

	if _, _, err := store.AcquireLease("cred_server_mode", "llm-bridge-server", time.Hour); err == nil {
		t.Fatal("acquired a lease on a server-mode credential, want refusal")
	}

	stored, err := store.Get("cred_server_mode")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if stored.LeaseID != "" || stored.IsLeased() {
		t.Errorf("refused acquire still stamped a lease: id=%q holder=%q", stored.LeaseID, stored.LeaseHolderApp)
	}
}

func TestAcquireLeaseGrantsExclusiveUseAndASecondAppIsRefused(t *testing.T) {
	store := newTestStore(t)
	mustSet(t, store, leasableCredential("cred_leased"))

	leaseID, expiresAt, err := store.AcquireLease("cred_leased", "llm-bridge-server", time.Hour)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if leaseID == "" {
		t.Fatal("acquire returned an empty lease id")
	}
	if expiresAt <= time.Now().UnixMilli() {
		t.Errorf("lease expires at %d, want a future time", expiresAt)
	}

	stored, err := store.Get("cred_leased")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !stored.IsLeased() {
		t.Error("credential does not report itself leased after a granted lease")
	}
	if stored.LeaseHolderApp != "llm-bridge-server" {
		t.Errorf("lease holder = %q, want llm-bridge-server", stored.LeaseHolderApp)
	}

	if _, _, err := store.AcquireLease("cred_leased", "some-other-app", time.Hour); err == nil {
		t.Error("a second app acquired a live lease, want refusal")
	}
	// The holder may re-acquire — a restarted client must be able to take its
	// own lease back rather than wait out the TTL.
	if _, _, err := store.AcquireLease("cred_leased", "llm-bridge-server", time.Hour); err != nil {
		t.Errorf("the lease holder could not re-acquire its own lease: %v", err)
	}
}

func TestALeaseStopsCountingOnceItsTTLHasPassed(t *testing.T) {
	store := newTestStore(t)
	mustSet(t, store, leasableCredential("cred_leased"))

	if _, _, err := store.AcquireLease("cred_leased", "llm-bridge-server", -1*time.Minute); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	stored, err := store.Get("cred_leased")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if stored.LeaseID == "" {
		t.Fatal("lease id was not stamped")
	}
	if stored.IsLeased() {
		t.Error("an elapsed lease still reports as leased")
	}
	if _, _, err := store.AcquireLease("cred_leased", "some-other-app", time.Hour); err != nil {
		t.Errorf("another app could not take over an elapsed lease: %v", err)
	}
}

func TestHeartbeatExtendsTheLeaseAndRequiresTheMatchingLeaseID(t *testing.T) {
	store := newTestStore(t)
	mustSet(t, store, leasableCredential("cred_leased"))

	leaseID, firstExpiry, err := store.AcquireLease("cred_leased", "llm-bridge-server", 1*time.Second)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	extended, err := store.HeartbeatLease("cred_leased", leaseID, time.Hour)
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if extended <= firstExpiry {
		t.Errorf("heartbeat moved the expiry to %d, want later than %d", extended, firstExpiry)
	}
	if _, err := store.HeartbeatLease("cred_leased", "not-the-lease-id", time.Hour); err == nil {
		t.Error("heartbeat accepted a mismatched lease id, want refusal")
	}
}

func TestWriteBackTokensRequiresTheLeaseAndRefusesAnExpiryThatDoesNotMoveForward(t *testing.T) {
	store := newTestStore(t)
	mustSet(t, store, leasableCredential("cred_leased"))
	original, err := store.Get("cred_leased")
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	if err := store.WriteBackTokens("cred_leased", "any-lease-id", "tok", "", millisFromNow(2*time.Hour)); err == nil {
		t.Error("write-back succeeded on an unleased credential, want refusal")
	}

	leaseID, _, err := store.AcquireLease("cred_leased", "llm-bridge-server", time.Hour)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if err := store.WriteBackTokens("cred_leased", "not-the-lease-id", "tok", "", millisFromNow(2*time.Hour)); err == nil {
		t.Error("write-back accepted a mismatched lease id, want refusal")
	}
	if err := store.WriteBackTokens("cred_leased", leaseID, "tok", "", original.ExpiresAt); err == nil {
		t.Error("write-back accepted an expiry equal to the stored one, want refusal")
	}

	newExpiry := millisFromNow(2 * time.Hour)
	if err := store.WriteBackTokens("cred_leased", leaseID, "client-refreshed-token", "", newExpiry); err != nil {
		t.Fatalf("write-back: %v", err)
	}
	stored, err := store.Get("cred_leased")
	if err != nil {
		t.Fatalf("get after write-back: %v", err)
	}
	if stored.Token != "client-refreshed-token" || stored.ExpiresAt != newExpiry {
		t.Errorf("stored token=%q expires_at=%d, want the written-back pair", stored.Token, stored.ExpiresAt)
	}
	if stored.RefreshToken != original.RefreshToken {
		t.Errorf("refresh token = %q, want the stored one kept when the write-back omits it", stored.RefreshToken)
	}
	if !stored.IsLeased() {
		t.Error("a mid-lease write-back ended the lease, want it held")
	}
}

func TestReleaseCarriesTheClientsFinalTokensBackAndEndsTheLease(t *testing.T) {
	store := newTestStore(t)
	mustSet(t, store, leasableCredential("cred_leased"))
	leaseID, _, err := store.AcquireLease("cred_leased", "llm-bridge-server", time.Hour)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	if err := store.ReleaseLease("cred_leased", "not-the-lease-id", "", "", 0); err == nil {
		t.Error("release accepted a mismatched lease id, want refusal")
	}

	finalExpiry := millisFromNow(3 * time.Hour)
	if err := store.ReleaseLease("cred_leased", leaseID, "final-access", "final-refresh", finalExpiry); err != nil {
		t.Fatalf("release: %v", err)
	}
	stored, err := store.Get("cred_leased")
	if err != nil {
		t.Fatalf("get after release: %v", err)
	}
	if stored.Token != "final-access" || stored.RefreshToken != "final-refresh" || stored.ExpiresAt != finalExpiry {
		t.Errorf("stored %q/%q/%d, want the final state the client handed back", stored.Token, stored.RefreshToken, stored.ExpiresAt)
	}
	if stored.LeaseID != "" || stored.LeaseHolderApp != "" || stored.LeaseExpiresAt != 0 {
		t.Errorf("release left lease state behind: id=%q holder=%q expires=%d", stored.LeaseID, stored.LeaseHolderApp, stored.LeaseExpiresAt)
	}
}

// Every final_* field on the release request is optional, so releasing without
// one is a supported shape — it means "I refreshed nothing, take the lease
// back". It must not be read as "erase the credential". WriteBackTokens
// already treats an omitted refresh_token that way, one function down.
func TestReleaseWithoutFinalTokensKeepsTheStoredCredentialIntact(t *testing.T) {
	store := newTestStore(t)
	mustSet(t, store, leasableCredential("cred_leased"))
	original, err := store.Get("cred_leased")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	leaseID, _, err := store.AcquireLease("cred_leased", "llm-bridge-server", time.Hour)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	if err := store.ReleaseLease("cred_leased", leaseID, "", "", 0); err != nil {
		t.Fatalf("release with no final state: %v", err)
	}

	stored, err := store.Get("cred_leased")
	if err != nil {
		t.Fatalf("get after release: %v", err)
	}
	if stored.Token != original.Token {
		t.Errorf("access token = %q, want the stored %q kept", stored.Token, original.Token)
	}
	if stored.RefreshToken != original.RefreshToken {
		t.Errorf("refresh token = %q, want the stored %q kept", stored.RefreshToken, original.RefreshToken)
	}
	if stored.ExpiresAt != original.ExpiresAt {
		t.Errorf("expires_at = %d, want the stored %d kept", stored.ExpiresAt, original.ExpiresAt)
	}
	if stored.IsLeased() {
		t.Error("the lease survived a release")
	}
}

// A final access token and a final expiry are one fact in two fields.
// WriteBackTokens requires both mid-lease; a release cannot be the loophole,
// or a client hands back a token that either never looks expired or inherits a
// lifetime it does not have.
func TestReleaseRefusesAFinalAccessTokenAndAFinalExpiryGivenApart(t *testing.T) {
	store := newTestStore(t)
	mustSet(t, store, leasableCredential("cred_leased"))
	original, err := store.Get("cred_leased")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	leaseID, _, err := store.AcquireLease("cred_leased", "llm-bridge-server", time.Hour)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	if err := store.ReleaseLease("cred_leased", leaseID, "final-access", "", 0); err == nil {
		t.Error("release accepted a final access token with no expiry, want refusal")
	}
	if err := store.ReleaseLease("cred_leased", leaseID, "", "", millisFromNow(3*time.Hour)); err == nil {
		t.Error("release accepted a final expiry with no access token, want refusal")
	}

	stored, err := store.Get("cred_leased")
	if err != nil {
		t.Fatalf("get after refusals: %v", err)
	}
	if stored.Token != original.Token || stored.ExpiresAt != original.ExpiresAt {
		t.Errorf("a refused release still wrote: token=%q expires_at=%d", stored.Token, stored.ExpiresAt)
	}
	if !stored.IsLeased() {
		t.Error("a refused release ended the lease")
	}
}

// Server-side refresh yields to a live lease: the holder is authoritative
// while it holds. This is the one lease check a caller can reach today, since
// Refresh does not look at refresh_mode.
func TestServerSideRefreshDeclinesACredentialThatIsCurrentlyLeased(t *testing.T) {
	store := newTestStore(t)
	provider := &recordingOAuthProvider{id: "anthropic"}
	store.RegisterOAuthProvider(provider)
	mustSet(t, store, leasableCredential("cred_leased"))
	if _, _, err := store.AcquireLease("cred_leased", "llm-bridge-server", time.Hour); err != nil {
		t.Fatalf("acquire: %v", err)
	}

	if err := store.Refresh("cred_leased"); err == nil {
		t.Error("server-side refresh ran against a leased credential, want refusal")
	}
	if provider.refreshCalls != 0 {
		t.Errorf("refresh calls = %d, want 0", provider.refreshCalls)
	}
}
