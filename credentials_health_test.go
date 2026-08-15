package authstore

import (
	"testing"
)

// SetHealth has two branches and until now only one of them had ever run.
//
// Every call site in this repo — three in credentials.go, one in
// credentials_refresh_mode_test.go — passes success=false. Nothing, in
// production or in a test, has ever called SetHealth(id, true, ""). So the
// recovery half of the function was dead code: written, shipped, never
// executed. These tests execute it.
//
// That matters more than the usual "the other branch is untested", because of
// what error_count does. Resolve orders candidates by
// `ORDER BY priority ASC, error_count ASC`, and the failure branch increments
// error_count without bound. With no caller ever clearing it, a credential
// demoted by one transient failure stays demoted for the life of the row. The
// only other path that resets the counter is MarkReloginSuccess, which runs on
// an interactive re-login — so today the recorded fix for a temporary network
// error is for a human to log in again.
//
// Filed by the 201st nightly pass, 2026-08-15, working step 2 of noteboard card
// 25ac6a72-a5a0-4ada-b4a9-aeeb4e688177.

// apiKeyCredential builds a credential that needs no refresh, so a test can
// move health fields around without the refresh path having an opinion.
func apiKeyCredential(id string, priority int) Credentials {
	return Credentials{
		ID:          id,
		Provider:    "anthropic",
		AuthType:    AuthTypeAPIKey,
		RefreshMode: RefreshModeNone,
		APIKey:      "sk-ant-" + id,
		Priority:    priority,
		Enabled:     true,
	}
}

// TestSetHealthSuccessClearsTheFailureItRecordedEarlier is the direct inverse
// of the assertion the failure branch already had: what one call records, the
// other call must be able to undo.
func TestSetHealthSuccessClearsTheFailureItRecordedEarlier(t *testing.T) {
	store := newTestStore(t)
	mustSet(t, store, apiKeyCredential("cred_flaky", 100))

	store.SetHealth("cred_flaky", false, "connection reset")
	store.SetHealth("cred_flaky", false, "connection reset again")

	failed, err := store.Get("cred_flaky")
	if err != nil {
		t.Fatalf("get after failures: %v", err)
	}
	if failed.ErrorCount != 2 {
		t.Fatalf("error_count = %d after two failures, want 2", failed.ErrorCount)
	}
	if failed.LastError != "connection reset again" {
		t.Fatalf("last_error = %q, want the most recent message", failed.LastError)
	}

	store.SetHealth("cred_flaky", true, "")

	recovered, err := store.Get("cred_flaky")
	if err != nil {
		t.Fatalf("get after success: %v", err)
	}
	if recovered.ErrorCount != 0 {
		t.Errorf("error_count = %d after a success, want 0 — the counter must be resettable or a credential can only ever get worse", recovered.ErrorCount)
	}
	if recovered.LastError != "" {
		t.Errorf("last_error = %q after a success, want empty", recovered.LastError)
	}
	if recovered.LastUsedAt == 0 {
		t.Error("last_used_at is still 0 after a success; the success branch is documented to stamp it")
	}
}

// TestSetHealthSuccessIgnoresTheMessageArgument pins that errMsg is read only
// on the failure branch. A caller reporting a success with a non-empty message
// — a warning, say — must not have it stored as an error.
func TestSetHealthSuccessIgnoresTheMessageArgument(t *testing.T) {
	store := newTestStore(t)
	mustSet(t, store, apiKeyCredential("cred_noisy", 100))

	store.SetHealth("cred_noisy", true, "refreshed, but the token is short-lived")

	got, err := store.Get("cred_noisy")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.LastError != "" {
		t.Errorf("last_error = %q; a success must not store its message as an error", got.LastError)
	}
}

// TestSetHealthSuccessLeavesLastErrorAtStanding records a real asymmetry
// between this store's two recovery paths rather than asserting it is right.
//
// SetHealth(success) clears last_error and error_count but does NOT clear
// last_error_at. MarkReloginSuccess, the other recovery path, clears all
// three. So after a recovery through SetHealth a credential reports an empty
// error with a live timestamp saying when it happened — a state no reader can
// interpret, and one that only exists because the two paths disagree.
//
// This test pins current behaviour. If the asymmetry is ever resolved, this
// test is the thing that will notice, and its name says which way it went.
func TestSetHealthSuccessLeavesLastErrorAtStanding(t *testing.T) {
	store := newTestStore(t)
	mustSet(t, store, apiKeyCredential("cred_asymmetric", 100))

	store.SetHealth("cred_asymmetric", false, "boom")
	failed, err := store.Get("cred_asymmetric")
	if err != nil {
		t.Fatalf("get after failure: %v", err)
	}
	if failed.LastErrorAt == 0 {
		t.Fatal("last_error_at was not stamped by the failure branch")
	}

	store.SetHealth("cred_asymmetric", true, "")
	viaSetHealth, err := store.Get("cred_asymmetric")
	if err != nil {
		t.Fatalf("get after SetHealth success: %v", err)
	}
	if viaSetHealth.LastErrorAt == 0 {
		t.Fatal("SetHealth(success) now clears last_error_at; it did not when this test was written — the two recovery paths have converged, which is an improvement, and this test should be rewritten to assert that")
	}
	if viaSetHealth.LastError != "" {
		t.Fatalf("last_error = %q, want empty", viaSetHealth.LastError)
	}

	// The other recovery path, for contrast: it clears the timestamp too.
	if err := store.MarkReloginSuccess("cred_asymmetric"); err != nil {
		t.Fatalf("mark relogin success: %v", err)
	}
	viaRelogin, err := store.Get("cred_asymmetric")
	if err != nil {
		t.Fatalf("get after relogin: %v", err)
	}
	if viaRelogin.LastErrorAt != 0 {
		t.Errorf("last_error_at = %d after MarkReloginSuccess, want 0 — this is the path that does clear it, and the contrast with SetHealth is the point of this test", viaRelogin.LastErrorAt)
	}
}

// TestSetHealthSuccessRestoresARankLostToATransientFailure is why the dead
// branch is worth waking up.
//
// credentials_refresh_mode_test.go already pins the demotion: tie the
// priorities and the credential with recorded failures loses. It stops there.
// This is the other half — the recovery — and it is the half no production
// caller can currently reach.
func TestSetHealthSuccessRestoresARankLostToATransientFailure(t *testing.T) {
	store := newTestStore(t)
	// Same priority, so error_count is the only thing that can order them.
	// cred_first sorts before cred_second on id, but Resolve does not order by
	// id — with both counters at zero the row order is the query's to choose,
	// so the test drives the ranking entirely through error_count.
	mustSet(t, store, apiKeyCredential("cred_first", 100))
	mustSet(t, store, apiKeyCredential("cred_second", 100))

	// Demote cred_first. Now the ordering is unambiguous.
	store.SetHealth("cred_first", false, "timeout")

	demoted, err := store.Resolve(ResolveQuery{Provider: "anthropic"})
	if err != nil {
		t.Fatalf("resolve while demoted: %v", err)
	}
	if demoted.ID != "cred_second" {
		t.Fatalf("resolved %s, want cred_second — a recorded failure must lose a priority tie", demoted.ID)
	}

	// Demote cred_second harder, and recover cred_first. Only the success
	// branch can produce this ordering: without it cred_first is stuck at 1
	// and would need cred_second to reach 2 before it won again.
	store.SetHealth("cred_second", false, "timeout")
	store.SetHealth("cred_first", true, "")

	recovered, err := store.Resolve(ResolveQuery{Provider: "anthropic"})
	if err != nil {
		t.Fatalf("resolve after recovery: %v", err)
	}
	if recovered.ID != "cred_first" {
		t.Errorf("resolved %s, want cred_first — a credential that recovers must be able to win back its rank", recovered.ID)
	}
}
