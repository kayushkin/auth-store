// Package oauth contains OAuth provider plugins for auth-store.
//
// Each provider implements the Provider interface; auth-store wires them up at
// startup and uses them for both interactive login (BeginLogin/CompleteLogin)
// and server-side refresh of stored tokens (Refresh).
package oauth

import (
	"context"
)

// AppCredentials carries the OAuth app-level credentials (client_id, etc.)
// that an OAuth provider needs in order to drive a flow. These come from the
// stored credential row in auth-store, not from environment variables.
type AppCredentials struct {
	ClientID     string
	ClientSecret string
	TenantID     string
	RedirectURL  string
}

// LoginResult is what BeginLogin returns. State is opaque server-side
// bookkeeping; the auth-store callback handler uses it to look up the
// pending flow.
type LoginResult struct {
	AuthURL      string
	State        string
	CodeVerifier string // PKCE; empty if provider doesn't use PKCE
	// Manual is true for out-of-band flows where the provider displays the
	// authorization code to the user instead of redirecting back to our
	// callback (e.g. Anthropic's console copy/paste page). The caller must
	// collect the pasted code and submit it to the /complete endpoint.
	Manual bool
}

// TokenResult is what CompleteLogin and Refresh return.
type TokenResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresAtMs  int64
	OwnerEmail   string // optional; populated when provider exposes a userinfo endpoint
}

// Provider is the OAuth plugin interface.
type Provider interface {
	// ID is the provider identifier (e.g. "anthropic", "google", "microsoft").
	ID() string

	// BeginLogin starts an OAuth flow and returns the URL to send the user to.
	// state is the opaque state token the server mints; the provider must
	// embed it in the auth URL so the callback can correlate.
	BeginLogin(ctx context.Context, app AppCredentials, state string) (LoginResult, error)

	// CompleteLogin exchanges the authorization code for tokens.
	// codeVerifier is the PKCE verifier from BeginLogin (empty for non-PKCE providers).
	CompleteLogin(ctx context.Context, app AppCredentials, code, codeVerifier string) (TokenResult, error)

	// Refresh exchanges a refresh_token for a new access_token (and possibly a
	// new refresh_token).
	Refresh(ctx context.Context, app AppCredentials, refreshToken string) (TokenResult, error)
}
