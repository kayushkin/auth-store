package server

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	authstore "github.com/kayushkin/auth-store"
	"github.com/kayushkin/auth-store/internal/oauth"
)

// pendingFlow tracks an in-flight OAuth login between BeginLogin and the
// /oauth/callback handler.
type pendingFlow struct {
	provider     string
	credentialID string // pre-existing row to update, or "" for new
	owner        string // optional override (provider userinfo wins if available)
	label        string
	intendedApp  string
	intendedPurp string
	app          oauth.AppCredentials
	created      time.Time
}

// flowRegistry stores pending flows keyed by state. Lives on the Server.
type flowRegistry struct {
	mu      sync.Mutex
	pending map[string]*pendingFlow
}

func newFlowRegistry() *flowRegistry {
	return &flowRegistry{pending: make(map[string]*pendingFlow)}
}

func (r *flowRegistry) put(state string, f *pendingFlow) {
	r.mu.Lock()
	r.pending[state] = f
	r.mu.Unlock()
}

func (r *flowRegistry) take(state string) *pendingFlow {
	r.mu.Lock()
	defer r.mu.Unlock()
	f := r.pending[state]
	delete(r.pending, state)
	return f
}

func (r *flowRegistry) sweep(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	r.mu.Lock()
	defer r.mu.Unlock()
	for s, f := range r.pending {
		if f.created.Before(cutoff) {
			delete(r.pending, s)
		}
	}
}

type startLoginRequest struct {
	CredentialID    string `json:"credential_id,omitempty"`
	Owner           string `json:"owner,omitempty"`
	Account         string `json:"account,omitempty"`
	Label           string `json:"label,omitempty"`
	IntendedApp     string `json:"intended_app,omitempty"`
	IntendedPurpose string `json:"intended_purpose,omitempty"`
	ClientID        string `json:"client_id,omitempty"`
	ClientSecret    string `json:"client_secret,omitempty"`
	TenantID        string `json:"tenant_id,omitempty"`
	RedirectURL     string `json:"redirect_url,omitempty"`
	RefreshMode     string `json:"refresh_mode,omitempty"`
}

func (s *Server) handleStartOAuthLogin(w http.ResponseWriter, r *http.Request) {
	providerID := r.PathValue("provider")
	prov := s.cfg.Store.OAuthProvider(providerID)
	if prov == nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown OAuth provider %q", providerID))
		return
	}

	var in startLoginRequest
	if r.ContentLength > 0 {
		if err := decodeJSON(r, &in); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
	}

	// Resolve app credentials. Priority: explicit body > existing credential row.
	app := oauth.AppCredentials{
		ClientID:     in.ClientID,
		ClientSecret: in.ClientSecret,
		TenantID:     in.TenantID,
		RedirectURL:  in.RedirectURL,
	}
	if in.CredentialID != "" {
		existing, err := s.cfg.Store.Get(in.CredentialID)
		if err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		if app.ClientID == "" {
			app.ClientID = existing.ClientID
		}
		if app.ClientSecret == "" {
			app.ClientSecret = existing.ClientSecret
		}
		if app.TenantID == "" {
			app.TenantID = existing.TenantID
		}
		if app.RedirectURL == "" {
			app.RedirectURL = existing.RedirectURL
		}
	}
	if app.RedirectURL == "" {
		app.RedirectURL = s.cfg.CallbackURL
	}

	state := randomHex(16)
	res, err := prov.BeginLogin(r.Context(), app, state)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.flows.put(state, &pendingFlow{
		provider:     providerID,
		credentialID: in.CredentialID,
		owner:        in.Owner,
		label:        in.Label,
		intendedApp:  in.IntendedApp,
		intendedPurp: in.IntendedPurpose,
		app:          app,
		created:      time.Now(),
	})

	s.cfg.Store.LogAccess(authstore.AuditEntry{
		CredentialID: in.CredentialID,
		Provider:     providerID,
		App:          r.Header.Get("X-Auth-App"),
		Reason:       "oauth login start",
		Action:       authstore.AuditActionOAuthLogin,
		OK:           true,
		RemoteAddr:   remoteAddr(r),
	})

	writeJSON(w, http.StatusOK, map[string]string{
		"auth_url": res.AuthURL,
		"state":    state,
	})
}

func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	errParam := r.URL.Query().Get("error")
	if errParam != "" {
		writeError(w, http.StatusBadRequest, "provider error: "+errParam)
		return
	}
	if state == "" || code == "" {
		writeError(w, http.StatusBadRequest, "missing state or code")
		return
	}

	flow := s.flows.take(state)
	if flow == nil {
		writeError(w, http.StatusBadRequest, "unknown or expired state")
		return
	}
	prov := s.cfg.Store.OAuthProvider(flow.provider)
	if prov == nil {
		writeError(w, http.StatusInternalServerError, "provider gone")
		return
	}

	// Anthropic provider stores a per-state PKCE verifier; pass it through.
	verifier := ""
	if a, ok := prov.(*oauth.Anthropic); ok {
		verifier = a.VerifierFor(state)
	}

	tok, err := prov.CompleteLogin(r.Context(), flow.app, code, verifier)
	if err != nil {
		s.cfg.Store.LogAccess(authstore.AuditEntry{
			CredentialID: flow.credentialID,
			Provider:     flow.provider,
			App:          "oauth-callback",
			Reason:       "exchange failed",
			Action:       authstore.AuditActionOAuthCallback,
			OK:           false,
			Error:        err.Error(),
			RemoteAddr:   remoteAddr(r),
		})
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	owner := flow.owner
	if owner == "" {
		owner = tok.OwnerEmail
	}
	now := time.Now().UnixMilli()

	var stored *authstore.Credentials
	if flow.credentialID != "" {
		existing, err := s.cfg.Store.Get(flow.credentialID)
		if err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		existing.Token = tok.AccessToken
		if tok.RefreshToken != "" {
			existing.RefreshToken = tok.RefreshToken
		}
		existing.ExpiresAt = tok.ExpiresAtMs
		existing.LastRefreshedAt = now
		existing.AuthType = authstore.AuthTypeOAuth
		if existing.RefreshMode == "" {
			existing.RefreshMode = authstore.RefreshModeServer
		}
		if owner != "" && existing.Owner == "" {
			existing.Owner = owner
		}
		// Persist whatever app credentials the flow was started with so refresh
		// works without re-passing them.
		if flow.app.ClientID != "" {
			existing.ClientID = flow.app.ClientID
		}
		if flow.app.ClientSecret != "" {
			existing.ClientSecret = flow.app.ClientSecret
		}
		if flow.app.TenantID != "" {
			existing.TenantID = flow.app.TenantID
		}
		if flow.app.RedirectURL != "" {
			existing.RedirectURL = flow.app.RedirectURL
		}
		if err := s.cfg.Store.Set(*existing); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		stored = existing
	} else {
		c := authstore.Credentials{
			ID:              "cred_" + randomHex(12),
			Provider:        flow.provider,
			Owner:           owner,
			Label:           flow.label,
			IntendedApp:     flow.intendedApp,
			IntendedPurpose: flow.intendedPurp,
			AuthType:        authstore.AuthTypeOAuth,
			RefreshMode:     authstore.RefreshModeServer,
			Token:           tok.AccessToken,
			RefreshToken:    tok.RefreshToken,
			ExpiresAt:       tok.ExpiresAtMs,
			LastRefreshedAt: now,
			ClientID:        flow.app.ClientID,
			ClientSecret:    flow.app.ClientSecret,
			TenantID:        flow.app.TenantID,
			RedirectURL:     flow.app.RedirectURL,
			Priority:        100,
			Enabled:         true,
		}
		if err := s.cfg.Store.Set(c); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		stored = &c
	}

	s.cfg.Store.LogAccess(authstore.AuditEntry{
		CredentialID: stored.ID,
		Provider:     stored.Provider,
		Owner:        stored.Owner,
		App:          "oauth-callback",
		Reason:       "exchange ok",
		Action:       authstore.AuditActionOAuthCallback,
		OK:           true,
		RemoteAddr:   remoteAddr(r),
	})

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<!DOCTYPE html><html><body>
<h2>Authenticated with %s</h2>
<p>Owner: %s</p>
<p>Credential id: <code>%s</code></p>
<p>You can close this window.</p>
</body></html>`, stored.Provider, stored.Owner, stored.ID)
}
