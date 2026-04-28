package server

import (
	"net/http"

	authstore "github.com/kayushkin/auth-store"
)

// resolvedView is the response for /resolve. Contains the live access token /
// API key. For credentials in client_lease mode that are currently leased,
// returns the last known access_token with leased=true so callers know it may
// be stale; the lease holder is the authoritative source.
type resolvedView struct {
	ID           string `json:"id"`
	Provider     string `json:"provider"`
	Owner        string `json:"owner,omitempty"`
	Account      string `json:"account,omitempty"`
	Label        string `json:"label,omitempty"`
	AuthType     string `json:"auth_type"`
	RefreshMode  string `json:"refresh_mode"`
	AccessToken  string `json:"access_token,omitempty"`
	APIKey       string `json:"api_key,omitempty"`
	Password     string `json:"password,omitempty"`
	Username     string `json:"username,omitempty"`
	Host         string `json:"host,omitempty"`
	Port         int    `json:"port,omitempty"`
	TLS          bool   `json:"tls,omitempty"`
	BaseURL      string `json:"base_url,omitempty"`
	ExpiresAt    int64  `json:"expires_at,omitempty"`
	Leased       bool   `json:"leased"`
	IntendedApp  string `json:"intended_app,omitempty"`
}

func toResolved(c *authstore.Credentials) resolvedView {
	v := resolvedView{
		ID:          c.ID,
		Provider:    c.Provider,
		Owner:       c.Owner,
		Account:     c.Account,
		Label:       c.Label,
		AuthType:    c.AuthType,
		RefreshMode: c.RefreshMode,
		BaseURL:     c.BaseURL,
		ExpiresAt:   c.ExpiresAt,
		Leased:      c.IsLeased(),
		IntendedApp: c.IntendedApp,
	}
	switch c.AuthType {
	case authstore.AuthTypeAPIKey:
		v.APIKey = c.APIKey
	case authstore.AuthTypeOAuth, authstore.AuthTypeToken:
		v.AccessToken = c.Token
	case authstore.AuthTypePassword:
		v.Username = c.Username
		v.Password = c.Password
		v.Host = c.Host
		v.Port = c.Port
		v.TLS = c.TLS
	}
	return v
}

func (s *Server) handleResolveByID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	app := appFromCtx(r.Context())
	reason := reasonFromCtx(r.Context())

	c, err := s.cfg.Store.ResolveByID(id)
	if err != nil {
		s.cfg.Store.LogAccess(authstore.AuditEntry{
			CredentialID: id,
			App:          app,
			Reason:       reason,
			Action:       authstore.AuditActionResolve,
			OK:           false,
			Error:        err.Error(),
			RemoteAddr:   remoteAddr(r),
		})
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	s.cfg.Store.LogAccess(authstore.AuditEntry{
		CredentialID:     c.ID,
		Provider:         c.Provider,
		Owner:            c.Owner,
		App:              app,
		Reason:           reason,
		Action:           authstore.AuditActionResolve,
		OK:               true,
		IntendedAppMatch: c.IntendedApp == "" || c.IntendedApp == app,
		RemoteAddr:       remoteAddr(r),
	})

	writeJSON(w, http.StatusOK, toResolved(c))
}

func (s *Server) handleResolveByProvider(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	app := appFromCtx(r.Context())
	reason := reasonFromCtx(r.Context())
	intendedApp := r.URL.Query().Get("intended_app")
	if intendedApp == "" {
		intendedApp = app
	}

	c, err := s.cfg.Store.Resolve(provider, intendedApp)
	if err != nil {
		// Try again without the intended_app filter; the request may be a
		// cross-app use which is allowed but flagged.
		c, err = s.cfg.Store.Resolve(provider, "")
		if err != nil {
			s.cfg.Store.LogAccess(authstore.AuditEntry{
				Provider:   provider,
				App:        app,
				Reason:     reason,
				Action:     authstore.AuditActionResolve,
				OK:         false,
				Error:      err.Error(),
				RemoteAddr: remoteAddr(r),
			})
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
	}

	s.cfg.Store.LogAccess(authstore.AuditEntry{
		CredentialID:     c.ID,
		Provider:         c.Provider,
		Owner:            c.Owner,
		App:              app,
		Reason:           reason,
		Action:           authstore.AuditActionResolve,
		OK:               true,
		IntendedAppMatch: c.IntendedApp == "" || c.IntendedApp == app,
		RemoteAddr:       remoteAddr(r),
	})

	writeJSON(w, http.StatusOK, toResolved(c))
}
