package server

import (
	"net/http"

	authstore "github.com/kayushkin/auth-store"
)

// credentialView is the wire-side projection of a credential. Secret material
// is masked unless the caller is reading via /resolve or holds a valid lease —
// those paths use the unmasked struct directly.
type credentialView struct {
	ID              string `json:"id"`
	Provider        string `json:"provider"`
	Owner           string `json:"owner,omitempty"`
	Account         string `json:"account,omitempty"`
	Label           string `json:"label,omitempty"`
	IntendedApp     string `json:"intended_app,omitempty"`
	IntendedPurpose string `json:"intended_purpose,omitempty"`
	AuthType        string `json:"auth_type"`
	RefreshMode     string `json:"refresh_mode"`
	APIKey          string `json:"api_key,omitempty"`
	Token           string `json:"token,omitempty"`
	HasRefreshToken bool   `json:"has_refresh_token"`
	ExpiresAt       int64  `json:"expires_at,omitempty"`
	BaseURL         string `json:"base_url,omitempty"`

	ClientID     string `json:"client_id,omitempty"`
	HasSecret    bool   `json:"has_client_secret"`
	TenantID     string `json:"tenant_id,omitempty"`
	RedirectURL  string `json:"redirect_url,omitempty"`

	Username string `json:"username,omitempty"`
	HasPassword bool `json:"has_password,omitempty"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	TLS      bool   `json:"tls,omitempty"`

	Leased         bool   `json:"leased"`
	LeaseHolderApp string `json:"lease_holder_app,omitempty"`
	LeaseExpiresAt int64  `json:"lease_expires_at,omitempty"`

	Priority        int    `json:"priority"`
	Enabled         bool   `json:"enabled"`
	LastUsedAt      int64  `json:"last_used_at,omitempty"`
	LastRefreshedAt int64  `json:"last_refreshed_at,omitempty"`
	LastError       string `json:"last_error,omitempty"`
	LastErrorAt     int64  `json:"last_error_at,omitempty"`
	ErrorCount      int    `json:"error_count,omitempty"`
	CreatedAt       string `json:"created_at,omitempty"`
}

func toView(c *authstore.Credentials) credentialView {
	return credentialView{
		ID:              c.ID,
		Provider:        c.Provider,
		Owner:           c.Owner,
		Account:         c.Account,
		Label:           c.Label,
		IntendedApp:     c.IntendedApp,
		IntendedPurpose: c.IntendedPurpose,
		AuthType:        c.AuthType,
		RefreshMode:     c.RefreshMode,
		APIKey:          authstore.MaskSecret(c.APIKey),
		Token:           authstore.MaskSecret(c.Token),
		HasRefreshToken: c.RefreshToken != "",
		ExpiresAt:       c.ExpiresAt,
		BaseURL:         c.BaseURL,
		ClientID:        c.ClientID,
		HasSecret:       c.ClientSecret != "",
		TenantID:        c.TenantID,
		RedirectURL:     c.RedirectURL,
		Username:        c.Username,
		HasPassword:     c.Password != "",
		Host:            c.Host,
		Port:            c.Port,
		TLS:             c.TLS,
		Leased:          c.IsLeased(),
		LeaseHolderApp:  c.LeaseHolderApp,
		LeaseExpiresAt:  c.LeaseExpiresAt,
		Priority:        c.Priority,
		Enabled:         c.Enabled,
		LastUsedAt:      c.LastUsedAt,
		LastRefreshedAt: c.LastRefreshedAt,
		LastError:       c.LastError,
		LastErrorAt:     c.LastErrorAt,
		ErrorCount:      c.ErrorCount,
		CreatedAt:       c.CreatedAt,
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	creds, err := s.cfg.Store.List(authstore.ListFilter{
		Provider:    q.Get("provider"),
		Owner:       q.Get("owner"),
		IntendedApp: q.Get("intended_app"),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	views := make([]credentialView, 0, len(creds))
	for i := range creds {
		views = append(views, toView(&creds[i]))
	}
	writeJSON(w, http.StatusOK, views)
}

func (s *Server) handleGetCredential(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	c, err := s.cfg.Store.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toView(c))
}

type credentialInput struct {
	ID              string `json:"id,omitempty"`
	Provider        string `json:"provider"`
	Owner           string `json:"owner"`
	Account         string `json:"account,omitempty"`
	Label           string `json:"label,omitempty"`
	IntendedApp     string `json:"intended_app,omitempty"`
	IntendedPurpose string `json:"intended_purpose,omitempty"`
	AuthType        string `json:"auth_type"`
	RefreshMode     string `json:"refresh_mode,omitempty"`
	APIKey          string `json:"api_key,omitempty"`
	Token           string `json:"token,omitempty"`
	RefreshToken    string `json:"refresh_token,omitempty"`
	ExpiresAt       int64  `json:"expires_at,omitempty"`
	BaseURL         string `json:"base_url,omitempty"`
	ClientID        string `json:"client_id,omitempty"`
	ClientSecret    string `json:"client_secret,omitempty"`
	TenantID        string `json:"tenant_id,omitempty"`
	RedirectURL     string `json:"redirect_url,omitempty"`
	Username        string `json:"username,omitempty"`
	Password        string `json:"password,omitempty"`
	Host            string `json:"host,omitempty"`
	Port            int    `json:"port,omitempty"`
	TLS             *bool  `json:"tls,omitempty"`
	Priority        int    `json:"priority,omitempty"`
	Enabled         *bool  `json:"enabled,omitempty"`
}

func (in *credentialInput) toCredentials() authstore.Credentials {
	c := authstore.Credentials{
		ID:              in.ID,
		Provider:        in.Provider,
		Owner:           in.Owner,
		Account:         in.Account,
		Label:           in.Label,
		IntendedApp:     in.IntendedApp,
		IntendedPurpose: in.IntendedPurpose,
		AuthType:        in.AuthType,
		RefreshMode:     in.RefreshMode,
		APIKey:          in.APIKey,
		Token:           in.Token,
		RefreshToken:    in.RefreshToken,
		ExpiresAt:       in.ExpiresAt,
		BaseURL:         in.BaseURL,
		ClientID:        in.ClientID,
		ClientSecret:    in.ClientSecret,
		TenantID:        in.TenantID,
		RedirectURL:     in.RedirectURL,
		Username:        in.Username,
		Password:        in.Password,
		Host:            in.Host,
		Port:            in.Port,
		Priority:        in.Priority,
		Enabled:         true,
	}
	if in.TLS != nil {
		c.TLS = *in.TLS
	} else {
		c.TLS = true
	}
	if in.Enabled != nil {
		c.Enabled = *in.Enabled
	}
	if c.RefreshMode == "" {
		c.RefreshMode = authstore.RefreshModeServer
	}
	if c.Priority == 0 {
		c.Priority = 100
	}
	return c
}

func (s *Server) handleCreateCredential(w http.ResponseWriter, r *http.Request) {
	var in credentialInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if in.Provider == "" {
		writeError(w, http.StatusBadRequest, "provider is required")
		return
	}
	if in.Owner == "" {
		writeError(w, http.StatusBadRequest, "owner is required")
		return
	}
	if in.AuthType == "" {
		writeError(w, http.StatusBadRequest, "auth_type is required")
		return
	}
	if in.ID == "" {
		in.ID = "cred_" + randomHex(12)
	}
	c := in.toCredentials()
	if err := s.cfg.Store.Set(c); err != nil {
		s.logCRUD(r, authstore.AuditActionCreate, in.ID, in.Provider, in.Owner, false, err.Error())
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	stored, err := s.cfg.Store.Get(c.ID)
	if err != nil {
		s.logCRUD(r, authstore.AuditActionCreate, c.ID, c.Provider, c.Owner, false, err.Error())
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logCRUD(r, authstore.AuditActionCreate, stored.ID, stored.Provider, stored.Owner, true, "")
	writeJSON(w, http.StatusCreated, toView(stored))
}

func (s *Server) handleUpdateCredential(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := s.cfg.Store.Get(id)
	if err != nil {
		s.logCRUD(r, authstore.AuditActionUpdate, id, "", "", false, err.Error())
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	var in credentialInput
	if err := decodeJSON(r, &in); err != nil {
		s.logCRUD(r, authstore.AuditActionUpdate, id, existing.Provider, existing.Owner, false, "invalid JSON: "+err.Error())
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	in.ID = id
	if in.Provider == "" {
		in.Provider = existing.Provider
	}
	if in.Owner == "" {
		in.Owner = existing.Owner
	}
	if in.AuthType == "" {
		in.AuthType = existing.AuthType
	}
	if in.RefreshMode == "" {
		in.RefreshMode = existing.RefreshMode
	}
	c := in.toCredentials()

	// Preserve secret fields when caller omits them (lets clients update label
	// without re-supplying credentials). Empty strings always overwrite.
	if c.APIKey == "" {
		c.APIKey = existing.APIKey
	}
	if c.Token == "" {
		c.Token = existing.Token
	}
	if c.RefreshToken == "" {
		c.RefreshToken = existing.RefreshToken
	}
	if c.ClientSecret == "" {
		c.ClientSecret = existing.ClientSecret
	}
	if c.Password == "" {
		c.Password = existing.Password
	}

	// Preserve metadata fields when caller omits them. Same rationale as
	// the secret preservation above: a partial update (e.g. dash UI sending
	// just {owner: "slava"}) must not silently zero the rest of the row.
	if c.Account == "" {
		c.Account = existing.Account
	}
	if c.Label == "" {
		c.Label = existing.Label
	}
	if c.IntendedApp == "" {
		c.IntendedApp = existing.IntendedApp
	}
	if c.IntendedPurpose == "" {
		c.IntendedPurpose = existing.IntendedPurpose
	}
	if c.ClientID == "" {
		c.ClientID = existing.ClientID
	}
	if c.TenantID == "" {
		c.TenantID = existing.TenantID
	}
	if c.RedirectURL == "" {
		c.RedirectURL = existing.RedirectURL
	}
	if c.BaseURL == "" {
		c.BaseURL = existing.BaseURL
	}
	if c.ExpiresAt == 0 {
		c.ExpiresAt = existing.ExpiresAt
	}

	// Lease state is never editable through this endpoint.
	c.LeaseID = existing.LeaseID
	c.LeaseHolderApp = existing.LeaseHolderApp
	c.LeaseExpiresAt = existing.LeaseExpiresAt
	c.LastUsedAt = existing.LastUsedAt
	c.LastRefreshedAt = existing.LastRefreshedAt
	c.LastError = existing.LastError
	c.LastErrorAt = existing.LastErrorAt
	c.ErrorCount = existing.ErrorCount

	if err := s.cfg.Store.Set(c); err != nil {
		s.logCRUD(r, authstore.AuditActionUpdate, id, c.Provider, c.Owner, false, err.Error())
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	stored, err := s.cfg.Store.Get(id)
	if err != nil {
		s.logCRUD(r, authstore.AuditActionUpdate, id, c.Provider, c.Owner, false, err.Error())
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logCRUD(r, authstore.AuditActionUpdate, stored.ID, stored.Provider, stored.Owner, true, "")
	writeJSON(w, http.StatusOK, toView(stored))
}

func (s *Server) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, _ := s.cfg.Store.Get(id) // best-effort, just for audit context
	if err := s.cfg.Store.Delete(id); err != nil {
		s.logCRUD(r, authstore.AuditActionDelete, id, "", "", false, err.Error())
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	provider, owner := "", ""
	if existing != nil {
		provider, owner = existing.Provider, existing.Owner
	}
	s.logCRUD(r, authstore.AuditActionDelete, id, provider, owner, true, "")
	w.WriteHeader(http.StatusNoContent)
}

// logCRUD records an audit entry for a credential mutation. CRUD routes use
// the `protected` middleware (bearer-only), so X-Auth-App / X-Auth-Reason
// are not enforced — the headers are best-effort and absent values appear
// blank in the audit trail. Errors are swallowed (writes to a separate
// table; we never want auditing failure to mask the API response).
func (s *Server) logCRUD(r *http.Request, action, credID, provider, owner string, ok bool, errMsg string) {
	app := r.Header.Get("X-Auth-App")
	reason := r.Header.Get("X-Auth-Reason")
	_ = s.cfg.Store.LogAccess(authstore.AuditEntry{
		CredentialID: credID,
		Provider:     provider,
		Owner:        owner,
		App:          app,
		Reason:       reason,
		Action:       action,
		OK:           ok,
		Error:        errMsg,
		RemoteAddr:   remoteAddr(r),
	})
}
