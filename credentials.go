package authstore

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// credentialColumns is the canonical column list used for SELECT queries.
const credentialColumns = `
	id, provider, owner, account, label,
	intended_app, intended_purpose,
	auth_type, refresh_mode,
	api_key, token, refresh_token, expires_at,
	base_url, client_id, client_secret, tenant_id, redirect_url,
	username, password, host, port, tls,
	lease_id, lease_holder_app, lease_expires_at,
	priority, enabled,
	last_used_at, last_refreshed_at,
	last_error, last_error_at, error_count, created_at`

// Set stores or updates a credential.
func (s *Store) Set(c Credentials) error {
	if c.ID == "" {
		return fmt.Errorf("credential ID is required")
	}
	if c.Provider == "" {
		return fmt.Errorf("credential provider is required")
	}
	if c.RefreshMode == "" {
		c.RefreshMode = RefreshModeServer
	}
	enabled := 0
	if c.Enabled {
		enabled = 1
	}
	tls := 0
	if c.TLS {
		tls = 1
	}
	_, err := s.db.Exec(`
		INSERT INTO credentials
			(id, provider, owner, account, label,
			 intended_app, intended_purpose,
			 auth_type, refresh_mode,
			 api_key, token, refresh_token, expires_at,
			 base_url, client_id, client_secret, tenant_id, redirect_url,
			 username, password, host, port, tls,
			 lease_id, lease_holder_app, lease_expires_at,
			 priority, enabled,
			 last_used_at, last_refreshed_at,
			 last_error, last_error_at, error_count)
		VALUES (?, ?, ?, ?, ?,
		        ?, ?,
		        ?, ?,
		        ?, ?, ?, ?,
		        ?, ?, ?, ?, ?,
		        ?, ?, ?, ?, ?,
		        ?, ?, ?,
		        ?, ?,
		        ?, ?,
		        ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			provider = excluded.provider,
			owner = excluded.owner,
			account = excluded.account,
			label = excluded.label,
			intended_app = excluded.intended_app,
			intended_purpose = excluded.intended_purpose,
			auth_type = excluded.auth_type,
			refresh_mode = excluded.refresh_mode,
			api_key = excluded.api_key,
			token = excluded.token,
			refresh_token = excluded.refresh_token,
			expires_at = excluded.expires_at,
			base_url = excluded.base_url,
			client_id = excluded.client_id,
			client_secret = excluded.client_secret,
			tenant_id = excluded.tenant_id,
			redirect_url = excluded.redirect_url,
			username = excluded.username,
			password = excluded.password,
			host = excluded.host,
			port = excluded.port,
			tls = excluded.tls,
			priority = excluded.priority,
			enabled = excluded.enabled`,
		c.ID, c.Provider, c.Owner, c.Account, c.Label,
		c.IntendedApp, c.IntendedPurpose,
		c.AuthType, c.RefreshMode,
		c.APIKey, c.Token, c.RefreshToken, c.ExpiresAt,
		c.BaseURL, c.ClientID, c.ClientSecret, c.TenantID, c.RedirectURL,
		c.Username, c.Password, c.Host, c.Port, tls,
		c.LeaseID, c.LeaseHolderApp, c.LeaseExpiresAt,
		c.Priority, enabled,
		c.LastUsedAt, c.LastRefreshedAt,
		c.LastError, c.LastErrorAt, c.ErrorCount,
	)
	return err
}

// Get returns a credential by id.
func (s *Store) Get(id string) (*Credentials, error) {
	rows, err := s.db.Query(`SELECT `+credentialColumns+` FROM credentials WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, fmt.Errorf("credential %q not found", id)
	}
	return scanCredential(rows)
}

// Resolve returns the best available credential for a provider, applying
// server-mode refresh if needed. Pass an empty intendedApp to skip filtering.
func (s *Store) Resolve(provider string, intendedApp string) (*Credentials, error) {
	q := `SELECT ` + credentialColumns + ` FROM credentials WHERE provider = ? AND enabled = 1`
	args := []any{provider}
	if intendedApp != "" {
		q += ` AND (intended_app = '' OR intended_app = ?)`
		args = append(args, intendedApp)
	}
	q += ` ORDER BY priority ASC, error_count ASC`

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("querying credentials for %s: %w", provider, err)
	}
	defer rows.Close()

	var candidates []*Credentials
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			continue
		}
		candidates = append(candidates, c)
	}
	rows.Close()

	for _, c := range candidates {
		if err := s.maybeRefresh(c); err != nil {
			s.SetHealth(c.ID, false, err.Error())
			continue
		}
		now := time.Now().UnixMilli()
		s.db.Exec(`UPDATE credentials SET last_used_at = ? WHERE id = ?`, now, c.ID)
		return c, nil
	}

	return nil, fmt.Errorf("no credentials for provider %s", provider)
}

// ResolveByID returns a single credential by id, applying server-mode refresh if needed.
func (s *Store) ResolveByID(id string) (*Credentials, error) {
	c, err := s.Get(id)
	if err != nil {
		return nil, err
	}
	if !c.Enabled {
		return nil, fmt.Errorf("credential %s is disabled", id)
	}
	if err := s.maybeRefresh(c); err != nil {
		s.SetHealth(c.ID, false, err.Error())
		return nil, err
	}
	now := time.Now().UnixMilli()
	s.db.Exec(`UPDATE credentials SET last_used_at = ? WHERE id = ?`, now, c.ID)
	return c, nil
}

// maybeRefresh applies server-mode refresh logic if the credential is OAuth,
// expired, in server mode, and not currently leased.
func (s *Store) maybeRefresh(c *Credentials) error {
	if c.AuthType != AuthTypeOAuth {
		return nil
	}
	if c.RefreshMode != RefreshModeServer {
		return nil
	}
	if c.IsLeased() {
		return nil
	}
	if !c.IsExpired() {
		return nil
	}

	mu := s.refreshMutex(c.ID)
	mu.Lock()
	defer mu.Unlock()

	// Re-read after acquiring the lock — another goroutine may have refreshed.
	fresh, err := s.Get(c.ID)
	if err != nil {
		return err
	}
	if !fresh.IsExpired() {
		*c = *fresh
		return nil
	}

	if err := s.refreshOAuthCredential(fresh); err != nil {
		return err
	}
	*c = *fresh
	return nil
}

// ResolveForModel resolves credentials for a model ID.
// Checks model_credentials first for model-specific bindings, then falls back to provider-level.
func (s *Store) ResolveForModel(modelID string, providerLookup func(modelID string) (string, error)) (*Credentials, error) {
	rows, err := s.db.Query(`
		SELECT `+credentialColumns+`
		FROM credentials c
		JOIN model_credentials mc ON c.id = mc.credential_id
		WHERE mc.model_id = ? AND c.enabled = 1
		ORDER BY mc.priority ASC, c.error_count ASC`,
		modelID,
	)
	if err == nil {
		var modelCandidates []*Credentials
		for rows.Next() {
			c, scanErr := scanCredential(rows)
			if scanErr != nil {
				continue
			}
			modelCandidates = append(modelCandidates, c)
		}
		rows.Close()

		for _, c := range modelCandidates {
			if err := s.maybeRefresh(c); err != nil {
				s.SetHealth(c.ID, false, err.Error())
				continue
			}
			now := time.Now().UnixMilli()
			s.db.Exec(`UPDATE credentials SET last_used_at = ? WHERE id = ?`, now, c.ID)
			return c, nil
		}
	}

	provider, err := providerLookup(modelID)
	if err != nil {
		return nil, err
	}
	return s.Resolve(provider, "")
}

// ListFilter narrows a List() call.
type ListFilter struct {
	Provider    string
	Owner       string
	IntendedApp string
}

// List lists credentials matching the filter (all if filter is zero).
func (s *Store) List(f ListFilter) ([]Credentials, error) {
	q := `SELECT ` + credentialColumns + ` FROM credentials WHERE 1=1`
	var args []any
	if f.Provider != "" {
		q += ` AND provider = ?`
		args = append(args, f.Provider)
	}
	if f.Owner != "" {
		q += ` AND owner = ?`
		args = append(args, f.Owner)
	}
	if f.IntendedApp != "" {
		q += ` AND intended_app = ?`
		args = append(args, f.IntendedApp)
	}
	q += ` ORDER BY provider, priority ASC, label`

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []Credentials
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			continue
		}
		creds = append(creds, *c)
	}
	return creds, nil
}

// Delete removes a credential by ID.
func (s *Store) Delete(id string) error {
	s.db.Exec(`DELETE FROM model_credentials WHERE credential_id = ?`, id)
	res, err := s.db.Exec(`DELETE FROM credentials WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("credential %q not found", id)
	}
	return nil
}

// SetEnabled enables or disables a credential by ID.
func (s *Store) SetEnabled(id string, enabled bool) error {
	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	res, err := s.db.Exec(`UPDATE credentials SET enabled = ? WHERE id = ?`, enabledInt, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("credential %q not found", id)
	}
	return nil
}

// SetHealth updates health tracking fields for a credential.
func (s *Store) SetHealth(id string, success bool, errMsg string) {
	now := time.Now().UnixMilli()
	if success {
		s.db.Exec(`UPDATE credentials SET last_error = '', error_count = 0, last_used_at = ? WHERE id = ?`, now, id)
	} else {
		s.db.Exec(`UPDATE credentials SET last_error = ?, last_error_at = ?, error_count = error_count + 1 WHERE id = ?`,
			errMsg, now, id)
	}
}

// ActiveKey returns the usable key/token from a credential based on its auth_type.
func ActiveKey(cred *Credentials) string {
	if cred == nil {
		return ""
	}
	switch cred.AuthType {
	case AuthTypeAPIKey:
		return cred.APIKey
	case AuthTypeOAuth, AuthTypeToken:
		return cred.Token
	case AuthTypePassword:
		return cred.Password
	default:
		return ""
	}
}

// ForModel returns credentials available for a specific model.
func (s *Store) ForModel(modelID, provider string) ([]Credentials, error) {
	rows, err := s.db.Query(`
		SELECT `+credentialColumns+`
		FROM credentials c
		JOIN model_credentials mc ON c.id = mc.credential_id
		WHERE mc.model_id = ?
		ORDER BY mc.priority ASC, c.priority ASC`,
		modelID,
	)
	if err != nil {
		return nil, err
	}

	var creds []Credentials
	for rows.Next() {
		c, scanErr := scanCredential(rows)
		if scanErr != nil {
			continue
		}
		creds = append(creds, *c)
	}
	rows.Close()

	if len(creds) > 0 {
		return creds, nil
	}

	return s.List(ListFilter{Provider: provider})
}

// BindModel creates a model-specific credential binding.
func (s *Store) BindModel(modelID, credentialID string, priority int) error {
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO model_credentials (model_id, credential_id, priority)
		VALUES (?, ?, ?)`, modelID, credentialID, priority)
	return err
}

// UnbindModel removes a model-specific credential binding.
func (s *Store) UnbindModel(modelID, credentialID string) error {
	_, err := s.db.Exec(`DELETE FROM model_credentials WHERE model_id = ? AND credential_id = ?`,
		modelID, credentialID)
	return err
}

// Refresh refreshes an OAuth credential by ID.
func (s *Store) Refresh(id string) error {
	c, err := s.Get(id)
	if err != nil {
		return err
	}
	if c.IsLeased() {
		return fmt.Errorf("credential %s is leased to %s; cannot refresh server-side", id, c.LeaseHolderApp)
	}
	mu := s.refreshMutex(id)
	mu.Lock()
	defer mu.Unlock()
	return s.refreshOAuthCredential(c)
}

// AcquireLease grants exclusive use of a credential to a client app for ttl.
// Returns the lease_id (callers must echo this back on heartbeat/release/write-back).
// Errors if the credential is not in client_lease mode, or is already leased.
func (s *Store) AcquireLease(credID, app string, ttl time.Duration) (leaseID string, expiresAt int64, err error) {
	c, err := s.Get(credID)
	if err != nil {
		return "", 0, err
	}
	if c.RefreshMode != RefreshModeClientLease {
		return "", 0, fmt.Errorf("credential %s is not in client_lease mode (mode=%s)", credID, c.RefreshMode)
	}
	if c.IsLeased() && c.LeaseHolderApp != app {
		return "", 0, fmt.Errorf("credential %s already leased by %s until %d", credID, c.LeaseHolderApp, c.LeaseExpiresAt)
	}

	leaseID = randomID(16)
	expiresAt = time.Now().Add(ttl).UnixMilli()

	_, err = s.db.Exec(`UPDATE credentials SET lease_id = ?, lease_holder_app = ?, lease_expires_at = ? WHERE id = ?`,
		leaseID, app, expiresAt, credID)
	return leaseID, expiresAt, err
}

// HeartbeatLease extends the lease expiry. The lease_id must match.
func (s *Store) HeartbeatLease(credID, leaseID string, ttl time.Duration) (newExpiresAt int64, err error) {
	c, err := s.Get(credID)
	if err != nil {
		return 0, err
	}
	if c.LeaseID == "" {
		return 0, fmt.Errorf("credential %s is not leased", credID)
	}
	if c.LeaseID != leaseID {
		return 0, fmt.Errorf("lease_id mismatch")
	}
	newExpiresAt = time.Now().Add(ttl).UnixMilli()
	_, err = s.db.Exec(`UPDATE credentials SET lease_expires_at = ? WHERE id = ?`, newExpiresAt, credID)
	return newExpiresAt, err
}

// ReleaseLease ends the lease and writes back final token state.
// finalAccess/finalRefresh/finalExpiresAt are the latest values held by the client.
func (s *Store) ReleaseLease(credID, leaseID, finalAccess, finalRefresh string, finalExpiresAt int64) error {
	c, err := s.Get(credID)
	if err != nil {
		return err
	}
	if c.LeaseID == "" {
		return fmt.Errorf("credential %s is not leased", credID)
	}
	if c.LeaseID != leaseID {
		return fmt.Errorf("lease_id mismatch")
	}
	if finalExpiresAt != 0 && finalExpiresAt < c.ExpiresAt {
		return fmt.Errorf("write-back expires_at (%d) is older than stored (%d)", finalExpiresAt, c.ExpiresAt)
	}
	now := time.Now().UnixMilli()
	_, err = s.db.Exec(`UPDATE credentials SET token = ?, refresh_token = ?, expires_at = ?, last_refreshed_at = ?, lease_id = '', lease_holder_app = '', lease_expires_at = 0 WHERE id = ?`,
		finalAccess, finalRefresh, finalExpiresAt, now, credID)
	return err
}

// WriteBackTokens applies a mid-lease token update from the lease holder.
// The lease_id must match and expires_at must be strictly greater than stored.
func (s *Store) WriteBackTokens(credID, leaseID, access, refresh string, expiresAt int64) error {
	c, err := s.Get(credID)
	if err != nil {
		return err
	}
	if c.LeaseID == "" {
		return fmt.Errorf("credential %s is not leased", credID)
	}
	if c.LeaseID != leaseID {
		return fmt.Errorf("lease_id mismatch")
	}
	if expiresAt <= c.ExpiresAt {
		return fmt.Errorf("write-back expires_at (%d) must be greater than stored (%d)", expiresAt, c.ExpiresAt)
	}
	now := time.Now().UnixMilli()
	finalRefresh := refresh
	if finalRefresh == "" {
		finalRefresh = c.RefreshToken
	}
	_, err = s.db.Exec(`UPDATE credentials SET token = ?, refresh_token = ?, expires_at = ?, last_refreshed_at = ? WHERE id = ?`,
		access, finalRefresh, expiresAt, now, credID)
	return err
}

func scanCredential(rows *sql.Rows) (*Credentials, error) {
	var c Credentials
	var enabled, tls int
	var apiKey, token, refreshToken, baseURL, label, lastError, createdAt sql.NullString
	var owner, account, intendedApp, intendedPurpose, refreshMode sql.NullString
	var clientID, clientSecret, tenantID, redirectURL sql.NullString
	var username, password, host, leaseID, leaseHolderApp sql.NullString
	var port sql.NullInt64
	var expiresAt, lastUsedAt, lastErrorAt, lastRefreshedAt, leaseExpiresAt sql.NullInt64
	var errorCount sql.NullInt64

	err := rows.Scan(
		&c.ID, &c.Provider, &owner, &account, &label,
		&intendedApp, &intendedPurpose,
		&c.AuthType, &refreshMode,
		&apiKey, &token, &refreshToken, &expiresAt,
		&baseURL, &clientID, &clientSecret, &tenantID, &redirectURL,
		&username, &password, &host, &port, &tls,
		&leaseID, &leaseHolderApp, &leaseExpiresAt,
		&c.Priority, &enabled,
		&lastUsedAt, &lastRefreshedAt,
		&lastError, &lastErrorAt, &errorCount, &createdAt,
	)
	if err != nil {
		return nil, err
	}

	c.Owner = owner.String
	c.Account = account.String
	c.Label = label.String
	c.IntendedApp = intendedApp.String
	c.IntendedPurpose = intendedPurpose.String
	c.RefreshMode = refreshMode.String
	if c.RefreshMode == "" {
		c.RefreshMode = RefreshModeServer
	}
	c.APIKey = apiKey.String
	c.Token = token.String
	c.RefreshToken = refreshToken.String
	c.ExpiresAt = expiresAt.Int64
	c.BaseURL = baseURL.String
	c.ClientID = clientID.String
	c.ClientSecret = clientSecret.String
	c.TenantID = tenantID.String
	c.RedirectURL = redirectURL.String
	c.Username = username.String
	c.Password = password.String
	c.Host = host.String
	c.Port = int(port.Int64)
	c.TLS = tls != 0
	c.LeaseID = leaseID.String
	c.LeaseHolderApp = leaseHolderApp.String
	c.LeaseExpiresAt = leaseExpiresAt.Int64
	c.Enabled = enabled != 0
	c.LastUsedAt = lastUsedAt.Int64
	c.LastRefreshedAt = lastRefreshedAt.Int64
	c.LastError = lastError.String
	c.LastErrorAt = lastErrorAt.Int64
	c.ErrorCount = int(errorCount.Int64)
	c.CreatedAt = createdAt.String

	return &c, nil
}

// MaskSecret masks a token/key for display (4 prefix, 4 suffix, *** between).
func MaskSecret(s string) string {
	if len(s) <= 12 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + "..." + s[len(s)-4:]
}

// randomID returns a hex-encoded random id of n bytes (so 2n chars).
func randomID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// Crypto failure is unrecoverable; surface it loud.
		panic(fmt.Sprintf("rand.Read: %v", err))
	}
	return hex.EncodeToString(b)
}
