package authstore

import (
	"context"
	"fmt"
	"time"

	"github.com/kayushkin/auth-store/internal/oauth"
)

// oauthProvider is the internal interface used for refreshing tokens.
// It mirrors oauth.Provider but is exported so the store can hold a registry
// without leaking the internal package.
type oauthProvider = oauth.Provider

// RegisterOAuthProvider registers a provider for OAuth refresh / login flows.
// Most callers want RegisterDefaultOAuthProviders.
func (s *Store) RegisterOAuthProvider(p oauthProvider) {
	s.oauthProviders[p.ID()] = p
}

// HasOAuthProvider reports whether a provider is registered.
func (s *Store) HasOAuthProvider(id string) bool {
	_, ok := s.oauthProviders[id]
	return ok
}

// OAuthProvider returns the registered provider, or nil.
func (s *Store) OAuthProvider(id string) oauthProvider {
	return s.oauthProviders[id]
}

// RegisterDefaultOAuthProviders registers the built-in providers
// (Anthropic, Google, Microsoft).
func (s *Store) RegisterDefaultOAuthProviders() {
	s.RegisterOAuthProvider(oauth.NewAnthropic())
	s.RegisterOAuthProvider(oauth.NewGoogle(nil))
	s.RegisterOAuthProvider(oauth.NewMicrosoft(nil))
}

// refreshOAuthCredential refreshes an OAuth credential using the registered
// provider, threading the credential's app-level config (client_id/secret/
// tenant_id/redirect_url) through to the provider.
func (s *Store) refreshOAuthCredential(c *Credentials) error {
	p, ok := s.oauthProviders[c.Provider]
	if !ok {
		return fmt.Errorf("no OAuth provider registered for %s", c.Provider)
	}

	app := oauth.AppCredentials{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		TenantID:     c.TenantID,
		RedirectURL:  c.RedirectURL,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := p.Refresh(ctx, app, c.RefreshToken)
	if err != nil {
		return fmt.Errorf("refresh failed for %s: %w", c.ID, err)
	}

	c.Token = res.AccessToken
	if res.RefreshToken != "" {
		c.RefreshToken = res.RefreshToken
	}
	c.ExpiresAt = res.ExpiresAtMs
	c.LastRefreshedAt = time.Now().UnixMilli()

	_, err = s.db.Exec(`UPDATE credentials SET token = ?, refresh_token = ?, expires_at = ?, last_refreshed_at = ?, last_error = '', error_count = 0 WHERE id = ?`,
		c.Token, c.RefreshToken, c.ExpiresAt, c.LastRefreshedAt, c.ID)
	return err
}
