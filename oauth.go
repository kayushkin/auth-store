package authstore

import (
	"github.com/kayushkin/aiauth"
	"github.com/kayushkin/aiauth/providers"
)

// aiauthAdapter wraps an aiauth.Provider to implement OAuthProvider.
type aiauthAdapter struct {
	provider aiauth.Provider
}

func (a *aiauthAdapter) ID() string { return a.provider.ID() }

func (a *aiauthAdapter) RefreshToken(accessToken, refreshToken string) (string, string, int64, error) {
	cred := &aiauth.Credential{
		Type:     "oauth",
		Provider: a.provider.ID(),
		Access:   accessToken,
		Refresh:  refreshToken,
	}

	refreshed, err := a.provider.RefreshToken(cred)
	if err != nil {
		return "", "", 0, err
	}

	return refreshed.Access, refreshed.Refresh, refreshed.Expires, nil
}

// RegisterAiauthProvider registers an aiauth.Provider for OAuth refresh.
func (s *Store) RegisterAiauthProvider(p aiauth.Provider) {
	s.RegisterOAuthProvider(&aiauthAdapter{provider: p})
}

// RegisterDefaultOAuthProviders registers the built-in OAuth providers (Anthropic).
func (s *Store) RegisterDefaultOAuthProviders() {
	s.RegisterAiauthProvider(providers.NewAnthropic())
}
