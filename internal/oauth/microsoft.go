package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

// DefaultMicrosoftScopes covers Graph calendar + mail.
var DefaultMicrosoftScopes = []string{
	"Calendars.ReadWrite",
	"Mail.ReadWrite",
	"Mail.Send",
	"User.Read",
	"offline_access",
}

// Microsoft implements Provider for Azure AD / Microsoft Graph OAuth2.
type Microsoft struct {
	scopes []string
}

// NewMicrosoft returns a Microsoft provider.
func NewMicrosoft(scopes []string) *Microsoft {
	if len(scopes) == 0 {
		scopes = DefaultMicrosoftScopes
	}
	return &Microsoft{scopes: scopes}
}

func (m *Microsoft) ID() string { return "microsoft" }

func (m *Microsoft) config(app AppCredentials) *oauth2.Config {
	tenant := app.TenantID
	if tenant == "" {
		tenant = "common"
	}
	return &oauth2.Config{
		ClientID:     app.ClientID,
		ClientSecret: app.ClientSecret,
		Endpoint:     microsoft.AzureADEndpoint(tenant),
		RedirectURL:  app.RedirectURL,
		Scopes:       m.scopes,
	}
}

func (m *Microsoft) BeginLogin(ctx context.Context, app AppCredentials, state string) (LoginResult, error) {
	if app.ClientID == "" || app.ClientSecret == "" {
		return LoginResult{}, fmt.Errorf("microsoft: client_id and client_secret required")
	}
	cfg := m.config(app)
	url := cfg.AuthCodeURL(state, oauth2.AccessTypeOffline)
	return LoginResult{AuthURL: url, State: state}, nil
}

func (m *Microsoft) CompleteLogin(ctx context.Context, app AppCredentials, code, _ string) (TokenResult, error) {
	cfg := m.config(app)
	tok, err := cfg.Exchange(ctx, code)
	if err != nil {
		return TokenResult{}, fmt.Errorf("microsoft exchange: %w", err)
	}
	res := tokenResultFromOAuth2(tok)
	res.OwnerEmail = fetchMicrosoftUPN(ctx, tok.AccessToken)
	return res, nil
}

func (m *Microsoft) Refresh(ctx context.Context, app AppCredentials, refreshToken string) (TokenResult, error) {
	if refreshToken == "" {
		return TokenResult{}, fmt.Errorf("microsoft: no refresh_token")
	}
	cfg := m.config(app)
	src := cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken})
	tok, err := src.Token()
	if err != nil {
		return TokenResult{}, fmt.Errorf("microsoft refresh: %w", err)
	}
	res := tokenResultFromOAuth2(tok)
	if res.RefreshToken == "" {
		res.RefreshToken = refreshToken
	}
	return res, nil
}

func fetchMicrosoftUPN(ctx context.Context, accessToken string) string {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://graph.microsoft.com/v1.0/me", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var info struct {
		UPN  string `json:"userPrincipalName"`
		Mail string `json:"mail"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return ""
	}
	if info.Mail != "" {
		return info.Mail
	}
	return info.UPN
}
