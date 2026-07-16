package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// DefaultGoogleScopes covers calendar + gmail + userinfo, matching the
// previous apiauth defaults.
var DefaultGoogleScopes = []string{
	"https://www.googleapis.com/auth/calendar",
	"https://www.googleapis.com/auth/calendar.events",
	"https://mail.google.com/",
	"https://www.googleapis.com/auth/userinfo.email",
	"openid",
}

// Google implements Provider for the standard Google OAuth2 flow.
type Google struct {
	scopes []string
}

// NewGoogle returns a Google provider with the given scopes (or defaults if
// scopes is nil).
func NewGoogle(scopes []string) *Google {
	if len(scopes) == 0 {
		scopes = DefaultGoogleScopes
	}
	return &Google{scopes: scopes}
}

func (g *Google) ID() string { return "google" }

func (g *Google) config(app AppCredentials) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     app.ClientID,
		ClientSecret: app.ClientSecret,
		Endpoint:     google.Endpoint,
		RedirectURL:  app.RedirectURL,
		Scopes:       g.scopes,
	}
}

func (g *Google) BeginLogin(ctx context.Context, app AppCredentials, state string) (LoginResult, error) {
	if app.ClientID == "" || app.ClientSecret == "" {
		return LoginResult{}, fmt.Errorf("google: client_id and client_secret required")
	}
	cfg := g.config(app)
	url := cfg.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("prompt", "consent"),
	)
	return LoginResult{AuthURL: url, State: state}, nil
}

func (g *Google) CompleteLogin(ctx context.Context, app AppCredentials, _, code, _ string) (TokenResult, error) {
	cfg := g.config(app)
	tok, err := cfg.Exchange(ctx, code)
	if err != nil {
		return TokenResult{}, fmt.Errorf("google exchange: %w", err)
	}
	res := tokenResultFromOAuth2(tok)
	res.OwnerEmail = fetchGoogleEmail(ctx, tok.AccessToken)
	return res, nil
}

func (g *Google) Refresh(ctx context.Context, app AppCredentials, refreshToken string) (TokenResult, error) {
	if refreshToken == "" {
		return TokenResult{}, fmt.Errorf("google: no refresh_token")
	}
	cfg := g.config(app)
	src := cfg.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken})
	tok, err := src.Token()
	if err != nil {
		return TokenResult{}, fmt.Errorf("google refresh: %w", err)
	}
	res := tokenResultFromOAuth2(tok)
	if res.RefreshToken == "" {
		// Google sometimes omits refresh_token on rotation; reuse the previous one.
		res.RefreshToken = refreshToken
	}
	return res, nil
}

func tokenResultFromOAuth2(tok *oauth2.Token) TokenResult {
	expires := int64(0)
	if !tok.Expiry.IsZero() {
		// 5 minute buffer.
		expires = tok.Expiry.Add(-5*time.Minute).UnixMilli()
	}
	return TokenResult{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		ExpiresAtMs:  expires,
	}
}

func fetchGoogleEmail(ctx context.Context, accessToken string) string {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://openidconnect.googleapis.com/v1/userinfo", nil)
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
		Email string `json:"email"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return ""
	}
	return info.Email
}
