package oauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Anthropic OAuth constants. The client_id and redirect_uri are the same as
// the official claude.ai web app — Anthropic does not currently issue per-app
// OAuth credentials, so all clients share these. The stored AppCredentials
// fields are ignored.
const (
	anthropicClientID     = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	anthropicAuthorizeURL = "https://claude.ai/oauth/authorize"
	anthropicTokenURL     = "https://console.anthropic.com/v1/oauth/token"
	anthropicRedirectURI  = "https://console.anthropic.com/oauth/code/callback"
	anthropicScopes       = "org:create_api_key user:profile user:inference"
)

// Anthropic implements Provider for Anthropic's Claude OAuth flow with PKCE.
type Anthropic struct {
	mu        sync.Mutex
	verifiers map[string]string // state -> code_verifier; for callback correlation
}

// NewAnthropic returns a fresh Anthropic provider.
func NewAnthropic() *Anthropic {
	return &Anthropic{verifiers: make(map[string]string)}
}

func (a *Anthropic) ID() string { return "anthropic" }

func (a *Anthropic) BeginLogin(ctx context.Context, _ AppCredentials, state string) (LoginResult, error) {
	verifier, challenge, err := generatePKCE()
	if err != nil {
		return LoginResult{}, fmt.Errorf("PKCE: %w", err)
	}
	a.mu.Lock()
	a.verifiers[state] = verifier
	a.mu.Unlock()

	params := url.Values{
		"code":                  {"true"},
		"client_id":             {anthropicClientID},
		"redirect_uri":          {anthropicRedirectURI},
		"response_type":         {"code"},
		"scope":                 {anthropicScopes},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
	}
	return LoginResult{
		AuthURL:      anthropicAuthorizeURL + "?" + params.Encode(),
		State:        state,
		CodeVerifier: verifier,
	}, nil
}

func (a *Anthropic) CompleteLogin(ctx context.Context, _ AppCredentials, code, codeVerifier string) (TokenResult, error) {
	if codeVerifier == "" {
		return TokenResult{}, fmt.Errorf("anthropic: PKCE code_verifier required")
	}
	payload := map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     anthropicClientID,
		"code":          code,
		"redirect_uri":  anthropicRedirectURI,
		"code_verifier": codeVerifier,
	}
	return a.postToken(ctx, payload, "")
}

func (a *Anthropic) Refresh(ctx context.Context, _ AppCredentials, refreshToken string) (TokenResult, error) {
	if refreshToken == "" {
		return TokenResult{}, fmt.Errorf("anthropic: no refresh_token")
	}
	payload := map[string]string{
		"grant_type":    "refresh_token",
		"client_id":     anthropicClientID,
		"refresh_token": refreshToken,
	}
	return a.postToken(ctx, payload, refreshToken)
}

// VerifierFor returns and removes the stored PKCE verifier for the given state.
// Used by the auth-store callback handler.
func (a *Anthropic) VerifierFor(state string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	v := a.verifiers[state]
	delete(a.verifiers, state)
	return v
}

func (a *Anthropic) postToken(ctx context.Context, payload map[string]string, prevRefresh string) (TokenResult, error) {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", anthropicTokenURL, bytes.NewReader(body))
	if err != nil {
		return TokenResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "auth-store/1.0")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return TokenResult{}, fmt.Errorf("anthropic token request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return TokenResult{}, fmt.Errorf("anthropic token returned %d: %s", resp.StatusCode, respBody)
	}

	var tr struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(respBody, &tr); err != nil {
		return TokenResult{}, fmt.Errorf("parse anthropic response: %w", err)
	}

	refresh := tr.RefreshToken
	if refresh == "" {
		refresh = prevRefresh
	}
	// 5 minute buffer before expiry.
	expiresAt := time.Now().UnixMilli() + tr.ExpiresIn*1000 - 5*60*1000

	return TokenResult{
		AccessToken:  tr.AccessToken,
		RefreshToken: refresh,
		ExpiresAtMs:  expiresAt,
	}, nil
}

func generatePKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}
