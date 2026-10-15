package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/spotify"
)

// DefaultSpotifyScopes covers what kayushkin.com's music shelf does: read the
// saved library and playlists, search, see and move playback between Connect
// devices, and play in the browser through the Web Playback SDK (which needs
// streaming, user-read-email and user-read-private).
var DefaultSpotifyScopes = []string{
	"user-read-email",
	"user-read-private",
	"user-library-read",
	"user-library-modify",
	"playlist-read-private",
	"playlist-read-collaborative",
	"user-read-recently-played",
	"user-read-playback-state",
	"user-modify-playback-state",
	"user-read-currently-playing",
	"streaming",
}

const spotifyProfileURL = "https://api.spotify.com/v1/me"

// Spotify implements Provider for Spotify's authorization code flow.
type Spotify struct {
	scopes []string
}

// NewSpotify returns a Spotify provider with the given scopes (or defaults if
// scopes is nil).
func NewSpotify(scopes []string) *Spotify {
	if len(scopes) == 0 {
		scopes = DefaultSpotifyScopes
	}
	return &Spotify{scopes: scopes}
}

func (s *Spotify) ID() string { return "spotify" }

func (s *Spotify) config(app AppCredentials) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     app.ClientID,
		ClientSecret: app.ClientSecret,
		Endpoint:     spotify.Endpoint,
		RedirectURL:  app.RedirectURL,
		Scopes:       s.scopes,
	}
}

func (s *Spotify) BeginLogin(ctx context.Context, app AppCredentials, state string) (LoginResult, error) {
	if app.ClientID == "" || app.ClientSecret == "" {
		return LoginResult{}, fmt.Errorf("spotify: client_id and client_secret required")
	}
	return LoginResult{AuthURL: s.config(app).AuthCodeURL(state), State: state}, nil
}

func (s *Spotify) CompleteLogin(ctx context.Context, app AppCredentials, _, code, _ string) (TokenResult, error) {
	tok, err := s.config(app).Exchange(ctx, code)
	if err != nil {
		return TokenResult{}, fmt.Errorf("spotify exchange: %w", err)
	}
	res := tokenResultFromOAuth2(tok)
	email, err := fetchSpotifyEmail(ctx, tok.AccessToken)
	if err != nil {
		return TokenResult{}, err
	}
	res.OwnerEmail = email
	return res, nil
}

func (s *Spotify) Refresh(ctx context.Context, app AppCredentials, refreshToken string) (TokenResult, error) {
	if refreshToken == "" {
		return TokenResult{}, fmt.Errorf("spotify: no refresh_token")
	}
	tok, err := s.config(app).TokenSource(ctx, &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		return TokenResult{}, fmt.Errorf("spotify refresh: %w", err)
	}
	res := tokenResultFromOAuth2(tok)
	if res.RefreshToken == "" {
		// Spotify returns a new refresh_token only sometimes; keep the old one otherwise.
		res.RefreshToken = refreshToken
	}
	return res, nil
}

// fetchSpotifyEmail reads the account email from the profile endpoint. Unlike
// the Google and Microsoft lookups it fails the login on error: the token was
// granted user-read-email, so a failure here means something is wrong with it.
func fetchSpotifyEmail(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", spotifyProfileURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("spotify profile: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("spotify profile: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("spotify profile: %s: %s", resp.Status, body)
	}
	var profile struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(body, &profile); err != nil {
		return "", fmt.Errorf("spotify profile: %w", err)
	}
	return profile.Email, nil
}
