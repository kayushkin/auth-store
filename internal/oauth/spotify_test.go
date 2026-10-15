package oauth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestSpotifyBeginLoginAsksForEveryScope(t *testing.T) {
	res, err := NewSpotify(nil).BeginLogin(context.Background(),
		AppCredentials{ClientID: "id", ClientSecret: "secret", RedirectURL: "https://example.com/cb"}, "state-1")
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	u, err := url.Parse(res.AuthURL)
	if err != nil {
		t.Fatalf("parse auth url: %v", err)
	}
	if u.Host != "accounts.spotify.com" {
		t.Fatalf("host = %q, want accounts.spotify.com", u.Host)
	}
	q := u.Query()
	if q.Get("state") != "state-1" || q.Get("client_id") != "id" || q.Get("redirect_uri") != "https://example.com/cb" {
		t.Fatalf("query = %v", q)
	}
	if got, want := q.Get("scope"), strings.Join(DefaultSpotifyScopes, " "); got != want {
		t.Fatalf("scope = %q, want %q", got, want)
	}
}

func TestSpotifyBeginLoginRequiresAppCredentials(t *testing.T) {
	if _, err := NewSpotify(nil).BeginLogin(context.Background(), AppCredentials{ClientID: "id"}, "s"); err == nil {
		t.Fatal("BeginLogin without client_secret succeeded")
	}
}

func TestSpotifyCompleteLoginReadsOwnerEmail(t *testing.T) {
	origClient := http.DefaultClient
	defer func() { http.DefaultClient = origClient }()
	http.DefaultClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.String() {
		case "https://accounts.spotify.com/api/token":
			return jsonResponse(http.StatusOK, `{"access_token":"access","refresh_token":"refresh","expires_in":3600,"token_type":"Bearer"}`), nil
		case spotifyProfileURL:
			if got := req.Header.Get("Authorization"); got != "Bearer access" {
				t.Fatalf("profile auth = %q", got)
			}
			return jsonResponse(http.StatusOK, `{"email":"me@example.com"}`), nil
		}
		t.Fatalf("unexpected request to %s", req.URL)
		return nil, nil
	})}

	res, err := NewSpotify(nil).CompleteLogin(context.Background(), AppCredentials{ClientID: "id", ClientSecret: "secret"}, "s", "code", "")
	if err != nil {
		t.Fatalf("CompleteLogin: %v", err)
	}
	if res.AccessToken != "access" || res.RefreshToken != "refresh" || res.OwnerEmail != "me@example.com" {
		t.Fatalf("result = %+v", res)
	}
}

func TestSpotifyCompleteLoginFailsWhenProfileFails(t *testing.T) {
	origClient := http.DefaultClient
	defer func() { http.DefaultClient = origClient }()
	http.DefaultClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() == spotifyProfileURL {
			return jsonResponse(http.StatusForbidden, `{"error":"forbidden"}`), nil
		}
		return jsonResponse(http.StatusOK, `{"access_token":"access","refresh_token":"refresh","expires_in":3600,"token_type":"Bearer"}`), nil
	})}

	if _, err := NewSpotify(nil).CompleteLogin(context.Background(), AppCredentials{ClientID: "id", ClientSecret: "secret"}, "s", "code", ""); err == nil {
		t.Fatal("CompleteLogin succeeded with a 403 profile")
	}
}

func TestSpotifyRefreshKeepsRefreshTokenWhenNoneReturned(t *testing.T) {
	origClient := http.DefaultClient
	defer func() { http.DefaultClient = origClient }()
	http.DefaultClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"access_token":"new-access","expires_in":3600,"token_type":"Bearer"}`), nil
	})}

	res, err := NewSpotify(nil).Refresh(context.Background(), AppCredentials{ClientID: "id", ClientSecret: "secret"}, "old-refresh")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if res.AccessToken != "new-access" || res.RefreshToken != "old-refresh" {
		t.Fatalf("result = %+v", res)
	}
}
