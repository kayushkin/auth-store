package oauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestAnthropicCompleteLoginIncludesState(t *testing.T) {
	origClient := http.DefaultClient
	defer func() { http.DefaultClient = origClient }()

	var got map[string]string
	http.DefaultClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Method != http.MethodPost {
				t.Fatalf("method = %s, want POST", req.Method)
			}
			if req.URL.String() != anthropicTokenURL {
				t.Fatalf("url = %s, want %s", req.URL.String(), anthropicTokenURL)
			}
			if ct := req.Header.Get("Content-Type"); ct != "application/json" {
				t.Fatalf("content-type = %q, want application/json", ct)
			}

			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			if err := json.Unmarshal(body, &got); err != nil {
				t.Fatalf("decode body: %v", err)
			}

			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(
					`{"access_token":"access","refresh_token":"refresh","expires_in":3600}`,
				)),
			}, nil
		}),
	}

	a := NewAnthropic()
	_, err := a.CompleteLogin(context.Background(), AppCredentials{}, "state-123", "code-456", "verifier-789")
	if err != nil {
		t.Fatalf("CompleteLogin error: %v", err)
	}

	if got["state"] != "state-123" {
		t.Fatalf("state = %q, want %q", got["state"], "state-123")
	}
	if got["code"] != "code-456" {
		t.Fatalf("code = %q, want %q", got["code"], "code-456")
	}
	if got["code_verifier"] != "verifier-789" {
		t.Fatalf("code_verifier = %q, want %q", got["code_verifier"], "verifier-789")
	}
}
