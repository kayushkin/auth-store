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

func TestAnthropicCompleteLoginNormalizesPastedCallbackURL(t *testing.T) {
	origClient := http.DefaultClient
	defer func() { http.DefaultClient = origClient }()

	var got map[string]string
	http.DefaultClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
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
	pasted := "https://console.anthropic.com/oauth/code/callback?code=code-456&state=state-123#state-123"
	_, err := a.CompleteLogin(context.Background(), AppCredentials{}, "state-123", pasted, "verifier-789")
	if err != nil {
		t.Fatalf("CompleteLogin error: %v", err)
	}

	if got["code"] != "code-456" {
		t.Fatalf("code = %q, want %q", got["code"], "code-456")
	}
}

func TestAnthropicCompleteLoginRetriesWithoutStateAndOnPlatform(t *testing.T) {
	origClient := http.DefaultClient
	defer func() { http.DefaultClient = origClient }()

	type call struct {
		URL     string
		Payload map[string]string
	}
	var calls []call
	http.DefaultClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			var payload map[string]string
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			calls = append(calls, call{URL: req.URL.String(), Payload: payload})

			switch len(calls) {
			case 1:
				if payload["state"] != "state-123" {
					t.Fatalf("first call state = %q, want state-123", payload["state"])
				}
				return jsonResponse(http.StatusBadRequest,
					`{"type":"error","error":{"type":"invalid_request_error","message":"Invalid request format"}}`), nil
			case 2:
				if _, ok := payload["state"]; ok {
					t.Fatalf("second call unexpectedly included state")
				}
				return jsonResponse(http.StatusBadRequest,
					`{"type":"error","error":{"type":"invalid_request_error","message":"Invalid request format"}}`), nil
			case 3:
				if req.URL.String() != anthropicPlatformTokenURL {
					t.Fatalf("third call url = %q, want %q", req.URL.String(), anthropicPlatformTokenURL)
				}
				if payload["state"] != "state-123" {
					t.Fatalf("third call state = %q, want state-123", payload["state"])
				}
				return jsonResponse(http.StatusOK,
					`{"access_token":"access","refresh_token":"refresh","expires_in":3600}`), nil
			default:
				t.Fatalf("unexpected extra call %d", len(calls))
				return nil, nil
			}
		}),
	}

	a := NewAnthropic()
	_, err := a.CompleteLogin(context.Background(), AppCredentials{}, "state-123", "code-456", "verifier-789")
	if err != nil {
		t.Fatalf("CompleteLogin error: %v", err)
	}

	if len(calls) != 3 {
		t.Fatalf("calls = %d, want 3", len(calls))
	}
	if calls[0].URL != anthropicTokenURL {
		t.Fatalf("first call url = %q, want %q", calls[0].URL, anthropicTokenURL)
	}
}

func TestNormalizeAnthropicCode(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "raw", in: " code-123 ", want: "code-123"},
		{name: "hash suffix", in: "code-123#state-456", want: "code-123"},
		{name: "callback url", in: "https://console.anthropic.com/oauth/code/callback?code=code-123&state=state-456#state-456", want: "code-123"},
		{name: "query string only", in: "https://console.anthropic.com/oauth/code/callback?code=code-123", want: "code-123"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeAnthropicCode(tt.in)
			if got != tt.want {
				t.Fatalf("normalizeAnthropicCode(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
