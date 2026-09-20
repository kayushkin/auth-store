package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	authstore "github.com/kayushkin/auth-store"
	"github.com/kayushkin/llm-bridge/msg"
	"github.com/kayushkin/llm-bridge/servicesettings"
)

const settingsTestBearerToken = "settings-test-bearer-token-that-must-not-be-served"

func newSettingsTestServer(t *testing.T, environment map[string]string) *Server {
	t.Helper()
	store, err := authstore.Open(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	registry, err := authstore.NewSettingsRegistry(authstore.DefaultListenPort, servicesettings.MapEnvironment(environment))
	if err != nil {
		t.Fatal(err)
	}
	return New(Config{
		Store:       store,
		AuthToken:   registry.String(authstore.SettingBearerToken),
		CallbackURL: registry.String(authstore.SettingOAuthCallbackURL),
		Settings:    registry,
	})
}

func getSettings(t *testing.T, srv *Server, method, path, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(`{"value":"x"}`))
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	recorder := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recorder, request)
	return recorder
}

func TestGetSettingsSitsBehindTheBearerAndNeverServesTheToken(t *testing.T) {
	srv := newSettingsTestServer(t, map[string]string{
		"AUTHSTORE_TOKEN":        settingsTestBearerToken,
		"AUTHSTORE_CALLBACK_URL": "https://example.com/api/authstore/callback",
	})

	if recorder := getSettings(t, srv, http.MethodGet, "/settings", ""); recorder.Code != http.StatusUnauthorized {
		t.Errorf("GET /settings with no bearer = %d: %s", recorder.Code, recorder.Body)
	}
	if recorder := getSettings(t, srv, http.MethodGet, "/settings", "not-the-token"); recorder.Code != http.StatusUnauthorized {
		t.Errorf("GET /settings with a wrong bearer = %d: %s", recorder.Code, recorder.Body)
	}

	recorder := getSettings(t, srv, http.MethodGet, "/settings", settingsTestBearerToken)
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /settings with the bearer = %d: %s", recorder.Code, recorder.Body)
	}
	if strings.Contains(recorder.Body.String(), settingsTestBearerToken) {
		t.Fatal("GET /settings served the bearer token's value")
	}
	var described msg.ServiceSettings
	if err := json.Unmarshal(recorder.Body.Bytes(), &described); err != nil {
		t.Fatal(err)
	}
	if described.Service != authstore.ServiceName || len(described.Settings) != len(authstore.SettingDefinitions(authstore.DefaultListenPort)) {
		t.Fatalf("service=%q with %d settings", described.Service, len(described.Settings))
	}
	for _, setting := range described.Settings {
		if setting.Editable {
			t.Errorf("%s is editable, and no write route is mounted", setting.Key)
		}
		switch setting.Key {
		case authstore.SettingBearerToken:
			if setting.Kind != msg.ServiceSettingKindSecret || !setting.IsSet || setting.Value != "" {
				t.Errorf("token served as kind=%q is_set=%t value=%q, want a set secret with no value", setting.Kind, setting.IsSet, setting.Value)
			}
		case authstore.SettingOAuthCallbackURL:
			if setting.Value != "https://example.com/api/authstore/callback" || setting.Source != msg.ServiceSettingSourceEnvironment {
				t.Errorf("callback served as %q from %q", setting.Value, setting.Source)
			}
		}
	}

	if recorder := getSettings(t, srv, http.MethodPut, "/settings/"+authstore.SettingOAuthCallbackURL, settingsTestBearerToken); recorder.Code == http.StatusOK {
		t.Errorf("PUT /settings/%s = 200: a write route is mounted", authstore.SettingOAuthCallbackURL)
	}
}

// With no token the service runs open and says so at startup; /settings is
// then as open as /api/*, not more and not less.
func TestGetSettingsIsAsOpenAsTheAPIWhenNoTokenIsSet(t *testing.T) {
	srv := newSettingsTestServer(t, map[string]string{})
	settings := getSettings(t, srv, http.MethodGet, "/settings", "")
	credentials := getSettings(t, srv, http.MethodGet, "/api/credentials", "")
	if settings.Code != http.StatusOK || credentials.Code != http.StatusOK {
		t.Errorf("with no token: GET /settings = %d, GET /api/credentials = %d, want both 200", settings.Code, credentials.Code)
	}
}

func TestNewRefusesAMissingSettingsRegistry(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("New without Settings did not panic: GET /settings would fail at its first read instead of at boot")
		}
	}()
	New(Config{})
}
