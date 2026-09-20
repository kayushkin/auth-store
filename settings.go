package authstore

import (
	"fmt"

	"github.com/kayushkin/llm-bridge/msg"
	"github.com/kayushkin/llm-bridge/servicesettings"
)

// ServiceName is this service's name in its own settings description, as
// healthcheck and the repo know it.
const ServiceName = "auth-store"

// OwnedEnvironmentVariablePrefix is the prefix of the variables that are this
// service's alone. A set variable carrying it that SettingDefinitions does not
// declare stops the service from starting: it is a misspelling or a leftover,
// and either way someone believes it does something. It has no underscore in
// the middle: AUTH_STORE_URL and AUTH_STORE_TOKEN are what callers read to
// find and present themselves to this service, and are theirs.
const OwnedEnvironmentVariablePrefix = "AUTHSTORE_"

// Keys of the settings, as GET /settings names them.
const (
	SettingBearerToken      = "bearer_token"
	SettingOAuthCallbackURL = "oauth_callback_url"
)

// DefaultListenPort is the port the --port flag defaults to.
const DefaultListenPort = 8303

// DefaultOAuthCallbackURL is the callback address with AUTHSTORE_CALLBACK_URL
// unset: this service's own /oauth/callback on the port it listens on, which
// only a browser on this host can reach.
func DefaultOAuthCallbackURL(listenPort int) string {
	return fmt.Sprintf("http://localhost:%d/oauth/callback", listenPort)
}

// SettingDefinitions declares every environment variable this process reads,
// once. The command reads its configuration from it; GET /settings describes
// the service from it; and a test holds every os.Getenv in the repo to it, so
// a variable cannot be read without being declared here. listenPort is the
// --port flag's value, which the callback URL's default is built from.
//
// The token is a string on purpose: a string always parses, so no error from
// servicesettings.New can quote it. The listen address and database path are
// flags, not environment variables, and are not settings.
func SettingDefinitions(listenPort int) []servicesettings.Definition {
	return []servicesettings.Definition{
		{Key: SettingBearerToken, EnvironmentVariable: "AUTHSTORE_TOKEN", Kind: msg.ServiceSettingKindSecret, ValueType: msg.ServiceSettingValueTypeString,
			Description: "The bearer token every /api/* route and GET /settings demand. Unset leaves all of them open to any caller that can reach the port, and the service says so in its log at startup. Changing it locks out every caller still holding the old one."},
		{Key: SettingOAuthCallbackURL, EnvironmentVariable: "AUTHSTORE_CALLBACK_URL", Kind: msg.ServiceSettingKindWiring, ValueType: msg.ServiceSettingValueTypeString, Default: DefaultOAuthCallbackURL(listenPort),
			Description: "The public address of /oauth/callback, sent to a provider as the redirect when a login starts. It must be the address registered with each provider, or the provider refuses the login."},
	}
}

// NewSettingsRegistry reads this service's settings from environment. It fails
// on a set AUTHSTORE_ variable nobody declared.
func NewSettingsRegistry(listenPort int, environment servicesettings.Environment) (*servicesettings.Registry, error) {
	return servicesettings.New(ServiceName, []string{OwnedEnvironmentVariablePrefix}, SettingDefinitions(listenPort), environment)
}
