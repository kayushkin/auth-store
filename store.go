package authstore

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Store is the credential vault.
type Store struct {
	db             *sql.DB
	path           string
	oauthProviders map[string]OAuthProvider
}

// OAuthProvider is the interface for refreshing OAuth tokens.
type OAuthProvider interface {
	ID() string
	RefreshToken(accessToken, refreshToken string) (newAccess, newRefresh string, expiresAtMs int64, err error)
}

// Credentials holds auth for a provider.
type Credentials struct {
	ID           string `json:"id"`
	Provider     string `json:"provider"`
	Label        string `json:"label,omitempty"`
	AuthType     string `json:"auth_type"` // "api_key", "oauth", "token", "none"
	APIKey       string `json:"api_key,omitempty"`
	Token        string `json:"token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresAt    int64  `json:"expires_at,omitempty"` // unix ms
	BaseURL      string `json:"base_url,omitempty"`
	Priority     int    `json:"priority"`
	Enabled      bool   `json:"enabled"`
	LastUsedAt   int64  `json:"last_used_at,omitempty"`
	LastError    string `json:"last_error,omitempty"`
	LastErrorAt  int64  `json:"last_error_at,omitempty"`
	ErrorCount   int    `json:"error_count,omitempty"`
	CreatedAt    string `json:"created_at,omitempty"`
}

// IsExpired returns true if OAuth credentials need refreshing.
func (c *Credentials) IsExpired() bool {
	if c.AuthType != "oauth" || c.ExpiresAt == 0 {
		return false
	}
	return c.ExpiresAt < time.Now().UnixMilli()
}

// DefaultPath returns the default store path.
func DefaultPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "auth-store", "auth.db")
}

// Open opens or creates an auth store.
func Open(path string) (*Store, error) {
	if path == "" {
		path = DefaultPath()
	}
	os.MkdirAll(filepath.Dir(path), 0755)

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	s := &Store{db: db, path: path, oauthProviders: make(map[string]OAuthProvider)}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return s, nil
}

// Close closes the store.
func (s *Store) Close() error {
	return s.db.Close()
}

// RegisterOAuthProvider registers a provider for OAuth token refresh.
func (s *Store) RegisterOAuthProvider(p OAuthProvider) {
	s.oauthProviders[p.ID()] = p
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS credentials (
			id            TEXT PRIMARY KEY,
			provider      TEXT NOT NULL,
			label         TEXT DEFAULT '',
			auth_type     TEXT NOT NULL,
			api_key       TEXT,
			token         TEXT,
			refresh_token TEXT,
			expires_at    INTEGER DEFAULT 0,
			base_url      TEXT,
			priority      INTEGER DEFAULT 100,
			enabled       INTEGER DEFAULT 1,
			last_used_at  INTEGER DEFAULT 0,
			last_error    TEXT DEFAULT '',
			last_error_at INTEGER DEFAULT 0,
			error_count   INTEGER DEFAULT 0,
			created_at    TEXT DEFAULT (datetime('now'))
		);

		CREATE TABLE IF NOT EXISTS model_credentials (
			model_id      TEXT NOT NULL,
			credential_id TEXT NOT NULL REFERENCES credentials(id),
			priority      INTEGER DEFAULT 100,
			PRIMARY KEY (model_id, credential_id)
		);
	`)
	return err
}
