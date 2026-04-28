package authstore

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kayushkin/auth-store/internal/oauth"

	_ "modernc.org/sqlite"
)

// Store is the credential vault.
type Store struct {
	db             *sql.DB
	path           string
	oauthProviders map[string]oauth.Provider

	refreshMu   sync.Mutex
	refreshLock map[string]*sync.Mutex
}

// Refresh modes for credentials.
const (
	RefreshModeServer      = "server"       // auth-store refreshes on /resolve
	RefreshModeClientLease = "client_lease" // client app refreshes; lease enforces single refresher
	RefreshModeNone        = "none"         // static credentials (api_key, password)
)

// Auth types for credentials.
const (
	AuthTypeAPIKey   = "api_key"
	AuthTypeOAuth    = "oauth"
	AuthTypeToken    = "token"
	AuthTypePassword = "password"
	AuthTypeNone     = "none"
)

// Credentials holds auth for a provider.
type Credentials struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	Owner    string `json:"owner"`
	Account  string `json:"account,omitempty"`
	Label    string `json:"label,omitempty"`

	IntendedApp     string `json:"intended_app,omitempty"`
	IntendedPurpose string `json:"intended_purpose,omitempty"`

	AuthType     string `json:"auth_type"`
	RefreshMode  string `json:"refresh_mode"`
	APIKey       string `json:"api_key,omitempty"`
	Token        string `json:"token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresAt    int64  `json:"expires_at,omitempty"` // unix ms
	BaseURL      string `json:"base_url,omitempty"`

	// OAuth client config (used to be in apiauth's `credentials` table)
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	TenantID     string `json:"tenant_id,omitempty"`
	RedirectURL  string `json:"redirect_url,omitempty"`

	// IMAP / SMTP fields (auth_type = "password")
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	TLS      bool   `json:"tls,omitempty"`

	// Lease state (only meaningful for refresh_mode = "client_lease")
	LeaseID         string `json:"lease_id,omitempty"`
	LeaseHolderApp  string `json:"lease_holder_app,omitempty"`
	LeaseExpiresAt  int64  `json:"lease_expires_at,omitempty"`

	Priority        int    `json:"priority"`
	Enabled         bool   `json:"enabled"`
	LastUsedAt      int64  `json:"last_used_at,omitempty"`
	LastRefreshedAt int64  `json:"last_refreshed_at,omitempty"`
	LastError       string `json:"last_error,omitempty"`
	LastErrorAt     int64  `json:"last_error_at,omitempty"`
	ErrorCount      int    `json:"error_count,omitempty"`
	CreatedAt       string `json:"created_at,omitempty"`
}

// IsExpired returns true if OAuth credentials need refreshing.
func (c *Credentials) IsExpired() bool {
	if c.AuthType != AuthTypeOAuth || c.ExpiresAt == 0 {
		return false
	}
	return c.ExpiresAt < time.Now().UnixMilli()
}

// IsLeased returns true if the credential is currently leased to a client.
func (c *Credentials) IsLeased() bool {
	if c.LeaseID == "" {
		return false
	}
	return c.LeaseExpiresAt > time.Now().UnixMilli()
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

	// modernc sqlite + WAL needs single writer to avoid SQLITE_BUSY.
	db.SetMaxOpenConns(1)

	s := &Store{
		db:             db,
		path:           path,
		oauthProviders: make(map[string]oauth.Provider),
		refreshLock:    make(map[string]*sync.Mutex),
	}
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

// DB returns the underlying database handle (used by server-side handlers).
func (s *Store) DB() *sql.DB {
	return s.db
}

// Path returns the on-disk database path.
func (s *Store) Path() string {
	return s.path
}

// refreshMutex returns a per-credential mutex for serialising refresh attempts.
func (s *Store) refreshMutex(credID string) *sync.Mutex {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	mu, ok := s.refreshLock[credID]
	if !ok {
		mu = &sync.Mutex{}
		s.refreshLock[credID] = mu
	}
	return mu
}

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)`); err != nil {
		return fmt.Errorf("schema_version table: %w", err)
	}

	var current int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&current); err != nil {
		return fmt.Errorf("read schema_version: %w", err)
	}

	migrations := []func() error{
		s.migrateV1,
		s.migrateV2,
	}

	for i := current; i < len(migrations); i++ {
		if err := migrations[i](); err != nil {
			return fmt.Errorf("migration v%d: %w", i+1, err)
		}
		if _, err := s.db.Exec(`INSERT INTO schema_version (version) VALUES (?)`, i+1); err != nil {
			return fmt.Errorf("record schema_version v%d: %w", i+1, err)
		}
	}
	return nil
}

func (s *Store) migrateV1() error {
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

func (s *Store) migrateV2() error {
	stmts := []string{
		`ALTER TABLE credentials ADD COLUMN owner TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE credentials ADD COLUMN account TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE credentials ADD COLUMN intended_app TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE credentials ADD COLUMN intended_purpose TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE credentials ADD COLUMN refresh_mode TEXT NOT NULL DEFAULT 'server'`,
		`ALTER TABLE credentials ADD COLUMN client_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE credentials ADD COLUMN client_secret TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE credentials ADD COLUMN tenant_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE credentials ADD COLUMN redirect_url TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE credentials ADD COLUMN username TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE credentials ADD COLUMN password TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE credentials ADD COLUMN host TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE credentials ADD COLUMN port INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE credentials ADD COLUMN tls INTEGER NOT NULL DEFAULT 1`,
		`ALTER TABLE credentials ADD COLUMN lease_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE credentials ADD COLUMN lease_holder_app TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE credentials ADD COLUMN lease_expires_at INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE credentials ADD COLUMN last_refreshed_at INTEGER NOT NULL DEFAULT 0`,

		`CREATE TABLE IF NOT EXISTS key_access_log (
			id                 INTEGER PRIMARY KEY AUTOINCREMENT,
			ts                 INTEGER NOT NULL,
			credential_id      TEXT NOT NULL DEFAULT '',
			provider           TEXT NOT NULL DEFAULT '',
			owner              TEXT NOT NULL DEFAULT '',
			app                TEXT NOT NULL,
			reason             TEXT NOT NULL,
			action             TEXT NOT NULL,
			ok                 INTEGER NOT NULL,
			error              TEXT NOT NULL DEFAULT '',
			intended_app_match INTEGER NOT NULL DEFAULT 0,
			remote_addr        TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_cred ON key_access_log(credential_id, ts)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_app ON key_access_log(app, ts)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_owner ON key_access_log(owner, ts)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_ts ON key_access_log(ts)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("%s: %w", q, err)
		}
	}
	return nil
}
