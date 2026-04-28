package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	authstore "github.com/kayushkin/auth-store"
	_ "modernc.org/sqlite"
)

// ============================================================================
// aiauth → auth-store
// ============================================================================

type aiauthFile struct {
	Profiles map[string]aiauthProfile `json:"profiles"`
}

type aiauthProfile struct {
	Type     string `json:"type"`     // "api_key" | "token" | "oauth"
	Provider string `json:"provider"`
	Key      string `json:"key,omitempty"`
	Token    string `json:"token,omitempty"`
	Access   string `json:"access,omitempty"`
	Refresh  string `json:"refresh,omitempty"`
	Expires  int64  `json:"expires,omitempty"`
}

func migrateAiauth(store *authstore.Store, dryRun bool) error {
	home, _ := os.UserHomeDir()
	path := filepath.Join(home, ".openclaw", "agents", "main", "agent", "auth-profiles.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read aiauth file: %w", err)
	}

	var f aiauthFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("parse aiauth file: %w", err)
	}

	count := 0
	for name, p := range f.Profiles {
		c := authstore.Credentials{
			ID:       "cred_aiauth_" + sanitize(name),
			Provider: p.Provider,
			Owner:    "", // aiauth has no owner concept; user fills via UI
			Label:    name,
			Priority: 100,
			Enabled:  true,
		}

		switch p.Type {
		case "api_key":
			c.AuthType = authstore.AuthTypeAPIKey
			c.RefreshMode = authstore.RefreshModeNone
			c.APIKey = p.Key
		case "token":
			c.AuthType = authstore.AuthTypeToken
			c.RefreshMode = authstore.RefreshModeNone
			c.Token = p.Token
			c.ExpiresAt = p.Expires
		case "oauth":
			c.AuthType = authstore.AuthTypeOAuth
			// CC and similar harnesses auto-refresh internally — make these
			// client_lease so auth-store doesn't race with the harness.
			c.RefreshMode = authstore.RefreshModeClientLease
			c.IntendedApp = "llm-bridge-server"
			c.Token = p.Access
			c.RefreshToken = p.Refresh
			c.ExpiresAt = p.Expires
		default:
			log.Printf("  skip %s: unknown type %q", name, p.Type)
			continue
		}

		if dryRun {
			log.Printf("  [dry-run] would import %s as %s (provider=%s type=%s mode=%s)", name, c.ID, c.Provider, c.AuthType, c.RefreshMode)
		} else {
			if err := store.Set(c); err != nil {
				return fmt.Errorf("set %s: %w", name, err)
			}
			log.Printf("  imported %s as %s", name, c.ID)
		}
		count++
	}
	log.Printf("aiauth: %d profiles processed", count)
	return nil
}

// ============================================================================
// apiauth → auth-store
// ============================================================================

func migrateApiauth(store *authstore.Store, dryRun bool) error {
	home, _ := os.UserHomeDir()
	path := filepath.Join(home, ".config", "apiauth", "tokens.db")
	src, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return fmt.Errorf("open apiauth db: %w", err)
	}
	defer src.Close()

	type credRow struct {
		clientID, clientSecret, tenantID, redirectURL string
	}
	clientCreds := make(map[string]credRow)
	rows, err := src.Query(`SELECT provider, client_id, client_secret, tenant_id, redirect_url FROM credentials`)
	if err != nil {
		return fmt.Errorf("query apiauth credentials: %w", err)
	}
	for rows.Next() {
		var prov, cid, csec, tid, ru string
		if err := rows.Scan(&prov, &cid, &csec, &tid, &ru); err != nil {
			rows.Close()
			return err
		}
		clientCreds[prov] = credRow{cid, csec, tid, ru}
	}
	rows.Close()

	tokRows, err := src.Query(`SELECT provider, account, scopes, access, refresh, expires_at FROM tokens`)
	if err != nil {
		return fmt.Errorf("query apiauth tokens: %w", err)
	}
	defer tokRows.Close()

	count := 0
	for tokRows.Next() {
		var prov, account, scopes, access, refresh string
		var expiresUnix int64
		if err := tokRows.Scan(&prov, &account, &scopes, &access, &refresh, &expiresUnix); err != nil {
			return err
		}
		// apiauth stored expires_at as unix seconds; auth-store uses unix ms.
		expiresMs := expiresUnix * 1000

		c := authstore.Credentials{
			ID:           "cred_apiauth_" + sanitize(prov+"_"+account),
			Provider:     prov,
			Owner:        deriveOwner(prov, account),
			Account:      account,
			Label:        fmt.Sprintf("apiauth: %s/%s", prov, account),
			AuthType:     authstore.AuthTypeOAuth,
			RefreshMode:  authstore.RefreshModeServer,
			Token:        access,
			RefreshToken: refresh,
			ExpiresAt:    expiresMs,
			Priority:     100,
			Enabled:      true,
		}
		if cc, ok := clientCreds[prov]; ok {
			c.ClientID = cc.clientID
			c.ClientSecret = cc.clientSecret
			c.TenantID = cc.tenantID
			c.RedirectURL = cc.redirectURL
		}

		if dryRun {
			log.Printf("  [dry-run] would import apiauth %s/%s as %s (refresh_mode=server)", prov, account, c.ID)
		} else {
			if err := store.Set(c); err != nil {
				return fmt.Errorf("set %s: %w", c.ID, err)
			}
			log.Printf("  imported apiauth %s/%s as %s", prov, account, c.ID)
		}
		count++
	}
	log.Printf("apiauth: %d tokens processed (with %d app credentials)", count, len(clientCreds))
	return nil
}

// ============================================================================
// mailstack → auth-store
// ============================================================================

func migrateMailstack(store *authstore.Store, dryRun bool) error {
	home, _ := os.UserHomeDir()
	path := filepath.Join(home, ".config", "mailstack", "accounts.db")
	src, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return fmt.Errorf("open mailstack db: %w", err)
	}
	defer src.Close()

	rows, err := src.Query(`SELECT name, address, imap_host, imap_port, smtp_host, smtp_port, username, password, tls_mode FROM imap_creds`)
	if err != nil {
		return fmt.Errorf("query mailstack imap_creds: %w", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var name, address, imapHost, smtpHost, username, password, tlsMode string
		var imapPort, smtpPort int
		if err := rows.Scan(&name, &address, &imapHost, &imapPort, &smtpHost, &smtpPort, &username, &password, &tlsMode); err != nil {
			return err
		}
		c := authstore.Credentials{
			ID:          "cred_mailstack_" + sanitize(name),
			Provider:    "imap",
			Owner:       address,
			Account:     address,
			Label:       fmt.Sprintf("mailstack: %s", name),
			IntendedApp: "mailstack",
			AuthType:    authstore.AuthTypePassword,
			RefreshMode: authstore.RefreshModeNone,
			Username:    username,
			Password:    password,
			Host:        imapHost,
			Port:        imapPort,
			TLS:         strings.ToLower(tlsMode) != "none",
			Priority:    100,
			Enabled:     true,
		}
		// SMTP host/port is needed too; stash as base_url since we don't have a
		// dedicated column. Mailstack will need to read it back as e.g.
		// "smtp://host:port" or query a separate field. For now the consumer
		// will hold its own secondary fields if needed. (Phase 4 detail.)
		c.BaseURL = fmt.Sprintf("smtp://%s:%d", smtpHost, smtpPort)

		if dryRun {
			log.Printf("  [dry-run] would import mailstack %s (%s) as %s", name, address, c.ID)
		} else {
			if err := store.Set(c); err != nil {
				return fmt.Errorf("set %s: %w", c.ID, err)
			}
			log.Printf("  imported mailstack %s (%s) as %s", name, address, c.ID)
		}
		count++
	}
	log.Printf("mailstack: %d imap creds processed", count)

	// Also import the timestamps for completeness.
	_ = time.Now()
	return nil
}

// ============================================================================
// helpers
// ============================================================================

func sanitize(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			out = append(out, r)
		case r == '-' || r == '_':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}

// deriveOwner is best-effort: for the common "default" account label or
// missing data, we leave owner empty; the user fills it via UI later.
func deriveOwner(provider, account string) string {
	if account == "" || account == "default" {
		return ""
	}
	if strings.Contains(account, "@") {
		return account
	}
	return ""
}
