package authstore

import (
	"database/sql"
	"fmt"
	"time"
)

// AuditEntry is a single row from key_access_log.
type AuditEntry struct {
	ID               int64  `json:"id"`
	TS               int64  `json:"ts"`
	CredentialID     string `json:"credential_id,omitempty"`
	Provider         string `json:"provider,omitempty"`
	Owner            string `json:"owner,omitempty"`
	App              string `json:"app"`
	Reason           string `json:"reason"`
	Action           string `json:"action"`
	OK               bool   `json:"ok"`
	Error            string `json:"error,omitempty"`
	IntendedAppMatch bool   `json:"intended_app_match"`
	RemoteAddr       string `json:"remote_addr,omitempty"`
}

// Audit actions.
const (
	AuditActionResolve        = "resolve"
	AuditActionLeaseAcquire   = "lease_acquire"
	AuditActionLeaseHeartbeat = "lease_heartbeat"
	AuditActionLeaseRelease   = "lease_release"
	AuditActionWriteBack      = "write_back"
	AuditActionCreate         = "create"
	AuditActionUpdate         = "update"
	AuditActionDelete         = "delete"
	AuditActionList           = "list"
	AuditActionOAuthLogin     = "oauth_login"
	AuditActionOAuthCallback  = "oauth_callback"
	AuditActionRefresh        = "refresh"
)

// LogAccess records an audit entry. Should not block the caller on errors —
// log to stderr but propagate so callers can decide.
func (s *Store) LogAccess(e AuditEntry) error {
	if e.TS == 0 {
		e.TS = time.Now().UnixMilli()
	}
	ok := 0
	if e.OK {
		ok = 1
	}
	match := 0
	if e.IntendedAppMatch {
		match = 1
	}
	_, err := s.db.Exec(`
		INSERT INTO key_access_log
			(ts, credential_id, provider, owner, app, reason, action, ok, error, intended_app_match, remote_addr)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.TS, e.CredentialID, e.Provider, e.Owner, e.App, e.Reason, e.Action, ok, e.Error, match, e.RemoteAddr,
	)
	return err
}

// AuditFilter narrows a QueryAudit() call. Zero values are ignored.
type AuditFilter struct {
	CredentialID string
	Provider     string
	Owner        string
	App          string
	Action       string
	SinceMs      int64
	UntilMs      int64
	Limit        int
	Offset       int
}

// QueryAudit returns audit entries matching the filter, newest first.
func (s *Store) QueryAudit(f AuditFilter) ([]AuditEntry, error) {
	q := `SELECT id, ts, credential_id, provider, owner, app, reason, action, ok, error, intended_app_match, remote_addr
	      FROM key_access_log WHERE 1=1`
	var args []any
	if f.CredentialID != "" {
		q += ` AND credential_id = ?`
		args = append(args, f.CredentialID)
	}
	if f.Provider != "" {
		q += ` AND provider = ?`
		args = append(args, f.Provider)
	}
	if f.Owner != "" {
		q += ` AND owner = ?`
		args = append(args, f.Owner)
	}
	if f.App != "" {
		q += ` AND app = ?`
		args = append(args, f.App)
	}
	if f.Action != "" {
		q += ` AND action = ?`
		args = append(args, f.Action)
	}
	if f.SinceMs > 0 {
		q += ` AND ts >= ?`
		args = append(args, f.SinceMs)
	}
	if f.UntilMs > 0 {
		q += ` AND ts <= ?`
		args = append(args, f.UntilMs)
	}
	q += ` ORDER BY ts DESC, id DESC`
	if f.Limit > 0 {
		q += ` LIMIT ?`
		args = append(args, f.Limit)
		if f.Offset > 0 {
			q += ` OFFSET ?`
			args = append(args, f.Offset)
		}
	}

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("query audit: %w", err)
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		e, err := scanAudit(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

func scanAudit(rows *sql.Rows) (AuditEntry, error) {
	var e AuditEntry
	var ok, match int
	var credID, provider, owner, errMsg, remoteAddr sql.NullString
	if err := rows.Scan(&e.ID, &e.TS, &credID, &provider, &owner, &e.App, &e.Reason, &e.Action, &ok, &errMsg, &match, &remoteAddr); err != nil {
		return e, err
	}
	e.CredentialID = credID.String
	e.Provider = provider.String
	e.Owner = owner.String
	e.Error = errMsg.String
	e.RemoteAddr = remoteAddr.String
	e.OK = ok != 0
	e.IntendedAppMatch = match != 0
	return e, nil
}
