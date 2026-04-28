package server

import (
	"net/http"
	"strconv"

	authstore "github.com/kayushkin/auth-store"
)

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := authstore.AuditFilter{
		CredentialID: q.Get("credential_id"),
		Provider:     q.Get("provider"),
		Owner:        q.Get("owner"),
		App:          q.Get("app"),
		Action:       q.Get("action"),
		SinceMs:      atoi64(q.Get("since")),
		UntilMs:      atoi64(q.Get("until")),
		Limit:        atoi(q.Get("limit"), 200),
		Offset:       atoi(q.Get("offset"), 0),
	}
	entries, err := s.cfg.Store.QueryAudit(f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

func atoi(s string, def int) int {
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return v
}

func atoi64(s string) int64 {
	if s == "" {
		return 0
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}
