package server

import (
	"net/http"
	"time"

	authstore "github.com/kayushkin/auth-store"
)

const defaultLeaseTTL = 1 * time.Hour

type leaseAcquireResponse struct {
	LeaseID        string `json:"lease_id"`
	AccessToken    string `json:"access_token,omitempty"`
	APIKey         string `json:"api_key,omitempty"`
	RefreshToken   string `json:"refresh_token,omitempty"`
	ExpiresAt      int64  `json:"expires_at,omitempty"`
	LeaseExpiresAt int64  `json:"lease_expires_at"`
}

type leaseHeartbeatRequest struct {
	LeaseID string `json:"lease_id"`
	TTLSec  int64  `json:"ttl_seconds,omitempty"`
}

type leaseReleaseRequest struct {
	LeaseID            string `json:"lease_id"`
	FinalAccessToken   string `json:"final_access_token,omitempty"`
	FinalRefreshToken  string `json:"final_refresh_token,omitempty"`
	FinalExpiresAt     int64  `json:"final_expires_at,omitempty"`
}

type tokenWriteBackRequest struct {
	LeaseID      string `json:"lease_id"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresAt    int64  `json:"expires_at"`
}

type leaseAcquireRequest struct {
	TTLSec int64 `json:"ttl_seconds,omitempty"`
}

func ttlFrom(seconds int64) time.Duration {
	if seconds <= 0 {
		return defaultLeaseTTL
	}
	return time.Duration(seconds) * time.Second
}

func (s *Server) handleAcquireLease(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	app := appFromCtx(r.Context())
	reason := reasonFromCtx(r.Context())

	var in leaseAcquireRequest
	// Body is optional — empty request uses default TTL.
	if r.ContentLength > 0 {
		if err := decodeJSON(r, &in); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
			return
		}
	}
	ttl := ttlFrom(in.TTLSec)

	leaseID, leaseExpires, err := s.cfg.Store.AcquireLease(id, app, ttl)
	if err != nil {
		s.cfg.Store.LogAccess(authstore.AuditEntry{
			CredentialID: id,
			App:          app,
			Reason:       reason,
			Action:       authstore.AuditActionLeaseAcquire,
			OK:           false,
			Error:        err.Error(),
			RemoteAddr:   remoteAddr(r),
		})
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	c, err := s.cfg.Store.Get(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.cfg.Store.LogAccess(authstore.AuditEntry{
		CredentialID:     c.ID,
		Provider:         c.Provider,
		Owner:            c.Owner,
		App:              app,
		Reason:           reason,
		Action:           authstore.AuditActionLeaseAcquire,
		OK:               true,
		IntendedAppMatch: c.IntendedApp == "" || c.IntendedApp == app,
		RemoteAddr:       remoteAddr(r),
	})

	resp := leaseAcquireResponse{
		LeaseID:        leaseID,
		LeaseExpiresAt: leaseExpires,
		ExpiresAt:      c.ExpiresAt,
	}
	switch c.AuthType {
	case authstore.AuthTypeOAuth, authstore.AuthTypeToken:
		resp.AccessToken = c.Token
		resp.RefreshToken = c.RefreshToken
	case authstore.AuthTypeAPIKey:
		resp.APIKey = c.APIKey
	}
	writeJSON(w, http.StatusOK, resp)
}

// credMeta returns provider/owner/intended_app for audit logging on actions
// that don't otherwise need the full credential. Returns zero values if the
// credential can't be loaded — the action may still proceed (e.g. wrong id is
// the caller's problem; we still want to log).
func (s *Server) credMeta(id string) (provider, owner, intendedApp string) {
	c, err := s.cfg.Store.Get(id)
	if err != nil {
		return "", "", ""
	}
	return c.Provider, c.Owner, c.IntendedApp
}

func (s *Server) handleHeartbeatLease(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	app := appFromCtx(r.Context())
	reason := reasonFromCtx(r.Context())
	provider, owner, intendedApp := s.credMeta(id)

	var in leaseHeartbeatRequest
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if in.LeaseID == "" {
		writeError(w, http.StatusBadRequest, "lease_id is required")
		return
	}
	ttl := ttlFrom(in.TTLSec)

	expires, err := s.cfg.Store.HeartbeatLease(id, in.LeaseID, ttl)
	if err != nil {
		s.cfg.Store.LogAccess(authstore.AuditEntry{
			CredentialID:     id,
			Provider:         provider,
			Owner:            owner,
			App:              app,
			Reason:           reason,
			Action:           authstore.AuditActionLeaseHeartbeat,
			OK:               false,
			Error:            err.Error(),
			IntendedAppMatch: intendedApp == "" || intendedApp == app,
			RemoteAddr:       remoteAddr(r),
		})
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	s.cfg.Store.LogAccess(authstore.AuditEntry{
		CredentialID:     id,
		Provider:         provider,
		Owner:            owner,
		App:              app,
		Reason:           reason,
		Action:           authstore.AuditActionLeaseHeartbeat,
		OK:               true,
		IntendedAppMatch: intendedApp == "" || intendedApp == app,
		RemoteAddr:       remoteAddr(r),
	})

	writeJSON(w, http.StatusOK, map[string]int64{"lease_expires_at": expires})
}

func (s *Server) handleReleaseLease(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	app := appFromCtx(r.Context())
	reason := reasonFromCtx(r.Context())
	provider, owner, intendedApp := s.credMeta(id)

	var in leaseReleaseRequest
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if in.LeaseID == "" {
		writeError(w, http.StatusBadRequest, "lease_id is required")
		return
	}

	if err := s.cfg.Store.ReleaseLease(id, in.LeaseID, in.FinalAccessToken, in.FinalRefreshToken, in.FinalExpiresAt); err != nil {
		s.cfg.Store.LogAccess(authstore.AuditEntry{
			CredentialID:     id,
			Provider:         provider,
			Owner:            owner,
			App:              app,
			Reason:           reason,
			Action:           authstore.AuditActionLeaseRelease,
			OK:               false,
			Error:            err.Error(),
			IntendedAppMatch: intendedApp == "" || intendedApp == app,
			RemoteAddr:       remoteAddr(r),
		})
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	s.cfg.Store.LogAccess(authstore.AuditEntry{
		CredentialID:     id,
		Provider:         provider,
		Owner:            owner,
		App:              app,
		Reason:           reason,
		Action:           authstore.AuditActionLeaseRelease,
		OK:               true,
		IntendedAppMatch: intendedApp == "" || intendedApp == app,
		RemoteAddr:       remoteAddr(r),
	})

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleWriteBackTokens(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	app := appFromCtx(r.Context())
	reason := reasonFromCtx(r.Context())
	provider, owner, intendedApp := s.credMeta(id)

	var in tokenWriteBackRequest
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if in.LeaseID == "" {
		writeError(w, http.StatusBadRequest, "lease_id is required")
		return
	}
	if in.AccessToken == "" {
		writeError(w, http.StatusBadRequest, "access_token is required")
		return
	}
	if in.ExpiresAt == 0 {
		writeError(w, http.StatusBadRequest, "expires_at is required")
		return
	}

	if err := s.cfg.Store.WriteBackTokens(id, in.LeaseID, in.AccessToken, in.RefreshToken, in.ExpiresAt); err != nil {
		s.cfg.Store.LogAccess(authstore.AuditEntry{
			CredentialID:     id,
			Provider:         provider,
			Owner:            owner,
			App:              app,
			Reason:           reason,
			Action:           authstore.AuditActionWriteBack,
			OK:               false,
			Error:            err.Error(),
			IntendedAppMatch: intendedApp == "" || intendedApp == app,
			RemoteAddr:       remoteAddr(r),
		})
		writeError(w, http.StatusConflict, err.Error())
		return
	}

	s.cfg.Store.LogAccess(authstore.AuditEntry{
		CredentialID:     id,
		Provider:         provider,
		Owner:            owner,
		App:              app,
		Reason:           reason,
		Action:           authstore.AuditActionWriteBack,
		OK:               true,
		IntendedAppMatch: intendedApp == "" || intendedApp == app,
		RemoteAddr:       remoteAddr(r),
	})

	w.WriteHeader(http.StatusNoContent)
}
