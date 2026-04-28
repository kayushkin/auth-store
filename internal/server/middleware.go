package server

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
)

type ctxKey string

const (
	ctxKeyApp    ctxKey = "auth-app"
	ctxKeyReason ctxKey = "auth-reason"
)

// protected requires a valid bearer token (if AuthToken is set) on /api/* routes.
func (s *Server) protected(h http.HandlerFunc) http.Handler {
	return s.bearer(http.HandlerFunc(h))
}

// keyAccess requires bearer + X-Auth-App + X-Auth-Reason headers (or query equivalents).
// Used for routes that touch credential material.
func (s *Server) keyAccess(h http.HandlerFunc) http.Handler {
	return s.bearer(s.requireAppReason(http.HandlerFunc(h)))
}

func (s *Server) bearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AuthToken == "" {
			next.ServeHTTP(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") || auth[7:] != s.cfg.AuthToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAppReason(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		app := r.Header.Get("X-Auth-App")
		if app == "" {
			app = r.URL.Query().Get("app")
		}
		reason := r.Header.Get("X-Auth-Reason")
		if reason == "" {
			reason = r.URL.Query().Get("reason")
		}
		if app == "" || reason == "" {
			http.Error(w, "X-Auth-App and X-Auth-Reason are required", http.StatusBadRequest)
			return
		}
		ctx := context.WithValue(r.Context(), ctxKeyApp, app)
		ctx = context.WithValue(ctx, ctxKeyReason, reason)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func appFromCtx(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyApp).(string)
	return v
}

func reasonFromCtx(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyReason).(string)
	return v
}

func remoteAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		log.Printf("write json: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decodeJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return errors.New("missing body")
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
