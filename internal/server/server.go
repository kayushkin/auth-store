// Package server hosts the HTTP API for auth-store.
package server

import (
	"net/http"
	"time"

	authstore "github.com/kayushkin/auth-store"
	"github.com/kayushkin/llm-bridge/servicesettings"
)

// Config wires the server to its dependencies.
type Config struct {
	Store       *authstore.Store
	AuthToken   string // bearer token for /api/*; empty disables auth (with warning logged at startup)
	CallbackURL string // public URL of /oauth/callback (used when starting OAuth flows)
	// Settings is what GET /settings describes. Required: New panics without
	// it, at boot, rather than at the first read of the route.
	Settings *servicesettings.Registry
}

// Server is the auth-store HTTP server.
type Server struct {
	cfg   Config
	mux   *http.ServeMux
	flows *flowRegistry
}

// New constructs a Server.
func New(cfg Config) *Server {
	if cfg.Settings == nil {
		panic("auth-store: server.New needs the settings registry that GET /settings serves")
	}
	s := &Server{
		cfg:   cfg,
		mux:   http.NewServeMux(),
		flows: newFlowRegistry(),
	}
	s.routes()
	go s.flowSweepLoop()
	return s
}

// Handler returns the root http.Handler.
func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) routes() {
	// Public.
	s.mux.HandleFunc("GET /health", s.handleHealth)
	s.mux.HandleFunc("GET /oauth/callback", s.handleOAuthCallback)

	// Protected.
	s.mux.Handle("GET /api/credentials", s.protected(s.handleListCredentials))
	s.mux.Handle("GET /api/credentials/{id}", s.protected(s.handleGetCredential))
	s.mux.Handle("POST /api/credentials", s.protected(s.handleCreateCredential))
	s.mux.Handle("PUT /api/credentials/{id}", s.protected(s.handleUpdateCredential))
	s.mux.Handle("DELETE /api/credentials/{id}", s.protected(s.handleDeleteCredential))

	// Resolve / lease / write-back require both bearer + X-Auth-App + X-Auth-Reason.
	s.mux.Handle("GET /api/credentials/{id}/resolve", s.keyAccess(s.handleResolveByID))
	s.mux.Handle("GET /api/resolve/{provider}", s.keyAccess(s.handleResolveByProvider))

	s.mux.Handle("POST /api/credentials/{id}/lease", s.keyAccess(s.handleAcquireLease))
	s.mux.Handle("POST /api/credentials/{id}/lease/heartbeat", s.keyAccess(s.handleHeartbeatLease))
	s.mux.Handle("DELETE /api/credentials/{id}/lease", s.keyAccess(s.handleReleaseLease))
	s.mux.Handle("PUT /api/credentials/{id}/tokens", s.keyAccess(s.handleWriteBackTokens))

	// OAuth flow.
	s.mux.Handle("POST /api/oauth/{provider}/login", s.protected(s.handleStartOAuthLogin))
	s.mux.Handle("POST /api/oauth/{provider}/complete", s.protected(s.handleCompleteOAuthLogin))

	// Audit.
	s.mux.Handle("GET /api/audit", s.protected(s.handleAudit))

	// Settings: every environment variable the service reads, behind the same
	// bearer as /api/*. The token is served as set or unset, never its value.
	// PUT /settings/{key} is not mounted: no setting is Editable.
	s.mux.Handle("GET /settings", s.protected(servicesettings.Handler(s.cfg.Settings, "/settings").ServeHTTP))
}

// flowSweepLoop periodically removes pending OAuth flows that never completed.
func (s *Server) flowSweepLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.flows.sweep(15 * time.Minute)
	}
}
