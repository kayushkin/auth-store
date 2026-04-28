package server

import (
	"net/http"
)

// Phase 2 stubs — actual OAuth flow ships with the provider plugins.

func (s *Server) handleStartOAuthLogin(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "OAuth flow not yet implemented (Phase 2)")
}

func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "OAuth callback not yet implemented (Phase 2)")
}
