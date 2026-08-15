// Command mock-infisical-server is a minimal Infisical API stub for smoke tests.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

const (
	defaultAddr        = "127.0.0.1:18081"
	maxBodyBytes       = 1 << 20
	loginPath          = "POST /api/v1/auth/universal-auth/login"
	secretPath         = "/api/v4/secrets/{name}"
	defaultSmokeToken  = "infisical-smoke-token" // #nosec G101
	defaultSmokeClient = "smoke-client"
	defaultSmokeSecret = "smoke-secret" // #nosec G101
)

type server struct {
	token        string
	clientID     string
	clientSecret string
	mu           sync.RWMutex
	secrets      map[string]string
}

func main() {
	addr := flag.String("addr", defaultAddr, "listen address")
	token := flag.String("token", defaultSmokeToken, "expected bearer token")
	clientID := flag.String("client-id", defaultSmokeClient, "Universal Auth client id")
	clientSecret := flag.String("client-secret", defaultSmokeSecret, "Universal Auth client secret")
	flag.Parse()

	srv := &server{
		token:        *token,
		clientID:     *clientID,
		clientSecret: *clientSecret,
		secrets:      map[string]string{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc(loginPath, srv.handleLogin)
	mux.HandleFunc("GET "+secretPath, srv.handleGetSecret)
	mux.HandleFunc("POST "+secretPath, srv.handleWriteSecret)
	mux.HandleFunc("PATCH "+secretPath, srv.handleWriteSecret)
	mux.HandleFunc("DELETE "+secretPath, srv.handleDeleteSecret)

	log.Printf("Infisical mock listening on http://%s", *addr)

	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatalf("mock server failed: %v", err)
	}
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
	}
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}
	if req.ClientID != s.clientID || req.ClientSecret != s.clientSecret {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"accessToken": s.token,
		"expiresIn":   7200,
	})
}

func (s *server) handleGetSecret(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	name := r.PathValue("name")
	s.mu.RLock()
	value, ok := s.secrets[name]
	s.mu.RUnlock()
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"secret": map[string]string{"secretValue": value},
	})
}

func (s *server) handleWriteSecret(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		SecretValue string `json:"secretValue"`
	}
	if err := decodeJSON(r, &req); err != nil || req.SecretValue == "" {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	name := r.PathValue("name")
	s.mu.Lock()
	s.secrets[name] = req.SecretValue
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"secret": map[string]string{"secretValue": req.SecretValue},
	})
}

func (s *server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	if !s.authorize(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	name := r.PathValue("name")
	s.mu.Lock()
	delete(s.secrets, name)
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *server) authorize(r *http.Request) bool {
	return r.Header.Get("Authorization") == fmt.Sprintf("Bearer %s", s.token)
}

func decodeJSON(r *http.Request, dest any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, dest)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
