// Package dopplerwebhook implements the HTTP listener that receives Doppler
// webhook deliveries and triggers an immediate rotation check, bypassing the
// poll interval. It understands Doppler's payload and request-signing scheme
// (HMAC-SHA256 via the X-Doppler-Signature header).
package dopplerwebhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// signatureHeader carries the HMAC-SHA256 signature of the body, prefixed
	// with "sha256=" (see Doppler webhook request-signing docs).
	signatureHeader = "X-Doppler-Signature"

	// secretsUpdateType is the only event type this listener acts on.
	secretsUpdateType = "config.secrets.update"

	// maxBodyBytes caps how much of the request body we read.
	maxBodyBytes = 1 << 20 // 1 MiB

	// defaultPath is used when an empty path is supplied.
	defaultPath = "/webhooks/doppler"
)

// Payload is the subset of Doppler's webhook payload we act on.
type Payload struct {
	Type string `json:"type"`
	Diff struct {
		Added   []string `json:"added"`
		Removed []string `json:"removed"`
		Updated []string `json:"updated"`
	} `json:"diff"`
}

// Server receives Doppler webhook deliveries and triggers a rotation check via
// the onEvent callback. The plugin runs with host networking, so the listener
// is reachable at the host's <port>.
type Server struct {
	server  *http.Server
	path    string
	secret  string
	onEvent func(Payload)
}

// New builds a Doppler webhook listener. onEvent is invoked asynchronously
// after a request is authenticated and parsed.
func New(addr, path, secret string, onEvent func(Payload)) *Server {
	if path == "" {
		path = defaultPath
	}

	mux := http.NewServeMux()
	s := &Server{
		server: &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       30 * time.Second,
		},
		path:    path,
		secret:  secret,
		onEvent: onEvent,
	}
	mux.HandleFunc(path, s.handle)
	return s
}

// Start begins serving in the background.
func (s *Server) Start() {
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorf("Webhook server error: %v", err)
		}
	}()
	log.Infof("Started Doppler webhook listener on %s%s", s.server.Addr, s.path)
}

// Stop gracefully shuts down the webhook listener.
func (s *Server) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	if !s.verifySignature(r.Header.Get(signatureHeader), body) {
		log.Warn("Rejected Doppler webhook: invalid signature")
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	var payload Payload
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	// Custom payloads may omit "type"; only skip when a non-matching type is set.
	if payload.Type != "" && payload.Type != secretsUpdateType {
		log.Debugf("Ignoring Doppler webhook of type %q", payload.Type)
		w.WriteHeader(http.StatusOK)
		return
	}

	log.Infof("Received Doppler webhook (added=%d removed=%d updated=%d); triggering rotation check",
		len(payload.Diff.Added), len(payload.Diff.Removed), len(payload.Diff.Updated))

	// Respond immediately: Doppler delivery is best-effort and time-limited, so
	// the rotation check runs asynchronously.
	w.WriteHeader(http.StatusOK)

	if s.onEvent != nil {
		go s.onEvent(payload)
	}
}

// verifySignature reports whether the request is authentic.
//
// Doppler signs each delivery with HMAC-SHA256 over the raw body, keyed by the
// configured signing secret, and sends it as "X-Doppler-Signature: sha256=<hex>".
// When no secret is configured, verification is skipped (Doppler permits
// unsigned webhooks); this is discouraged and warned about at startup.
func (s *Server) verifySignature(header string, body []byte) bool {
	if s.secret == "" {
		return true
	}

	got := strings.TrimPrefix(strings.TrimSpace(header), "sha256=")
	if got == "" {
		return false
	}

	mac := hmac.New(sha256.New, []byte(s.secret))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(got), []byte(want))
}
