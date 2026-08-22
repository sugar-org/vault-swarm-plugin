package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/docker/go-plugins-helpers/secrets"
)

func TestDopplerProviderInitialize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  map[string]string
		wantErr string
	}{
		{
			name:    "missing token",
			config:  map[string]string{},
			wantErr: "DOPPLER_TOKEN is required",
		},
		{
			name: "cli token requires project and config",
			config: map[string]string{
				"DOPPLER_TOKEN": "dp.pt.example",
			},
			wantErr: "DOPPLER_PROJECT and DOPPLER_CONFIG are required",
		},
		{
			name: "service token only",
			config: map[string]string{
				"DOPPLER_TOKEN": "dp.st.example",
			},
		},
		{
			name: "cli token with project and config",
			config: map[string]string{
				"DOPPLER_TOKEN":   "dp.pt.example",
				"DOPPLER_PROJECT": "my-api",
				"DOPPLER_CONFIG":  "dev",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider := &DopplerProvider{}
			err := provider.Initialize(tt.config)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestDopplerProviderGetSecret(t *testing.T) {
	provider, _ := setupDopplerProvider(t, map[string]string{
		"MYSQL_PASSWORD": "secret-value",
		"API_KEY":        "key-value",
	}, "1m")

	t.Run("explicit label", func(t *testing.T) {
		req := secrets.Request{
			SecretName: "mysql_password",
			SecretLabels: map[string]string{
				"doppler_secret_name": "MYSQL_PASSWORD",
			},
		}
		got := mustGetSecret(t, provider, &SecretInfo{
			DockerSecretName: req.SecretName,
			SecretPath:       provider.BuildSecretPath(req),
			SecretField:      "MYSQL_PASSWORD",
			Labels:           req.SecretLabels,
		})
		if got != "secret-value" {
			t.Fatalf("expected secret-value, got %q", got)
		}
	})

	t.Run("uppercase fallback", func(t *testing.T) {
		got := mustGetSecret(t, provider, &SecretInfo{
			DockerSecretName: "api_key",
			SecretPath:       provider.BuildSecretPath(secrets.Request{SecretName: "api_key"}),
			SecretField:      "value",
		})
		if got != "key-value" {
			t.Fatalf("expected key-value, got %q", got)
		}
	})
}

func TestDopplerProviderCaching(t *testing.T) {
	t.Parallel()

	provider, state := setupDopplerProvider(t, map[string]string{"CACHE_TEST": "v1"}, "1m")
	info := &SecretInfo{
		DockerSecretName: "cache_test",
		SecretPath:       "my-api/dev/CACHE_TEST",
		SecretField:      "CACHE_TEST",
	}

	if got := mustGetSecret(t, provider, info); got != "v1" {
		t.Fatalf("expected v1, got %q", got)
	}
	assertRequestCount(t, state, 1)

	state.secrets["CACHE_TEST"] = "v2"
	if got := mustGetSecret(t, provider, info); got != "v1" {
		t.Fatalf("expected cached value v1, got %q", got)
	}
	assertRequestCount(t, state, 1)
}

func TestDopplerProviderRefreshAfterCacheTTL(t *testing.T) {
	t.Parallel()

	provider, state := setupDopplerProvider(t, map[string]string{"ROTATE_ME": "v1"}, "50ms")
	info := &SecretInfo{
		SecretPath:  "my-api/dev/ROTATE_ME",
		SecretField: "ROTATE_ME",
	}

	if got := mustGetSecret(t, provider, info); got != "v1" {
		t.Fatalf("expected v1, got %q", got)
	}
	assertRequestCount(t, state, 1)

	state.secrets["ROTATE_ME"] = "v2"
	if got := mustGetSecret(t, provider, info); got != "v1" {
		t.Fatalf("expected cached value v1, got %q", got)
	}
	assertRequestCount(t, state, 1)

	time.Sleep(75 * time.Millisecond)

	if got := mustGetSecret(t, provider, info); got != "v2" {
		t.Fatalf("expected refreshed value v2, got %q", got)
	}
	assertRequestCount(t, state, 2)
}

func TestDopplerProviderBuildSecretPath(t *testing.T) {
	t.Parallel()

	provider := &DopplerProvider{}
	if err := provider.Initialize(map[string]string{
		"DOPPLER_TOKEN":   "dp.st.example",
		"DOPPLER_PROJECT": "my-api",
		"DOPPLER_CONFIG":  "dev",
	}); err != nil {
		t.Fatalf("initialize failed: %v", err)
	}

	got := provider.BuildSecretPath(secrets.Request{
		SecretName: "mysql_password",
		SecretLabels: map[string]string{
			"doppler_secret_name": "MYSQL_PASSWORD",
		},
	})
	want := "my-api/dev/MYSQL_PASSWORD"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

type dopplerTestState struct {
	secrets      map[string]string
	requestCount atomic.Int32
}

func (s *dopplerTestState) handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != dopplerDownloadPath {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("Authorization") != "Bearer dp.pt.test" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	s.requestCount.Add(1)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.secrets)
}

func setupDopplerProvider(t *testing.T, secretsMap map[string]string, cacheTTL string) (*DopplerProvider, *dopplerTestState) {
	t.Helper()
	state := &dopplerTestState{secrets: secretsMap}
	server := httptest.NewServer(http.HandlerFunc(state.handler))
	t.Cleanup(server.Close)

	provider := &DopplerProvider{}
	if err := provider.Initialize(map[string]string{
		"DOPPLER_TOKEN":     "dp.pt.test",
		"DOPPLER_PROJECT":   "my-api",
		"DOPPLER_CONFIG":    "dev",
		"DOPPLER_API_URL":   server.URL,
		"DOPPLER_CACHE_TTL": cacheTTL,
	}); err != nil {
		t.Fatalf("initialize failed: %v", err)
	}
	return provider, state
}

func mustGetSecret(t *testing.T, provider *DopplerProvider, info *SecretInfo) string {
	t.Helper()
	value, err := provider.GetSecret(context.Background(), info)
	if err != nil {
		t.Fatalf("GetSecret failed: %v", err)
	}
	return string(value)
}

func assertRequestCount(t *testing.T, state *dopplerTestState, want int32) {
	t.Helper()
	if got := state.requestCount.Load(); got != want {
		t.Fatalf("expected %d API calls, got %d", want, got)
	}
}
