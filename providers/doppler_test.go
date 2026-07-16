package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
	server := newDopplerTestServer(map[string]string{
		"MYSQL_PASSWORD": "secret-value",
		"API_KEY":        "key-value",
	})
	defer server.Close()

	provider := &DopplerProvider{}
	if err := provider.Initialize(map[string]string{
		"DOPPLER_TOKEN":     "dp.pt.test",
		"DOPPLER_PROJECT":   "my-api",
		"DOPPLER_CONFIG":    "dev",
		"DOPPLER_API_URL":   server.URL,
		"DOPPLER_CACHE_TTL": "1m",
	}); err != nil {
		t.Fatalf("initialize failed: %v", err)
	}

	ctx := context.Background()

	t.Run("explicit label", func(t *testing.T) {
		req := secrets.Request{
			SecretName: "mysql_password",
			SecretLabels: map[string]string{
				"doppler_secret_name": "MYSQL_PASSWORD",
			},
		}
		secretInfo := &SecretInfo{
			DockerSecretName: req.SecretName,
			SecretPath:       provider.BuildSecretPath(req),
			SecretField:      "MYSQL_PASSWORD",
			Labels:           req.SecretLabels,
		}

		value, err := provider.GetSecret(ctx, secretInfo)
		if err != nil {
			t.Fatalf("GetSecret failed: %v", err)
		}
		if string(value) != "secret-value" {
			t.Fatalf("expected secret-value, got %q", string(value))
		}
	})

	t.Run("uppercase fallback", func(t *testing.T) {
		secretInfo := &SecretInfo{
			DockerSecretName: "api_key",
			SecretPath:       provider.BuildSecretPath(secrets.Request{SecretName: "api_key"}),
			SecretField:      "value",
		}

		value, err := provider.GetSecret(ctx, secretInfo)
		if err != nil {
			t.Fatalf("GetSecret failed: %v", err)
		}
		if string(value) != "key-value" {
			t.Fatalf("expected key-value, got %q", string(value))
		}
	})
}

func TestDopplerProviderCaching(t *testing.T) {
	t.Parallel()

	state := &dopplerTestState{
		secrets: map[string]string{
			"CACHE_TEST": "v1",
		},
	}
	server := httptest.NewServer(http.HandlerFunc(state.handler))
	defer server.Close()

	provider := &DopplerProvider{}
	if err := provider.Initialize(map[string]string{
		"DOPPLER_TOKEN":     "dp.pt.test",
		"DOPPLER_PROJECT":   "my-api",
		"DOPPLER_CONFIG":    "dev",
		"DOPPLER_API_URL":   server.URL,
		"DOPPLER_CACHE_TTL": "1m",
	}); err != nil {
		t.Fatalf("initialize failed: %v", err)
	}

	ctx := context.Background()
	secretInfo := &SecretInfo{
		DockerSecretName: "cache_test",
		SecretPath:       "my-api/dev/CACHE_TEST",
		SecretField:      "CACHE_TEST",
	}

	if _, err := provider.GetSecret(ctx, secretInfo); err != nil {
		t.Fatalf("first GetSecret failed: %v", err)
	}
	if state.requestCount != 1 {
		t.Fatalf("expected 1 API call, got %d", state.requestCount)
	}

	state.secrets["CACHE_TEST"] = "v2"

	if value, err := provider.GetSecret(ctx, secretInfo); err != nil {
		t.Fatalf("cached GetSecret failed: %v", err)
	} else if string(value) != "v1" {
		t.Fatalf("expected cached value v1, got %q", string(value))
	}
	if state.requestCount != 1 {
		t.Fatalf("expected cache hit with 1 API call, got %d", state.requestCount)
	}
}

func TestDopplerProviderRefreshAfterCacheTTL(t *testing.T) {
	t.Parallel()

	state := &dopplerTestState{
		secrets: map[string]string{
			"ROTATE_ME": "v1",
		},
	}
	server := httptest.NewServer(http.HandlerFunc(state.handler))
	defer server.Close()

	provider := &DopplerProvider{}
	if err := provider.Initialize(map[string]string{
		"DOPPLER_TOKEN":     "dp.pt.test",
		"DOPPLER_PROJECT":   "my-api",
		"DOPPLER_CONFIG":    "dev",
		"DOPPLER_API_URL":   server.URL,
		"DOPPLER_CACHE_TTL": "50ms",
	}); err != nil {
		t.Fatalf("initialize failed: %v", err)
	}

	ctx := context.Background()
	secretInfo := &SecretInfo{
		SecretPath:  "my-api/dev/ROTATE_ME",
		SecretField: "ROTATE_ME",
	}

	if value, err := provider.GetSecret(ctx, secretInfo); err != nil {
		t.Fatalf("GetSecret failed: %v", err)
	} else if string(value) != "v1" {
		t.Fatalf("expected v1, got %q", string(value))
	}
	if state.requestCount != 1 {
		t.Fatalf("expected 1 API call, got %d", state.requestCount)
	}

	state.secrets["ROTATE_ME"] = "v2"

	// Within TTL, rotation checks should still see the cached value.
	if value, err := provider.GetSecret(ctx, secretInfo); err != nil {
		t.Fatalf("cached GetSecret failed: %v", err)
	} else if string(value) != "v1" {
		t.Fatalf("expected cached value v1, got %q", string(value))
	}
	if state.requestCount != 1 {
		t.Fatalf("expected cache hit with 1 API call, got %d", state.requestCount)
	}

	time.Sleep(75 * time.Millisecond)

	if value, err := provider.GetSecret(ctx, secretInfo); err != nil {
		t.Fatalf("post-TTL GetSecret failed: %v", err)
	} else if string(value) != "v2" {
		t.Fatalf("expected refreshed value v2, got %q", string(value))
	}
	if state.requestCount != 2 {
		t.Fatalf("expected refresh after TTL with 2 API calls, got %d", state.requestCount)
	}
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
	requestCount int
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

	s.requestCount++
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.secrets)
}

func newDopplerTestServer(secretsMap map[string]string) *httptest.Server {
	state := &dopplerTestState{secrets: secretsMap}
	return httptest.NewServer(http.HandlerFunc(state.handler))
}
