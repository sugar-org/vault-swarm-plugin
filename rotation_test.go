package main

import (
	"testing"
	"time"
	"github.com/docker/go-plugins-helpers/secrets"
	"swarm-vault/providers"
)

func TestSecretTracking(t *testing.T) {
	// Create a mock provider
	mockProvider := &providers.VaultProvider{}
	
	// Create a mock VaultDriver for testing
	driver := &VaultDriver{
		provider: mockProvider,
		config: &VaultConfig{
			ProviderType:     "vault",
			EnableRotation:   true,
			RotationInterval: 1 * time.Minute,
		},
		secretTracker: make(map[string]*providers.SecretInfo),
	}

	// Mock a secret request
	req := secrets.Request{
		SecretName:  "test-secret",
		ServiceName: "test-service",
		SecretLabels: map[string]string{
			"vault_path":  "database/mysql",
			"vault_field": "password",
		},
	}

	secretValue := []byte("test-password")

	// Test secret tracking
	driver.trackSecret(req, secretValue)

	// Check if secret is tracked
	if len(driver.secretTracker) != 1 {
		t.Errorf("Expected 1 tracked secret, got %d", len(driver.secretTracker))
	}

	secretInfo, exists := driver.secretTracker["test-secret"]
	if !exists {
		t.Error("Secret not found in tracker")
	}

	if secretInfo.DockerSecretName != "test-secret" {
		t.Errorf("Expected secret name 'test-secret', got '%s'", secretInfo.DockerSecretName)
	}

	if secretInfo.SecretPath != "secret/data/database/mysql" {
		t.Errorf("Expected secret path 'secret/data/database/mysql', got '%s'", secretInfo.SecretPath)
	}

	if secretInfo.SecretField != "password" {
		t.Errorf("Expected secret field 'password', got '%s'", secretInfo.SecretField)
	}

	// Test adding same secret with different service
	req2 := req
	req2.ServiceName = "another-service"
	driver.trackSecret(req2, secretValue)

	// Should still have 1 secret but with 2 services
	if len(driver.secretTracker) != 1 {
		t.Errorf("Expected 1 tracked secret after adding same secret, got %d", len(driver.secretTracker))
	}

	if len(secretInfo.ServiceNames) != 2 {
		t.Errorf("Expected 2 services using the secret, got %d", len(secretInfo.ServiceNames))
	}
}

func TestParseDurationOrDefault(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
	}{
		{"5m", 5 * time.Minute},
		{"1h", 1 * time.Hour},
		{"30s", 30 * time.Second},
		{"invalid", 5 * time.Minute}, // Should return default
		{"", 5 * time.Minute},        // Should return default
	}

	for _, test := range tests {
		result := parseDurationOrDefault(test.input)
		if result != test.expected {
			t.Errorf("For input '%s', expected %v, got %v", test.input, test.expected, result)
		}
	}
}

func TestConfigurationDefaults(t *testing.T) {
	// Test environment variable defaults
	addr := getEnvOrDefault("NONEXISTENT_VAR", "default-value")
	if addr != "default-value" {
		t.Errorf("Expected 'default-value', got '%s'", addr)
	}

	// Test that rotation is enabled by default
	enableRotation := getEnvOrDefault("VAULT_ENABLE_ROTATION", "true") == "true"
	if !enableRotation {
		t.Error("Expected rotation to be enabled by default")
	}
}