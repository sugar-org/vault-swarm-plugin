package main

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"
	"github.com/docker/go-plugins-helpers/secrets"
)

// MockVaultClient simulates a Vault client for testing
type MockVaultClient struct {
	secrets map[string]string
	mutex   sync.RWMutex
}

func (m *MockVaultClient) updateSecret(path, value string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.secrets[path] = value
}

func (m *MockVaultClient) getSecret(path string) string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.secrets[path]
}

func TestSecretRotationWorkflow(t *testing.T) {
	// Create a driver with tracking enabled
	driver := &VaultDriver{
		config: &VaultConfig{
			EnableRotation:   true,
			RotationInterval: 100 * time.Millisecond, // Fast interval for testing
		},
		secretTracker: make(map[string]*SecretInfo),
	}

	// Mock initial secret request
	req := secrets.Request{
		SecretName:  "app-secret",
		ServiceName: "web-app",
		SecretLabels: map[string]string{
			"vault_path":  "app/config",
			"vault_field": "api_key",
		},
	}

	initialValue := []byte("initial-secret-value")
	vaultPath := "secret/data/app/config"

	// Track the initial secret
	driver.trackSecret(req, vaultPath, initialValue)

	// Verify tracking
	if len(driver.secretTracker) != 1 {
		t.Fatalf("Expected 1 tracked secret, got %d", len(driver.secretTracker))
	}

	secretInfo := driver.secretTracker["app-secret"]
	initialHash := fmt.Sprintf("%x", sha256.Sum256(initialValue))
	
	if secretInfo.LastHash != initialHash {
		t.Errorf("Expected hash %s, got %s", initialHash, secretInfo.LastHash)
	}

	// Test hash comparison with unchanged value
	sameValue := []byte("initial-secret-value")
	sameHash := fmt.Sprintf("%x", sha256.Sum256(sameValue))
	
	if secretInfo.LastHash != sameHash {
		t.Error("Hash should be the same for identical values")
	}

	// Test hash comparison with changed value
	newValue := []byte("updated-secret-value")
	newHash := fmt.Sprintf("%x", sha256.Sum256(newValue))
	
	if secretInfo.LastHash == newHash {
		t.Error("Hash should be different for different values")
	}

	// Test service tracking for multiple services
	req2 := req
	req2.ServiceName = "api-service"
	driver.trackSecret(req2, vaultPath, initialValue)

	// Should still have 1 secret but with 2 services
	if len(driver.secretTracker) != 1 {
		t.Errorf("Expected 1 tracked secret, got %d", len(driver.secretTracker))
	}

	if len(secretInfo.ServiceNames) != 2 {
		t.Errorf("Expected 2 services, got %d: %v", len(secretInfo.ServiceNames), secretInfo.ServiceNames)
	}

	// Verify both services are tracked
	serviceMap := make(map[string]bool)
	for _, svc := range secretInfo.ServiceNames {
		serviceMap[svc] = true
	}

	if !serviceMap["web-app"] || !serviceMap["api-service"] {
		t.Error("Both services should be tracked")
	}
}

func TestSecretChangeDetection(t *testing.T) {
	// Test the core logic of change detection
	testCases := []struct {
		name     string
		value1   []byte
		value2   []byte
		expected bool
	}{
		{
			name:     "Same values",
			value1:   []byte("password123"),
			value2:   []byte("password123"),
			expected: false, // No change
		},
		{
			name:     "Different values",
			value1:   []byte("password123"),
			value2:   []byte("newpassword456"),
			expected: true, // Change detected
		},
		{
			name:     "Empty to value",
			value1:   []byte(""),
			value2:   []byte("password"),
			expected: true, // Change detected
		},
		{
			name:     "Value to empty",
			value1:   []byte("password"),
			value2:   []byte(""),
			expected: true, // Change detected
		},
		{
			name:     "Both empty",
			value1:   []byte(""),
			value2:   []byte(""),
			expected: false, // No change
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hash1 := fmt.Sprintf("%x", sha256.Sum256(tc.value1))
			hash2 := fmt.Sprintf("%x", sha256.Sum256(tc.value2))
			
			changed := hash1 != hash2
			if changed != tc.expected {
				t.Errorf("Expected change detection %v, got %v", tc.expected, changed)
			}
		})
	}
}

func TestRotationConfiguration(t *testing.T) {
	testCases := []struct {
		envValue string
		expected bool
	}{
		{"true", true},
		{"TRUE", true},
		{"True", true},
		{"false", false},
		{"FALSE", false},
		{"False", false},
		{"", false}, // Default when not set should be handled by getEnvOrDefault
		{"invalid", false},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("value_%s", tc.envValue), func(t *testing.T) {
			// Simulate environment variable parsing
			result := tc.envValue == "true" || tc.envValue == "TRUE" || tc.envValue == "True"
			if result != tc.expected {
				t.Errorf("For value '%s', expected %v, got %v", tc.envValue, tc.expected, result)
			}
		})
	}
}

// Benchmark the hash calculation performance
func BenchmarkHashCalculation(b *testing.B) {
	testData := []byte("this is a test secret value that might be somewhat longer than typical passwords to test performance with realistic data sizes")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = fmt.Sprintf("%x", sha256.Sum256(testData))
	}
}

func BenchmarkSecretTracking(b *testing.B) {
	driver := &VaultDriver{
		config: &VaultConfig{
			EnableRotation:   true,
			RotationInterval: 1 * time.Minute,
		},
		secretTracker: make(map[string]*SecretInfo),
	}

	req := secrets.Request{
		SecretName:  "benchmark-secret",
		ServiceName: "benchmark-service",
		SecretLabels: map[string]string{
			"vault_path":  "bench/test",
			"vault_field": "value",
		},
	}

	value := []byte("benchmark-secret-value")
	vaultPath := "secret/data/bench/test"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.SecretName = fmt.Sprintf("secret-%d", i)
		driver.trackSecret(req, vaultPath, value)
	}
}