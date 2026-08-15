package providers

import (
	"testing"
)

func TestGCPProvider_InitializeEmulatorHost(t *testing.T) {
	provider := &GCPProvider{}
	err := provider.Initialize(map[string]string{
		"GCP_PROJECT_ID":               "floci-local",
		"SECRET_MANAGER_EMULATOR_HOST": "localhost:4588",
	})
	if err != nil {
		t.Fatalf("Initialize() with SECRET_MANAGER_EMULATOR_HOST error = %v", err)
	}
	if provider.config.EmulatorHost != "localhost:4588" {
		t.Fatalf("EmulatorHost = %q, want localhost:4588", provider.config.EmulatorHost)
	}
	if err := provider.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestGCPProvider_InitializeEmulatorHostStripsScheme(t *testing.T) {
	provider := &GCPProvider{}
	err := provider.Initialize(map[string]string{
		"GCP_PROJECT_ID": "floci-local",
		"GCP_ENDPOINT":   "http://localhost:4588",
	})
	if err != nil {
		t.Fatalf("Initialize() with GCP_ENDPOINT error = %v", err)
	}
	if provider.config.EmulatorHost != "localhost:4588" {
		t.Fatalf("EmulatorHost = %q, want localhost:4588", provider.config.EmulatorHost)
	}
	if err := provider.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}
