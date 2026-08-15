package providers

import (
	"strings"
	"testing"
)

func TestAzureProvider_InitializeAccessToken(t *testing.T) {
	provider := &AzureProvider{}
	err := provider.Initialize(map[string]string{
		"AZURE_VAULT_URL":      "https://localhost:4577/devstoreaccount1-keyvault",
		"AZURE_INSECURE_HTTP":  "true",
		"AZURE_ACCESS_TOKEN":   "fake-token",
		"AZURE_AUTHORITY_HOST": "http://localhost:4577",
	})
	if err != nil {
		t.Fatalf("Initialize() with AZURE_ACCESS_TOKEN error = %v", err)
	}
	if err := provider.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestAzureProvider_InitializeHTTPAuthorityRequiresAccessToken(t *testing.T) {
	provider := &AzureProvider{}
	err := provider.Initialize(map[string]string{
		"AZURE_VAULT_URL":      "https://localhost:4577/devstoreaccount1-keyvault",
		"AZURE_INSECURE_HTTP":  "true",
		"AZURE_TENANT_ID":      "00000000-0000-0000-0000-000000000002",
		"AZURE_CLIENT_ID":      "11111111-1111-1111-1111-111111111111",
		"AZURE_CLIENT_SECRET":  "floci-az-dev-secret",
		"AZURE_AUTHORITY_HOST": "http://localhost:4577",
	})
	if err == nil {
		t.Fatal("Initialize() with HTTP AZURE_AUTHORITY_HOST: want error, got nil")
	}
	if !strings.Contains(err.Error(), "AZURE_ACCESS_TOKEN") {
		t.Fatalf("Initialize() error = %q, want mention of AZURE_ACCESS_TOKEN", err.Error())
	}
}
