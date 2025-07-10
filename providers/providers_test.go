package providers

import (
	"context"
	"testing"

	"github.com/docker/go-plugins-helpers/secrets"
	"github.com/stretchr/testify/assert"
)

func TestCreateProvider(t *testing.T) {
	tests := []struct {
		name         string
		providerType string
		expectError  bool
	}{
		{"Vault provider", "vault", false},
		{"AWS provider", "aws", false},
		{"GCP provider", "gcp", false},
		{"Azure provider", "azure", false},
		{"OpenBao provider", "openbao", false},
		{"Invalid provider", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := CreateProvider(tt.providerType)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, provider)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, provider)
				assert.Equal(t, tt.providerType, provider.GetProviderName())
			}
		})
	}
}

func TestGetSupportedProviders(t *testing.T) {
	providers := GetSupportedProviders()
	expected := []string{"vault", "aws", "gcp", "azure", "openbao"}
	
	assert.Equal(t, expected, providers)
}

func TestGetProviderInfo(t *testing.T) {
	tests := []struct {
		name         string
		providerType string
		expectError  bool
	}{
		{"Vault info", "vault", false},
		{"AWS info", "aws", false},
		{"GCP info", "gcp", false},
		{"Azure info", "azure", false},
		{"OpenBao info", "openbao", false},
		{"Invalid provider info", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := GetProviderInfo(tt.providerType)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, info)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, info)
				assert.Contains(t, info, "name")
				assert.Contains(t, info, "description")
				assert.Contains(t, info, "auth_methods")
				assert.Contains(t, info, "env_vars")
			}
		})
	}
}

func TestGCPProviderPlaceholder(t *testing.T) {
	provider := &GCPProvider{}
	
	// Test initialization fails with placeholder
	config := map[string]string{
		"GCP_PROJECT_ID": "test-project",
	}
	err := provider.Initialize(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not yet fully implemented")
	
	// Test other methods return errors or false
	assert.False(t, provider.SupportsRotation())
	assert.Equal(t, "gcp", provider.GetProviderName())
	
	_, err = provider.GetSecret(context.Background(), secrets.Request{})
	assert.Error(t, err)
	
	_, err = provider.CheckSecretChanged(context.Background(), &SecretInfo{})
	assert.Error(t, err)
	
	err = provider.Close()
	assert.NoError(t, err)
}

func TestVaultProvider(t *testing.T) {
	provider := &VaultProvider{}
	
	// Test provider name
	assert.Equal(t, "vault", provider.GetProviderName())
	
	// Test supports rotation
	assert.True(t, provider.SupportsRotation())
	
	// Test close doesn't error
	err := provider.Close()
	assert.NoError(t, err)
}

func TestAWSProvider(t *testing.T) {
	provider := &AWSProvider{}
	
	// Test provider name
	assert.Equal(t, "aws", provider.GetProviderName())
	
	// Test supports rotation
	assert.True(t, provider.SupportsRotation())
	
	// Test close doesn't error
	err := provider.Close()
	assert.NoError(t, err)
}

func TestAzureProvider(t *testing.T) {
	provider := &AzureProvider{}
	
	// Test provider name
	assert.Equal(t, "azure", provider.GetProviderName())
	
	// Test supports rotation
	assert.True(t, provider.SupportsRotation())
	
	// Test close doesn't error
	err := provider.Close()
	assert.NoError(t, err)
}

func TestOpenBaoProvider(t *testing.T) {
	provider := &OpenBaoProvider{}
	
	// Test provider name
	assert.Equal(t, "openbao", provider.GetProviderName())
	
	// Test supports rotation
	assert.True(t, provider.SupportsRotation())
	
	// Test close doesn't error
	err := provider.Close()
	assert.NoError(t, err)
}