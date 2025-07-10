package providers

import (
	"context"
	"fmt"

	"github.com/docker/go-plugins-helpers/secrets"
	log "github.com/sirupsen/logrus"
)

// GCPProvider implements the SecretsProvider interface for GCP Secret Manager
// Note: This is a placeholder implementation
type GCPProvider struct {
	config *GCPConfig
}

// GCPConfig holds the configuration for the GCP Secret Manager client
type GCPConfig struct {
	ProjectID           string
	CredentialsPath     string
	CredentialsJSON     string
}

// Initialize sets up the GCP provider with the given configuration
func (g *GCPProvider) Initialize(config map[string]string) error {
	g.config = &GCPConfig{
		ProjectID:           getConfigOrDefault(config, "GCP_PROJECT_ID", ""),
		CredentialsPath:     config["GOOGLE_APPLICATION_CREDENTIALS"],
		CredentialsJSON:     config["GCP_CREDENTIALS_JSON"],
	}

	if g.config.ProjectID == "" {
		return fmt.Errorf("GCP_PROJECT_ID is required")
	}

	log.Printf("Successfully initialized GCP Secret Manager provider for project: %s (placeholder)", g.config.ProjectID)
	return fmt.Errorf("GCP provider is not yet fully implemented - use vault, aws, azure, or openbao providers")
}

// GetSecret retrieves a secret value from GCP Secret Manager
func (g *GCPProvider) GetSecret(ctx context.Context, req secrets.Request) ([]byte, error) {
	return nil, fmt.Errorf("GCP provider is not yet implemented")
}

// SupportsRotation indicates that GCP Secret Manager supports secret rotation monitoring
func (g *GCPProvider) SupportsRotation() bool {
	return false // Disabled for now
}

// CheckSecretChanged checks if a secret has changed in GCP Secret Manager
func (g *GCPProvider) CheckSecretChanged(ctx context.Context, secretInfo *SecretInfo) (bool, error) {
	return false, fmt.Errorf("GCP provider is not yet implemented")
}

// GetProviderName returns the name of this provider
func (g *GCPProvider) GetProviderName() string {
	return "gcp"
}

// Close performs cleanup for the GCP provider
func (g *GCPProvider) Close() error {
	return nil
}