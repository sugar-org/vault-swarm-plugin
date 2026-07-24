package providers

import (
	"context"
	"time"

	"github.com/docker/go-plugins-helpers/secrets"

	"github.com/sugar-org/swarm-external-secrets/internal/utils"
)

// SecretInfo tracks information about secrets being managed
type SecretInfo = utils.SecretInfo

// SecretsProvider defines the interface that all secret providers must implement
type SecretsProvider interface {
	// Initialize sets up the provider with the given configuration
	Initialize(config map[string]string) error

	// GetSecret retrieves a secret value from the provider
	GetSecret(ctx context.Context, secretInfo *SecretInfo) ([]byte, error)

	// SupportsRotation indicates if this provider supports secret rotation monitoring
	SupportsRotation() bool

	// GetSecretFieldLabel returns the label key used by this provider for the secret field
	GetSecretFieldLabel() string

	// BuildSecretPath constructs the provider-specific secret path from a request
	BuildSecretPath(req secrets.Request) string

	// GetProviderName returns the name of this provider
	GetProviderName() string

	// Close performs any cleanup needed by the provider
	Close() error
}

// ProviderConfig holds common configuration for all providers
type ProviderConfig struct {
	ProviderType     string            `json:"provider_type"`
	EnableRotation   bool              `json:"enable_rotation"`
	RotationInterval time.Duration     `json:"rotation_interval"`
	Settings         map[string]string `json:"settings"`
}
