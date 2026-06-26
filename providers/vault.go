package providers

import (
	"context"
	"fmt"
	"path"

	"github.com/docker/go-plugins-helpers/secrets"
	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"

	"github.com/sugar-org/swarm-external-secrets/internal/kvpath"
	"github.com/sugar-org/swarm-external-secrets/internal/utils"
)

// VaultProvider implements the SecretsProvider interface for HashiCorp Vault
type VaultProvider struct {
	client *api.Client
	config *SecretsConfig
}

// SecretsConfig holds the configuration for the Vault client
type SecretsConfig struct {
	Address    string
	Token      string
	MountPath  string
	RoleID     string
	SecretID   string
	AuthMethod string
	CACert     string
	ClientCert string
	ClientKey  string // #nosec G117
	SkipVerify bool
}

// Initialize sets up the Vault provider with the given configuration
func (v *VaultProvider) Initialize(config map[string]string) error {
	v.config = &SecretsConfig{
		Address:    utils.GetConfigOrDefault(config, "VAULT_ADDR", ""),
		Token:      utils.GetConfigOrDefault(config, "VAULT_TOKEN", ""),
		MountPath:  utils.GetConfigOrDefault(config, "VAULT_MOUNT_PATH", "secret"),
		RoleID:     config["VAULT_ROLE_ID"],
		SecretID:   config["VAULT_SECRET_ID"],
		AuthMethod: utils.GetConfigOrDefault(config, "VAULT_AUTH_METHOD", "token"),
		CACert:     config["VAULT_CACERT"],
		ClientCert: config["VAULT_CLIENT_CERT"],
		ClientKey:  config["VAULT_CLIENT_KEY"],
		SkipVerify: utils.GetConfigOrDefault(config, "VAULT_SKIP_VERIFY", "false") == "true",
	}

	// Configure Vault client
	SecretsConfig := api.DefaultConfig()
	SecretsConfig.Address = v.config.Address

	// Configure TLS if certificates are provided or verification is skipped
	if v.config.CACert != "" || v.config.ClientCert != "" || v.config.SkipVerify {
		tlsConfig := &api.TLSConfig{
			CACert:     v.config.CACert,
			ClientCert: v.config.ClientCert,
			ClientKey:  v.config.ClientKey,
			Insecure:   v.config.SkipVerify,
		}
		if err := SecretsConfig.ConfigureTLS(tlsConfig); err != nil {
			return fmt.Errorf("failed to configure TLS: %v", err)
		}
	}

	client, err := api.NewClient(SecretsConfig)
	if err != nil {
		return fmt.Errorf("failed to create vault client: %v", err)
	}

	v.client = client

	// Authenticate with Vault
	if err := v.authenticate(); err != nil {
		return fmt.Errorf("failed to authenticate with vault: %v", err)
	}

	log.Infof("Successfully initialized Vault provider using %s method", v.config.AuthMethod)
	return nil
}

// GetSecret retrieves a secret value from Vault
func (v *VaultProvider) GetSecret(ctx context.Context, secretInfo *SecretInfo) ([]byte, error) {
	log.Debugf("Reading secret from Vault/OpenBao path: %s", secretInfo.SecretPath)

	// Read secret from Vault
	secret, err := v.client.Logical().ReadWithContext(ctx, secretInfo.SecretPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret from vault: %v", err)
	}

	if secret == nil {
		return nil, fmt.Errorf("secret not found at path: %s", secretInfo.SecretPath)
	}

	// Extract the secret value (unwraps KV v2 nested data if present)
	value, err := ExtractSecretValueFromKV(secret.Data, secretInfo.SecretField)
	if err != nil {
		return nil, fmt.Errorf("failed to extract secret value: %v", err)
	}

	log.Debug("Successfully retrieved secret from Vault")
	return value, nil
}

// SupportsRotation indicates that Vault supports secret rotation monitoring
func (v *VaultProvider) SupportsRotation() bool {
	return true
}

// GetSecretFieldLabel returns the label key used by Vault for the secret field
func (v *VaultProvider) GetSecretFieldLabel() string {
	return "vault_field"
}

// BuildSecretPath constructs the Vault secret path based on request labels and service information
func (v *VaultProvider) BuildSecretPath(req secrets.Request) string {
	if customPath, exists := req.SecretLabels["vault_path"]; exists && customPath != "" {
		return kvpath.BuildMountedKVv2SecretPath(v.config.MountPath, customPath, "")
	}

	secretName := req.SecretName
	if req.ServiceName != "" {
		secretName = path.Join(req.ServiceName, req.SecretName)
	}

	return kvpath.BuildMountedKVv2SecretPath(v.config.MountPath, "", secretName)
}

// GetProviderName returns the name of this provider
func (v *VaultProvider) GetProviderName() string {
	return "vault"
}

// Close performs cleanup for the Vault provider
func (v *VaultProvider) Close() error {
	// Vault client doesn't require explicit cleanup
	return nil
}

// authenticate handles various Vault authentication methods
func (v *VaultProvider) authenticate() error {
	switch v.config.AuthMethod {
	case "token":
		if v.config.Token == "" {
			return fmt.Errorf("VAULT_TOKEN is required for token authentication")
		}
		v.client.SetToken(v.config.Token)

	case "approle":
		if v.config.RoleID == "" || v.config.SecretID == "" {
			return fmt.Errorf("VAULT_ROLE_ID and VAULT_SECRET_ID are required for approle authentication")
		}

		data := map[string]interface{}{
			"role_id":   v.config.RoleID,
			"secret_id": v.config.SecretID,
		}

		resp, err := v.client.Logical().Write("auth/approle/login", data)
		if err != nil {
			return fmt.Errorf("approle authentication failed: %v", err)
		}

		if resp.Auth == nil {
			return fmt.Errorf("no auth info returned from approle login")
		}

		v.client.SetToken(resp.Auth.ClientToken)

	default:
		return fmt.Errorf("unsupported authentication method: %s", v.config.AuthMethod)
	}

	return nil
}
