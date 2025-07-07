package main

import (
	"context"
	"fmt"
	"os"
	// "path/filepath"
	"strings"
	"time"
	log "github.com/sirupsen/logrus"
	"github.com/docker/go-plugins-helpers/secrets"
	"github.com/hashicorp/vault/api"
)

// VaultDriver implements the secrets.Driver interface
type VaultDriver struct {
	client *api.Client
	config *VaultConfig
}

// VaultConfig holds the configuration for the Vault client
type VaultConfig struct {
	Address    string
	Token      string
	MountPath  string
	RoleID     string
	SecretID   string
	AuthMethod string
	CACert     string
	ClientCert string
	ClientKey  string
}

// NewVaultDriver creates a new VaultDriver instance
func NewVaultDriver() (*VaultDriver, error) {
	config := &VaultConfig{
		Address:    getEnvOrDefault("VAULT_ADDR", "http://152.53.244.80:8200"),
		// Token:      os.Getenv("VAULT_TOKEN"),
		Token: 	getEnvOrDefault("VAULT_TOKEN", "hvs.tD053xbJ1C5lo2EbtZnn2JU8"), // Use environment variable for token
		MountPath:  getEnvOrDefault("VAULT_MOUNT_PATH", "secret"),
		RoleID:     os.Getenv("VAULT_ROLE_ID"),
		SecretID:   os.Getenv("VAULT_SECRET_ID"),
		AuthMethod: getEnvOrDefault("VAULT_AUTH_METHOD", "token"),
		CACert:     os.Getenv("VAULT_CACERT"),
		ClientCert: os.Getenv("VAULT_CLIENT_CERT"),
		ClientKey:  os.Getenv("VAULT_CLIENT_KEY"),
	}

	// Configure Vault client
	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = config.Address

	// Configure TLS if certificates are provided
	if config.CACert != "" || config.ClientCert != "" {
		tlsConfig := &api.TLSConfig{
			CACert:     config.CACert,
			ClientCert: config.ClientCert,
			ClientKey:  config.ClientKey,
		}
		if err := vaultConfig.ConfigureTLS(tlsConfig); err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %v", err)
		}
	}

	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %v", err)
	}

	driver := &VaultDriver{
		client: client,
		config: config,
	}

	// Authenticate with Vault
	if err := driver.authenticate(); err != nil {
		return nil, fmt.Errorf("failed to authenticate with vault: %v", err)
	}else{
		log.Printf("Successfully authenticated with Vault using %s method", config.AuthMethod)
	}

	return driver, nil
}

// authenticate handles various Vault authentication methods
func (d *VaultDriver) authenticate() error {
	switch d.config.AuthMethod {
	case "token":
		if d.config.Token == "" {
			return fmt.Errorf("VAULT_TOKEN is required for token authentication")
		}
		d.client.SetToken(d.config.Token)

	case "approle":
		if d.config.RoleID == "" || d.config.SecretID == "" {
			return fmt.Errorf("VAULT_ROLE_ID and VAULT_SECRET_ID are required for approle authentication")
		}

		data := map[string]interface{}{
			"role_id":   d.config.RoleID,
			"secret_id": d.config.SecretID,
		}

		resp, err := d.client.Logical().Write("auth/approle/login", data)
		if err != nil {
			return fmt.Errorf("approle authentication failed: %v", err)
		}

		if resp.Auth == nil {
			return fmt.Errorf("no auth info returned from approle login")
		}

		d.client.SetToken(resp.Auth.ClientToken)

	default:
		return fmt.Errorf("unsupported authentication method: %s", d.config.AuthMethod)
	}

	return nil
}

// Update the Get method with better logging
func (d *VaultDriver) Get(req secrets.Request) secrets.Response {
    log.Printf("Received secret request for: %s", req.SecretName)
    
    if req.SecretName == "" {
        return secrets.Response{
            Err: "secret name is required",
        }
    }

    // Build the secret path based on labels and service information
    secretPath := d.buildSecretPath(req)
    log.Printf("Built secret path: %s", secretPath)
    
    // Add context with timeout
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    // Read secret from Vault
    secret, err := d.client.Logical().ReadWithContext(ctx, secretPath)
    if err != nil {
        log.Printf("Error reading secret from vault: %v", err)
        return secrets.Response{
            Err: fmt.Sprintf("failed to read secret from vault: %v", err),
        }
    }

    if secret == nil {
        log.Printf("Secret not found at path: %s", secretPath)
        return secrets.Response{
            Err: fmt.Sprintf("secret not found at path: %s (verify the secret exists in Vault)", secretPath),
        }
    }

    log.Printf("Successfully read secret from vault")
    
    // Extract the secret value
    value, err := d.extractSecretValue(secret, req)
    if err != nil {
        log.Printf("Error extracting secret value: %v", err)
        return secrets.Response{
            Err: fmt.Sprintf("failed to extract secret value: %v", err),
        }
    }else{
		log.Printf("Extracted secret value successfully")
	}

    // Determine if secret should be reusable
    doNotReuse := d.shouldNotReuse(req)

    log.Printf("Successfully returning secret value")
    return secrets.Response{
        Value:      value,
        DoNotReuse: doNotReuse,
    }
}
// buildSecretPath constructs the Vault secret path based on request labels and service information
func (d *VaultDriver) buildSecretPath(req secrets.Request) string {
	// Use custom path from labels if provided
	if customPath, exists := req.SecretLabels["vault_path"]; exists {
		// For KV v2, ensure we have the /data/ prefix
		if d.config.MountPath == "secret" {
			return fmt.Sprintf("%s/data/%s", d.config.MountPath, customPath)
		}
		return fmt.Sprintf("%s/%s", d.config.MountPath, customPath)
	}

	// Default path structure for KV v2
	if d.config.MountPath == "secret" {
		if req.ServiceName != "" {
			return fmt.Sprintf("%s/data/%s/%s", d.config.MountPath, req.ServiceName, req.SecretName)
		}
		return fmt.Sprintf("%s/data/%s", d.config.MountPath, req.SecretName)
	}

	// For other mount paths
	if req.ServiceName != "" {
		return fmt.Sprintf("%s/%s/%s", d.config.MountPath, req.ServiceName, req.SecretName)
	}
	return fmt.Sprintf("%s/%s", d.config.MountPath, req.SecretName)
}

// extractSecretValue extracts the appropriate value from the Vault response
func (d *VaultDriver) extractSecretValue(secret *api.Secret, req secrets.Request) ([]byte, error) {
	// For KV v2, data is nested under "data"
	var data map[string]interface{}
	if secretData, ok := secret.Data["data"]; ok {
		data = secretData.(map[string]interface{})
	} else {
		data = secret.Data
	}

	// Check for specific field in labels
	if field, exists := req.SecretLabels["vault_field"]; exists {
		if value, ok := data[field]; ok {
			return []byte(fmt.Sprintf("%v", value)), nil
		}
		return nil, fmt.Errorf("field %s not found in secret", field)
	}

	// Default field names to try
	defaultFields := []string{"value", "password", "secret", "data"}

	// Try to find a value using default field names
	for _, field := range defaultFields {
		if value, ok := data[field]; ok {
			return []byte(fmt.Sprintf("%v", value)), nil
		}
	}

	// If no specific field found, return the first string value
	for _, value := range data {
		if strValue, ok := value.(string); ok {
			return []byte(strValue), nil
		}
	}

	return nil, fmt.Errorf("no suitable secret value found")
}

// shouldNotReuse determines if the secret should not be reused
func (d *VaultDriver) shouldNotReuse(req secrets.Request) bool {
	// Check for explicit label
	if reuse, exists := req.SecretLabels["vault_reuse"]; exists {
		return strings.ToLower(reuse) == "false"
	}

	// Don't reuse dynamic secrets or certificates
	if strings.Contains(req.SecretName, "cert") ||
		strings.Contains(req.SecretName, "token") ||
		strings.Contains(req.SecretName, "dynamic") {
		return true
	}

	return false
}

// getEnvOrDefault returns environment variable value or default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
