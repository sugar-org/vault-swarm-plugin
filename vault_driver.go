package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	// "path/filepath"
	"strings"
	"sync"
	"time"
	log "github.com/sirupsen/logrus"
	"github.com/docker/go-plugins-helpers/secrets"
	"github.com/hashicorp/vault/api"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/swarm"
	dockerclient "github.com/docker/docker/client"
)

// SecretInfo tracks information about secrets being managed
type SecretInfo struct {
	DockerSecretName string
	VaultPath        string
	VaultField       string
	ServiceNames     []string
	LastHash         string    // Hash of the secret value for change detection
	LastUpdated      time.Time
}

// VaultDriver implements the secrets.Driver interface
type VaultDriver struct {
	client        *api.Client
	config        *VaultConfig
	dockerClient  *dockerclient.Client
	secretTracker map[string]*SecretInfo // key: docker secret name
	trackerMutex  sync.RWMutex
	monitorCtx    context.Context
	monitorCancel context.CancelFunc
}

// VaultConfig holds the configuration for the Vault client
type VaultConfig struct {
	Address           string
	Token             string
	MountPath         string
	RoleID            string
	SecretID          string
	AuthMethod        string
	CACert            string
	ClientCert        string
	ClientKey         string
	EnableRotation    bool
	RotationInterval  time.Duration
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
		EnableRotation: getEnvOrDefault("VAULT_ENABLE_ROTATION", "true") == "true",
		RotationInterval: parseDurationOrDefault(getEnvOrDefault("VAULT_ROTATION_INTERVAL", "5m")),
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

	// Create Docker client
	dockerClient, err := dockerclient.NewClientWithOpts(dockerclient.FromEnv, dockerclient.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %v", err)
	}

	// Create context for monitoring
	monitorCtx, monitorCancel := context.WithCancel(context.Background())

	driver := &VaultDriver{
		client:        client,
		config:        config,
		dockerClient:  dockerClient,
		secretTracker: make(map[string]*SecretInfo),
		monitorCtx:    monitorCtx,
		monitorCancel: monitorCancel,
	}

	// Authenticate with Vault
	if err := driver.authenticate(); err != nil {
		return nil, fmt.Errorf("failed to authenticate with vault: %v", err)
	}else{
		log.Printf("Successfully authenticated with Vault using %s method", config.AuthMethod)
	}

	// Start monitoring if enabled
	if config.EnableRotation {
		log.Printf("Starting secret rotation monitoring with interval: %v", config.RotationInterval)
		go driver.startMonitoring()
	} else {
		log.Printf("Secret rotation monitoring is disabled")
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

// Update the Get method with better logging and secret tracking
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

    // Track this secret for monitoring if rotation is enabled
    if d.config.EnableRotation {
        d.trackSecret(req, secretPath, value)
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

// parseDurationOrDefault parses duration string or returns default
func parseDurationOrDefault(durationStr string) time.Duration {
	if duration, err := time.ParseDuration(durationStr); err == nil {
		return duration
	}
	return 5 * time.Minute // Default to 5 minutes
}

// trackSecret adds or updates a secret in the tracking system
func (d *VaultDriver) trackSecret(req secrets.Request, vaultPath string, value []byte) {
	d.trackerMutex.Lock()
	defer d.trackerMutex.Unlock()

	// Calculate hash for change detection
	hash := fmt.Sprintf("%x", sha256.Sum256(value))
	
	// Extract vault field from labels
	vaultField := req.SecretLabels["vault_field"]
	if vaultField == "" {
		vaultField = "value" // default field
	}
	
	secretInfo := &SecretInfo{
		DockerSecretName: req.SecretName,
		VaultPath:        vaultPath,
		VaultField:       vaultField,
		ServiceNames:     []string{req.ServiceName}, // Start with current service
		LastHash:         hash,
		LastUpdated:      time.Now(),
	}
	
	// If already tracking, update service names
	if existing, exists := d.secretTracker[req.SecretName]; exists {
		// Add service name if not already present
		serviceFound := false
		for _, svc := range existing.ServiceNames {
			if svc == req.ServiceName {
				serviceFound = true
				break
			}
		}
		if !serviceFound && req.ServiceName != "" {
			existing.ServiceNames = append(existing.ServiceNames, req.ServiceName)
		}
		existing.LastHash = hash
		existing.LastUpdated = time.Now()
	} else {
		d.secretTracker[req.SecretName] = secretInfo
	}
	
	log.Printf("Tracking secret: %s -> %s (services: %v)", req.SecretName, vaultPath, secretInfo.ServiceNames)
}

// startMonitoring starts the background monitoring goroutine
func (d *VaultDriver) startMonitoring() {
	ticker := time.NewTicker(d.config.RotationInterval)
	defer ticker.Stop()
	
	log.Printf("Secret monitoring started with interval: %v", d.config.RotationInterval)
	
	for {
		select {
		case <-d.monitorCtx.Done():
			log.Printf("Secret monitoring stopped")
			return
		case <-ticker.C:
			d.checkForSecretChanges()
		}
	}
}

// checkForSecretChanges monitors tracked secrets for changes
func (d *VaultDriver) checkForSecretChanges() {
	d.trackerMutex.RLock()
	secrets := make(map[string]*SecretInfo)
	for k, v := range d.secretTracker {
		secrets[k] = v
	}
	d.trackerMutex.RUnlock()
	
	if len(secrets) == 0 {
		log.Debug("No secrets to monitor")
		return
	}
	
	log.Printf("Checking %d tracked secrets for changes", len(secrets))
	
	for secretName, secretInfo := range secrets {
		if d.hasSecretChanged(secretInfo) {
			log.Printf("Detected change in secret: %s", secretName)
			if err := d.rotateSecret(secretInfo); err != nil {
				log.Errorf("Failed to rotate secret %s: %v", secretName, err)
			}
		}
	}
}

// hasSecretChanged checks if a secret has changed in Vault
func (d *VaultDriver) hasSecretChanged(secretInfo *SecretInfo) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Read secret from Vault
	secret, err := d.client.Logical().ReadWithContext(ctx, secretInfo.VaultPath)
	if err != nil {
		log.Errorf("Error reading secret %s from vault: %v", secretInfo.DockerSecretName, err)
		return false
	}
	
	if secret == nil {
		log.Warnf("Secret %s not found at path: %s", secretInfo.DockerSecretName, secretInfo.VaultPath)
		return false
	}
	
	// Extract current value
	var data map[string]interface{}
	if secretData, ok := secret.Data["data"]; ok {
		data = secretData.(map[string]interface{})
	} else {
		data = secret.Data
	}
	
	var currentValue []byte
	if value, ok := data[secretInfo.VaultField]; ok {
		currentValue = []byte(fmt.Sprintf("%v", value))
	} else {
		log.Errorf("Field %s not found in secret %s", secretInfo.VaultField, secretInfo.DockerSecretName)
		return false
	}
	
	// Calculate current hash
	currentHash := fmt.Sprintf("%x", sha256.Sum256(currentValue))
	
	return currentHash != secretInfo.LastHash
}

// rotateSecret handles the secret rotation process
func (d *VaultDriver) rotateSecret(secretInfo *SecretInfo) error {
	log.Printf("Starting rotation for secret: %s", secretInfo.DockerSecretName)
	
	// Get the new secret value from Vault
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	secret, err := d.client.Logical().ReadWithContext(ctx, secretInfo.VaultPath)
	if err != nil {
		return fmt.Errorf("failed to read updated secret from vault: %v", err)
	}
	
	if secret == nil {
		return fmt.Errorf("secret not found at path: %s", secretInfo.VaultPath)
	}
	
	// Extract the new value
	var data map[string]interface{}
	if secretData, ok := secret.Data["data"]; ok {
		data = secretData.(map[string]interface{})
	} else {
		data = secret.Data
	}
	
	var newValue []byte
	if value, ok := data[secretInfo.VaultField]; ok {
		newValue = []byte(fmt.Sprintf("%v", value))
	} else {
		return fmt.Errorf("field %s not found in secret", secretInfo.VaultField)
	}
	
	// Update Docker secret (this now handles service updates internally)
	if err := d.updateDockerSecret(secretInfo.DockerSecretName, newValue); err != nil {
		return fmt.Errorf("failed to update docker secret: %v", err)
	}
	
	// Update tracking information
	d.trackerMutex.Lock()
	secretInfo.LastHash = fmt.Sprintf("%x", sha256.Sum256(newValue))
	secretInfo.LastUpdated = time.Now()
	d.trackerMutex.Unlock()
	
	log.Printf("Successfully rotated secret: %s", secretInfo.DockerSecretName)
	return nil
}

// updateDockerSecret creates a new version of the Docker secret
func (d *VaultDriver) updateDockerSecret(secretName string, newValue []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// List existing secrets to find the one to update
	secrets, err := d.dockerClient.SecretList(ctx, types.SecretListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list secrets: %v", err)
	}
	
	var existingSecret *swarm.Secret
	for _, secret := range secrets {
		if secret.Spec.Name == secretName {
			existingSecret = &secret
			break
		}
	}
	
	if existingSecret == nil {
		return fmt.Errorf("secret %s not found", secretName)
	}
	
	// Generate a unique name for the new secret version
	newSecretName := fmt.Sprintf("%s-%d", secretName, time.Now().Unix())
	
	// Create new secret with versioned name and same labels but updated value
	newSecretSpec := swarm.SecretSpec{
		Annotations: swarm.Annotations{
			Name:   newSecretName,
			Labels: existingSecret.Spec.Labels,
		},
		Data: newValue,
	}
	
	// Create the new secret
	createResponse, err := d.dockerClient.SecretCreate(ctx, newSecretSpec)
	if err != nil {
		return fmt.Errorf("failed to create new secret version: %v", err)
	}
	
	log.Printf("Created new version of secret %s with name %s and ID: %s", secretName, newSecretName, createResponse.ID)
	
	// Update all services that use this secret to point to the new version
	if err := d.updateServicesSecretReference(secretName, newSecretName); err != nil {
		// If we can't update services, remove the new secret and return error
		d.dockerClient.SecretRemove(ctx, createResponse.ID)
		return fmt.Errorf("failed to update services to use new secret: %v", err)
	}
	
	// Remove the old secret only after services are updated
	if err := d.dockerClient.SecretRemove(ctx, existingSecret.ID); err != nil {
		log.Warnf("Failed to remove old secret version %s: %v", existingSecret.ID, err)
		// Don't return error as the new secret was created and services updated successfully
	}
	
	return nil
}

// updateServicesSecretReference updates all services to use the new secret version
func (d *VaultDriver) updateServicesSecretReference(oldSecretName, newSecretName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	
	// List all services
	services, err := d.dockerClient.ServiceList(ctx, types.ServiceListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list services: %v", err)
	}
	
	var updatedServices []string
	
	for _, service := range services {
		// Check if service uses this secret and update the reference
		needsUpdate := false
		updatedSecrets := make([]*swarm.SecretReference, len(service.Spec.TaskTemplate.ContainerSpec.Secrets))
		
		for i, secretRef := range service.Spec.TaskTemplate.ContainerSpec.Secrets {
			if secretRef.SecretName == oldSecretName {
				// Update to use the new secret name
				updatedSecrets[i] = &swarm.SecretReference{
					File:       secretRef.File,
					SecretID:   newSecretName, // Use new secret name as ID
					SecretName: newSecretName,
				}
				needsUpdate = true
			} else {
				updatedSecrets[i] = secretRef
			}
		}
		
		if needsUpdate {
			// Update service with new secret references
			serviceSpec := service.Spec
			serviceSpec.TaskTemplate.ContainerSpec.Secrets = updatedSecrets
			
			// Add/update a label to force the update
			if serviceSpec.Labels == nil {
				serviceSpec.Labels = make(map[string]string)
			}
			serviceSpec.Labels["vault.secret.rotated"] = fmt.Sprintf("%d", time.Now().Unix())
			
			updateOptions := types.ServiceUpdateOptions{}
			updateResponse, err := d.dockerClient.ServiceUpdate(ctx, service.ID, service.Version, serviceSpec, updateOptions)
			if err != nil {
				return fmt.Errorf("failed to update service %s: %v", service.Spec.Name, err)
			}
			
			if len(updateResponse.Warnings) > 0 {
				log.Warnf("Service update warnings for %s: %v", service.Spec.Name, updateResponse.Warnings)
			}
			
			updatedServices = append(updatedServices, service.Spec.Name)
		}
	}
	
	if len(updatedServices) > 0 {
		log.Printf("Updated services to use new secret %s: %v", newSecretName, updatedServices)
	}
	
	return nil
}

// updateServicesUsingSecret forces update of services using the rotated secret
func (d *VaultDriver) updateServicesUsingSecret(secretInfo *SecretInfo) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	
	// List all services
	services, err := d.dockerClient.ServiceList(ctx, types.ServiceListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list services: %v", err)
	}
	
	var updatedServices []string
	
	for _, service := range services {
		// Check if service uses this secret
		usesSecret := false
		for _, secret := range service.Spec.TaskTemplate.ContainerSpec.Secrets {
			if secret.SecretName == secretInfo.DockerSecretName {
				usesSecret = true
				break
			}
		}
		
		if usesSecret {
			// Force service update to pick up new secret
			if err := d.forceServiceUpdate(service); err != nil {
				log.Errorf("Failed to update service %s: %v", service.Spec.Name, err)
				continue
			}
			updatedServices = append(updatedServices, service.Spec.Name)
		}
	}
	
	if len(updatedServices) > 0 {
		log.Printf("Updated services using secret %s: %v", secretInfo.DockerSecretName, updatedServices)
	}
	
	return nil
}

// forceServiceUpdate forces a service to update (recreate tasks)
func (d *VaultDriver) forceServiceUpdate(service swarm.Service) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Get current service spec
	serviceSpec := service.Spec
	
	// Add/update a label to force the update
	if serviceSpec.Labels == nil {
		serviceSpec.Labels = make(map[string]string)
	}
	serviceSpec.Labels["vault.secret.rotated"] = fmt.Sprintf("%d", time.Now().Unix())
	
	// Update the service
	updateOptions := types.ServiceUpdateOptions{}
	updateResponse, err := d.dockerClient.ServiceUpdate(ctx, service.ID, service.Version, serviceSpec, updateOptions)
	if err != nil {
		return fmt.Errorf("failed to update service: %v", err)
	}
	
	if len(updateResponse.Warnings) > 0 {
		log.Warnf("Service update warnings for %s: %v", service.Spec.Name, updateResponse.Warnings)
	}
	
	log.Printf("Forced update for service: %s", service.Spec.Name)
	return nil
}

// Stop gracefully stops the monitoring
func (d *VaultDriver) Stop() error {
	if d.monitorCancel != nil {
		d.monitorCancel()
	}
	if d.dockerClient != nil {
		return d.dockerClient.Close()
	}
	return nil
}
