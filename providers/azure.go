package providers

import (
	"context"
	"fmt"
	"net/http"
	"os" // Imported to read environment variables
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore" // Imported for credentials
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/docker/go-plugins-helpers/secrets"
	log "github.com/sirupsen/logrus"
)

// AzureProvider implements the SecretsProvider interface for Azure Key Vault.
type AzureProvider struct {
	client *azsecrets.Client
	config *AzureConfig
}

// AzureConfig holds the configuration for the Azure Key Vault client.
type AzureConfig struct {
	VaultURL string
	// InsecureAllowHTTP allows HTTP connections to the vault (for local emulators like floci-az).
	InsecureAllowHTTP bool
}

// Initialize sets up the Azure provider with the given configuration.
func (az *AzureProvider) Initialize(config map[string]string) error {
	az.config = &AzureConfig{
		VaultURL: config["AZURE_VAULT_URL"],
	}

	if az.config.VaultURL == "" {
		return fmt.Errorf("AZURE_VAULT_URL is required in the configuration")
	}

	if !strings.HasSuffix(az.config.VaultURL, "/") {
		az.config.VaultURL += "/"
	}

	// Allow HTTP for local emulators like floci-az (opt-in via config or env).
	insecureHTTP := config["AZURE_INSECURE_HTTP"] == "true" || os.Getenv("AZURE_INSECURE_HTTP") == "true"
	az.config.InsecureAllowHTTP = insecureHTTP

	var cred azcore.TokenCredential
	var err error

	accessToken := firstNonEmpty(config["AZURE_ACCESS_TOKEN"], os.Getenv("AZURE_ACCESS_TOKEN"))
	tenantID := firstNonEmpty(config["AZURE_TENANT_ID"], os.Getenv("AZURE_TENANT_ID"))
	clientID := firstNonEmpty(config["AZURE_CLIENT_ID"], os.Getenv("AZURE_CLIENT_ID"))
	clientSecret := firstNonEmpty(config["AZURE_CLIENT_SECRET"], os.Getenv("AZURE_CLIENT_SECRET"))
	authorityHost := firstNonEmpty(config["AZURE_AUTHORITY_HOST"], os.Getenv("AZURE_AUTHORITY_HOST"))

	switch {
	case accessToken != "":
		// Static tokens skip Entra. Required for HTTP emulators: Azure Identity
		// rejects non-HTTPS authority hosts ("cannot use an authority host without https").
		log.Info("Authenticating with Azure using a static access token.")
		cred = staticTokenCredential{token: accessToken}
	case tenantID != "" && clientID != "" && clientSecret != "":
		log.Info("Authenticating with Azure using Service Principal credentials.")
		credOpts := &azidentity.ClientSecretCredentialOptions{
			DisableInstanceDiscovery: insecureHTTP,
		}
		if insecureHTTP {
			if authorityHost == "" {
				authorityHost = "https://localhost:4577"
			}
			if !strings.HasPrefix(strings.ToLower(authorityHost), "https://") {
				return fmt.Errorf("AZURE_AUTHORITY_HOST %q must use https (Azure Identity SDK requirement); for HTTP emulators like floci-az set AZURE_ACCESS_TOKEN instead", authorityHost)
			}
			credOpts.Cloud.ActiveDirectoryAuthorityHost = authorityHost
		}
		cred, err = azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, credOpts)
		if err != nil {
			return fmt.Errorf("failed to create Azure credential using Service Principal: %w", err)
		}
	default:
		// Fallback to default credential chain (Managed Identity, Azure CLI, etc.)
		log.Info("Service Principal credentials not found. Falling back to Default Azure Credential.")
		cred, err = azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return fmt.Errorf("failed to create Azure credential using default chain: %w", err)
		}
	}

	// Create a new secret client to interact with the Key Vault.
	clientOpts := &azsecrets.ClientOptions{}
	if insecureHTTP {
		clientOpts.DisableChallengeResourceVerification = true
		clientOpts.InsecureAllowCredentialWithHTTP = true
		clientOpts.Transport = &forceHTTPTransport{}
	}
	client, err := azsecrets.NewClient(az.config.VaultURL, cred, clientOpts)
	if err != nil {
		return fmt.Errorf("failed to create Azure Key Vault client: %w", err)
	}
	az.client = client

	log.Infof("Successfully initialized Azure Key Vault provider for vault: %s", az.config.VaultURL)
	return nil
}

// GetSecret retrieves a secret value from Azure Key Vault based on the request.
func (az *AzureProvider) GetSecret(ctx context.Context, secretInfo *SecretInfo) ([]byte, error) {
	log.Debugf("Reading secret '%s' from Azure Key Vault", secretInfo.SecretPath)

	resp, err := az.client.GetSecret(ctx, secretInfo.SecretPath, "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret '%s' from Azure Key Vault: %w", secretInfo.SecretPath, err)
	}

	if resp.Value == nil {
		return nil, fmt.Errorf("secret '%s' was found but has no value", secretInfo.SecretPath)
	}

	value, err := ExtractSecretValue(*resp.Value, secretInfo.SecretField)
	if err != nil {
		return nil, fmt.Errorf("failed to extract value from secret '%s': %w", secretInfo.SecretPath, err)
	}

	log.Debugf("Successfully retrieved secret '%s' from Azure Key Vault", secretInfo.SecretPath)
	return value, nil
}

// SupportsRotation indicates that Azure Key Vault supports secret rotation monitoring.
func (az *AzureProvider) SupportsRotation() bool {
	return true
}

// GetProviderName returns the name of this provider
func (az *AzureProvider) GetProviderName() string {
	return "azure"
}

// GetSecretFieldLabel returns the label key used by Azure for the secret field
func (az *AzureProvider) GetSecretFieldLabel() string {
	return "azure_field"
}

// BuildSecretPath constructs the Azure secret name based on request labels and service information.
func (az *AzureProvider) BuildSecretPath(req secrets.Request) string {
	if customName, exists := req.SecretLabels["azure_secret_name"]; exists {
		return customName
	}

	secretName := req.SecretName
	if req.ServiceName != "" {
		secretName = fmt.Sprintf("%s-%s", req.ServiceName, req.SecretName)
	}

	var sanitized strings.Builder
	for _, char := range secretName {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' {
			sanitized.WriteRune(char)
		} else {
			sanitized.WriteRune('-')
		}
	}

	result := sanitized.String()
	for strings.Contains(result, "--") {
		result = strings.ReplaceAll(result, "--", "-")
	}
	result = strings.Trim(result, "-")

	if result == "" {
		result = "default-secret"
	}

	return result
}

// Close performs cleanup for the Azure provider.
func (az *AzureProvider) Close() error {
	// The Azure SDK client does not require an explicit close operation.
	return nil
}

// forceHTTPTransport rewrites HTTPS requests to HTTP. The Azure Key Vault SDK
// enforces HTTPS, but local emulators like floci-az serve HTTP only. This
// transport transparently downgrades the scheme before sending the request.
type forceHTTPTransport struct{}

func (t *forceHTTPTransport) Do(req *http.Request) (*http.Response, error) {
	if req.URL != nil && req.URL.Scheme == "https" {
		clone := req.Clone(req.Context())
		clone.URL.Scheme = "http"
		return http.DefaultTransport.RoundTrip(clone)
	}
	return http.DefaultTransport.RoundTrip(req)
}

// Ensure forceHTTPTransport satisfies policy.Transporter.
var _ policy.Transporter = (*forceHTTPTransport)(nil)

// staticTokenCredential returns a fixed bearer token. Used for local emulators
// that accept any Authorization header (floci-az Key Vault REST).
type staticTokenCredential struct {
	token string
}

func (s staticTokenCredential) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{
		Token:     s.token,
		ExpiresOn: time.Now().Add(time.Hour),
	}, nil
}

var _ azcore.TokenCredential = staticTokenCredential{}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
