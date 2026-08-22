package providers

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/docker/go-plugins-helpers/secrets"
	infisical "github.com/infisical/go-sdk"
	log "github.com/sirupsen/logrus"

	"github.com/sugar-org/swarm-external-secrets/internal/utils"
)

const (
	defaultInfisicalSiteURL = "https://app.infisical.com"
	defaultInfisicalEnv     = "dev"
	defaultInfisicalPath    = "/"
)

// InfisicalProvider implements SecretsProvider for Infisical.
type InfisicalProvider struct {
	config *InfisicalConfig
	client infisical.InfisicalClientInterface
	cancel context.CancelFunc
}

// InfisicalConfig holds Infisical API client settings.
type InfisicalConfig struct {
	ClientID     string
	ClientSecret string
	Token        string // pre-issued bearer; skips Universal Auth when set
	ProjectID    string
	Environment  string
	SecretPath   string
	SiteURL      string
}

// Initialize sets up the Infisical provider.
func (p *InfisicalProvider) Initialize(config map[string]string) error {
	token := utils.GetConfigOrDefault(config, "INFISICAL_TOKEN", "")
	clientID := utils.GetConfigOrDefault(config, "INFISICAL_CLIENT_ID", "")
	clientSecret := utils.GetConfigOrDefault(config, "INFISICAL_CLIENT_SECRET", "")
	if token == "" && (clientID == "" || clientSecret == "") {
		return fmt.Errorf("INFISICAL_TOKEN or both INFISICAL_CLIENT_ID and INFISICAL_CLIENT_SECRET are required")
	}

	projectID := utils.GetConfigOrDefault(config, "INFISICAL_PROJECT_ID", "")
	if projectID == "" {
		return fmt.Errorf("INFISICAL_PROJECT_ID is required")
	}

	siteURL, err := validateInfisicalSiteURL(utils.GetConfigOrDefault(config, "INFISICAL_SITE_URL", defaultInfisicalSiteURL))
	if err != nil {
		return err
	}

	p.config = &InfisicalConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Token:        token,
		ProjectID:    projectID,
		Environment:  utils.GetConfigOrDefault(config, "INFISICAL_ENVIRONMENT", defaultInfisicalEnv),
		SecretPath:   normalizeInfisicalSecretPath(utils.GetConfigOrDefault(config, "INFISICAL_SECRET_PATH", defaultInfisicalPath)),
		SiteURL:      siteURL,
	}

	ctx, cancel := context.WithCancel(context.Background())
	client := infisical.NewInfisicalClient(ctx, infisical.Config{
		SiteUrl:          siteURL,
		AutoTokenRefresh: infisical.BoolPtr(token == ""),
		SilentMode:       true,
	})

	if token != "" {
		client.Auth().SetAccessToken(token)
	} else if _, err := client.Auth().UniversalAuthLogin(clientID, clientSecret); err != nil {
		cancel()
		return fmt.Errorf("infisical universal auth: %w", err)
	}

	p.client = client
	p.cancel = cancel

	log.Infof("Successfully initialized Infisical provider (site: %s, project: %s, env: %s)",
		p.config.SiteURL, p.config.ProjectID, p.config.Environment)
	return nil
}

// GetSecret retrieves a secret value from Infisical.
func (p *InfisicalProvider) GetSecret(ctx context.Context, secretInfo *SecretInfo) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	secretName := p.resolveSecretName(secretInfo)
	projectID, environment, secretPath := p.parseSecretPath(secretInfo.SecretPath)

	log.Debugf("Reading secret from Infisical: %s (project=%s, env=%s, path=%s)",
		secretName, projectID, environment, secretPath)

	secret, err := p.client.Secrets().Retrieve(infisical.RetrieveSecretOptions{
		SecretKey:              secretName,
		ProjectID:              projectID,
		Environment:            environment,
		SecretPath:             secretPath,
		ExpandSecretReferences: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve Infisical secret: %w", err)
	}

	extracted, err := ExtractSecretValue(secret.SecretValue, secretInfo.SecretField)
	if err != nil {
		return nil, fmt.Errorf("failed to extract secret value: %w", err)
	}
	return extracted, nil
}

// SupportsRotation indicates Infisical supports rotation monitoring.
func (p *InfisicalProvider) SupportsRotation() bool { return true }

// GetSecretFieldLabel returns the label key used for JSON field extraction.
func (p *InfisicalProvider) GetSecretFieldLabel() string { return "infisical_field" }

// BuildSecretPath encodes project/env/folder/name for tracking.
// Format: {projectID}/{environment}[/{folders...}]/{secretName}
func (p *InfisicalProvider) BuildSecretPath(req secrets.Request) string {
	secretName := p.resolveSecretNameFromRequest(req)
	projectID, environment, secretPath := p.resolveContextFromRequest(req)
	if secretPath == "/" {
		return fmt.Sprintf("%s/%s/%s", projectID, environment, secretName)
	}
	return fmt.Sprintf("%s/%s%s/%s", projectID, environment, secretPath, secretName)
}

// GetProviderName returns "infisical".
func (p *InfisicalProvider) GetProviderName() string { return "infisical" }

// Close stops the SDK token-refresh loop.
func (p *InfisicalProvider) Close() error {
	if p.cancel != nil {
		p.cancel()
	}
	return nil
}

func (p *InfisicalProvider) resolveSecretNameFromRequest(req secrets.Request) string {
	if name := req.SecretLabels["infisical_secret_name"]; name != "" {
		return name
	}
	return strings.ToUpper(req.SecretName)
}

func (p *InfisicalProvider) resolveSecretName(secretInfo *SecretInfo) string {
	if name := secretInfo.Labels["infisical_secret_name"]; name != "" {
		return name
	}
	return strings.ToUpper(secretInfo.DockerSecretName)
}

func (p *InfisicalProvider) resolveContextFromRequest(req secrets.Request) (projectID, environment, secretPath string) {
	projectID, environment, secretPath = p.config.ProjectID, p.config.Environment, p.config.SecretPath
	if v := req.SecretLabels["infisical_project_id"]; v != "" {
		projectID = v
	}
	if v := req.SecretLabels["infisical_environment"]; v != "" {
		environment = v
	}
	if v := req.SecretLabels["infisical_secret_path"]; v != "" {
		secretPath = normalizeInfisicalSecretPath(v)
	}
	return projectID, environment, secretPath
}

func (p *InfisicalProvider) parseSecretPath(secretPath string) (projectID, environment, path string) {
	parts := strings.Split(secretPath, "/")
	if len(parts) < 3 {
		return p.config.ProjectID, p.config.Environment, p.config.SecretPath
	}
	projectID, environment = parts[0], parts[1]
	if len(parts) == 3 {
		return projectID, environment, "/"
	}
	return projectID, environment, "/" + strings.Join(parts[2:len(parts)-1], "/")
}

func normalizeInfisicalSecretPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if path != "/" {
		path = strings.TrimRight(path, "/")
	}
	return path
}

func validateInfisicalSiteURL(raw string) (string, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if raw == "" {
		return "", fmt.Errorf("INFISICAL_SITE_URL is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid INFISICAL_SITE_URL: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", fmt.Errorf("INFISICAL_SITE_URL must use http or https scheme")
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("INFISICAL_SITE_URL must include a host")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("INFISICAL_SITE_URL must not include userinfo")
	}
	return parsed.Scheme + "://" + parsed.Host + strings.TrimRight(parsed.EscapedPath(), "/"), nil
}
