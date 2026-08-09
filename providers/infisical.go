package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/docker/go-plugins-helpers/secrets"
	log "github.com/sirupsen/logrus"

	"github.com/sugar-org/swarm-external-secrets/internal/utils"
)

const (
	defaultInfisicalSiteURL   = "https://app.infisical.com"
	defaultInfisicalEnv       = "dev"
	defaultInfisicalPath      = "/"
	infisicalLoginPath        = "/api/v1/auth/universal-auth/login"
	maxInfisicalResponseBytes = 10 << 20 // 10 MiB
	infisicalTokenSkew        = 60 * time.Second
)

// InfisicalProvider implements SecretsProvider for Infisical.
type InfisicalProvider struct {
	config     *InfisicalConfig
	httpClient *http.Client

	tokenMu     sync.Mutex
	accessToken string
	tokenExpiry time.Time
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
	p.httpClient = &http.Client{Timeout: 30 * time.Second}
	if token != "" {
		p.accessToken = token
	}

	log.Infof("Successfully initialized Infisical provider (site: %s, project: %s, env: %s)",
		p.config.SiteURL, p.config.ProjectID, p.config.Environment)
	return nil
}

// GetSecret retrieves a secret value from Infisical.
//
// ponytail: no response cache (unlike Doppler's config download). Infisical is
// per-secret GET; caching would fight rotation. Upgrade: short TTL cache keyed
// by project/env/path/name if provider QPS becomes an issue.
func (p *InfisicalProvider) GetSecret(ctx context.Context, secretInfo *SecretInfo) ([]byte, error) {
	secretName := p.resolveSecretName(secretInfo)
	projectID, environment, secretPath := p.parseSecretPath(secretInfo.SecretPath)

	log.Debugf("Reading secret from Infisical: %s (project=%s, env=%s, path=%s)",
		secretName, projectID, environment, secretPath)

	value, err := p.fetchSecret(ctx, projectID, environment, secretPath, secretName)
	if err != nil {
		return nil, err
	}
	return []byte(value), nil
}

// SupportsRotation indicates Infisical supports rotation monitoring.
func (p *InfisicalProvider) SupportsRotation() bool { return true }

// GetSecretFieldLabel returns the Infisical secret-name label key.
func (p *InfisicalProvider) GetSecretFieldLabel() string { return "infisical_secret_name" }

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

// Close is a no-op for Infisical.
func (p *InfisicalProvider) Close() error { return nil }

func (p *InfisicalProvider) resolveSecretNameFromRequest(req secrets.Request) string {
	if name := req.SecretLabels["infisical_secret_name"]; name != "" {
		return name
	}
	return strings.ToUpper(req.SecretName)
}

func (p *InfisicalProvider) resolveSecretName(secretInfo *SecretInfo) string {
	if secretInfo.SecretField != "" && secretInfo.SecretField != "value" {
		return secretInfo.SecretField
	}
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
	// Same shape as validateDopplerAPIURL; kept local to avoid a shared helper
	// until a third provider needs it.
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

func (p *InfisicalProvider) fetchSecret(ctx context.Context, projectID, environment, secretPath, secretName string) (string, error) {
	for attempt := 0; attempt < 2; attempt++ {
		token, err := p.getAccessToken(ctx)
		if err != nil {
			return "", err
		}

		value, status, err := p.doGetSecret(ctx, token, projectID, environment, secretPath, secretName)
		if status == http.StatusUnauthorized && attempt == 0 && p.config.Token == "" {
			p.invalidateAccessToken()
			continue
		}
		return value, err
	}
	return "", fmt.Errorf("infisical fetch failed after retry")
}

func (p *InfisicalProvider) invalidateAccessToken() {
	p.tokenMu.Lock()
	defer p.tokenMu.Unlock()
	p.accessToken = ""
	p.tokenExpiry = time.Time{}
}

func (p *InfisicalProvider) doGetSecret(
	ctx context.Context,
	token, projectID, environment, secretPath, secretName string,
) (string, int, error) {
	endpoint, err := url.Parse(p.config.SiteURL + "/api/v4/secrets/" + url.PathEscape(secretName))
	if err != nil {
		return "", 0, fmt.Errorf("invalid Infisical API URL: %w", err)
	}
	q := endpoint.Query()
	q.Set("projectId", projectID)
	q.Set("environment", environment)
	q.Set("secretPath", secretPath)
	q.Set("viewSecretValue", "true")
	q.Set("expandSecretReferences", "true")
	endpoint.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return "", 0, fmt.Errorf("failed to create Infisical request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req) // #nosec G704 — SiteURL validated at Initialize
	if err != nil {
		return "", 0, fmt.Errorf("failed to call Infisical API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxInfisicalResponseBytes))
	if err != nil {
		return "", resp.StatusCode, fmt.Errorf("failed to read Infisical response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode, fmt.Errorf("infisical API returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload struct {
		Secret struct {
			SecretValue string `json:"secretValue"`
		} `json:"secret"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", resp.StatusCode, fmt.Errorf("failed to parse Infisical response: %w", err)
	}
	return payload.Secret.SecretValue, resp.StatusCode, nil
}

func (p *InfisicalProvider) getAccessToken(ctx context.Context) (string, error) {
	p.tokenMu.Lock()
	defer p.tokenMu.Unlock()

	if p.config.Token != "" {
		return p.config.Token, nil
	}
	if p.accessToken != "" && time.Now().Before(p.tokenExpiry.Add(-infisicalTokenSkew)) {
		return p.accessToken, nil
	}

	token, expiresIn, err := p.loginUniversalAuth(ctx)
	if err != nil {
		return "", err
	}
	if expiresIn <= 0 {
		expiresIn = 7200
	}
	p.accessToken = token
	p.tokenExpiry = time.Now().Add(time.Duration(expiresIn) * time.Second)
	return p.accessToken, nil
}

func (p *InfisicalProvider) loginUniversalAuth(ctx context.Context) (string, int, error) {
	body, err := json.Marshal(map[string]string{
		"clientId":     p.config.ClientID,
		"clientSecret": p.config.ClientSecret,
	})
	if err != nil {
		return "", 0, fmt.Errorf("failed to encode Infisical login request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.config.SiteURL+infisicalLoginPath, strings.NewReader(string(body)))
	if err != nil {
		return "", 0, fmt.Errorf("failed to create Infisical login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req) // #nosec G704
	if err != nil {
		return "", 0, fmt.Errorf("failed to call Infisical login API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxInfisicalResponseBytes))
	if err != nil {
		return "", 0, fmt.Errorf("failed to read Infisical login response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("infisical login returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var payload struct {
		AccessToken string `json:"accessToken"`
		ExpiresIn   int    `json:"expiresIn"`
	}
	if err := json.Unmarshal(respBody, &payload); err != nil {
		return "", 0, fmt.Errorf("failed to parse Infisical login response: %w", err)
	}
	if payload.AccessToken == "" {
		return "", 0, fmt.Errorf("infisical login response missing accessToken")
	}
	return payload.AccessToken, payload.ExpiresIn, nil
}
