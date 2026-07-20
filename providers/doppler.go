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
	defaultDopplerAPIURL   = "https://api.doppler.com"
	defaultDopplerCacheTTL = 30 * time.Second
	dopplerDownloadPath    = "/v3/configs/config/secrets/download"
)

// DopplerProvider implements the SecretsProvider interface for Doppler.
type DopplerProvider struct {
	config     *DopplerConfig
	httpClient *http.Client
	cache      map[dopplerCacheKey]dopplerCacheEntry
	cacheMu    sync.RWMutex
	fetchMu    sync.Mutex
}

// DopplerConfig holds configuration for the Doppler API client.
type DopplerConfig struct {
	Token      string
	Project    string
	Config     string
	APIBaseURL string
	CacheTTL   time.Duration
}

type dopplerCacheKey struct {
	project string
	config  string
}

type dopplerCacheEntry struct {
	secrets   map[string]string
	fetchedAt time.Time
}

// Initialize sets up the Doppler provider with the given configuration.
func (d *DopplerProvider) Initialize(config map[string]string) error {
	token := utils.GetConfigOrDefault(config, "DOPPLER_TOKEN", "")
	if token == "" {
		return fmt.Errorf("DOPPLER_TOKEN is required")
	}

	cacheTTL := defaultDopplerCacheTTL
	if rawTTL := utils.GetConfigOrDefault(config, "DOPPLER_CACHE_TTL", ""); rawTTL != "" {
		parsed, err := time.ParseDuration(rawTTL)
		if err != nil {
			return fmt.Errorf("invalid DOPPLER_CACHE_TTL %q: %w", rawTTL, err)
		}
		cacheTTL = parsed
	}

	apiBaseURL, err := validateDopplerAPIURL(utils.GetConfigOrDefault(config, "DOPPLER_API_URL", defaultDopplerAPIURL))
	if err != nil {
		return err
	}

	d.config = &DopplerConfig{
		Token:      token,
		Project:    utils.GetConfigOrDefault(config, "DOPPLER_PROJECT", ""),
		Config:     utils.GetConfigOrDefault(config, "DOPPLER_CONFIG", ""),
		APIBaseURL: apiBaseURL,
		CacheTTL:   cacheTTL,
	}
	d.httpClient = &http.Client{Timeout: 30 * time.Second}
	d.cache = make(map[dopplerCacheKey]dopplerCacheEntry)

	if !isDopplerServiceToken(d.config.Token) {
		if d.config.Project == "" || d.config.Config == "" {
			return fmt.Errorf("DOPPLER_PROJECT and DOPPLER_CONFIG are required when not using a service token")
		}
	}

	log.Infof("Successfully initialized Doppler provider (cache TTL: %v)", d.config.CacheTTL)
	return nil
}

// GetSecret retrieves a secret value from Doppler.
func (d *DopplerProvider) GetSecret(ctx context.Context, secretInfo *SecretInfo) ([]byte, error) {
	secretName := d.resolveSecretName(secretInfo)
	project, configName := d.parseSecretPath(secretInfo.SecretPath)

	log.Debugf("Reading secret from Doppler: %s (project=%s, config=%s)", secretName, project, configName)

	secretsMap, err := d.getConfigSecrets(ctx, project, configName)
	if err != nil {
		return nil, err
	}

	value, ok := secretsMap[secretName]
	if !ok {
		return nil, fmt.Errorf("secret %q not found in Doppler config", secretName)
	}

	log.Debug("Successfully retrieved secret from Doppler")
	return []byte(value), nil
}

// SupportsRotation indicates that Doppler supports secret rotation monitoring.
func (d *DopplerProvider) SupportsRotation() bool {
	return true
}

// GetSecretFieldLabel returns the label key used by Doppler for the secret name.
func (d *DopplerProvider) GetSecretFieldLabel() string {
	return "doppler_secret_name"
}

// BuildSecretPath constructs the Doppler secret path from the request.
func (d *DopplerProvider) BuildSecretPath(req secrets.Request) string {
	secretName := d.resolveSecretNameFromRequest(req)
	project, configName := d.resolveProjectConfigFromRequest(req)
	return fmt.Sprintf("%s/%s/%s", project, configName, secretName)
}

// GetProviderName returns the name of this provider.
func (d *DopplerProvider) GetProviderName() string {
	return "doppler"
}

// Close performs cleanup for the Doppler provider.
func (d *DopplerProvider) Close() error {
	return nil
}

// InvalidateCache drops all cached Doppler config downloads so the next read
// fetches fresh values. Used for webhook-driven rotation.
func (d *DopplerProvider) InvalidateCache() {
	d.cacheMu.Lock()
	d.cache = make(map[dopplerCacheKey]dopplerCacheEntry)
	defer d.cacheMu.Unlock()
}

func (d *DopplerProvider) resolveSecretNameFromRequest(req secrets.Request) string {
	if customName, exists := req.SecretLabels["doppler_secret_name"]; exists && customName != "" {
		return customName
	}
	return strings.ToUpper(req.SecretName)
}

func (d *DopplerProvider) resolveSecretName(secretInfo *SecretInfo) string {
	if secretInfo.SecretField != "" && secretInfo.SecretField != "value" {
		return secretInfo.SecretField
	}
	if name, exists := secretInfo.Labels["doppler_secret_name"]; exists && name != "" {
		return name
	}
	return strings.ToUpper(secretInfo.DockerSecretName)
}

func (d *DopplerProvider) resolveProjectConfigFromRequest(req secrets.Request) (string, string) {
	project := d.config.Project
	configName := d.config.Config

	if override, exists := req.SecretLabels["doppler_project"]; exists && override != "" {
		project = override
	}
	if override, exists := req.SecretLabels["doppler_config"]; exists && override != "" {
		configName = override
	}

	return project, configName
}

func (d *DopplerProvider) parseSecretPath(secretPath string) (string, string) {
	parts := strings.SplitN(secretPath, "/", 3)
	if len(parts) < 3 {
		return d.config.Project, d.config.Config
	}
	return parts[0], parts[1]
}

func isDopplerServiceToken(token string) bool {
	return strings.HasPrefix(token, "dp.st.")
}

func validateDopplerAPIURL(raw string) (string, error) {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if raw == "" {
		return "", fmt.Errorf("DOPPLER_API_URL is required")
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid DOPPLER_API_URL: %w", err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", fmt.Errorf("DOPPLER_API_URL must use http or https scheme")
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("DOPPLER_API_URL must include a host")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("DOPPLER_API_URL must not include userinfo")
	}

	return parsed.Scheme + "://" + parsed.Host + strings.TrimRight(parsed.EscapedPath(), "/"), nil
}

func (d *DopplerProvider) getConfigSecrets(
	ctx context.Context,
	project string,
	configName string,
) (map[string]string, error) {
	cacheKey := dopplerCacheKey{project: project, config: configName}

	d.cacheMu.RLock()
	if entry, ok := d.cache[cacheKey]; ok && time.Since(entry.fetchedAt) < d.config.CacheTTL {
		cached := cloneSecretsMap(entry.secrets)
		d.cacheMu.RUnlock()
		return cached, nil
	}
	d.cacheMu.RUnlock()

	d.fetchMu.Lock()
	defer d.fetchMu.Unlock()

	// Double-check after acquiring fetch lock so concurrent callers share one refresh.
	d.cacheMu.RLock()
	if entry, ok := d.cache[cacheKey]; ok && time.Since(entry.fetchedAt) < d.config.CacheTTL {
		cached := cloneSecretsMap(entry.secrets)
		d.cacheMu.RUnlock()
		return cached, nil
	}
	d.cacheMu.RUnlock()

	secretsMap, err := d.downloadSecrets(ctx, project, configName)
	if err != nil {
		return nil, err
	}

	d.cacheMu.Lock()
	d.cache[cacheKey] = dopplerCacheEntry{
		secrets:   cloneSecretsMap(secretsMap),
		fetchedAt: time.Now(),
	}
	d.cacheMu.Unlock()

	return secretsMap, nil
}

func (d *DopplerProvider) downloadSecrets(ctx context.Context, project, configName string) (map[string]string, error) {
	endpoint, err := url.Parse(d.config.APIBaseURL + dopplerDownloadPath)
	if err != nil {
		return nil, fmt.Errorf("invalid Doppler API URL: %w", err)
	}

	query := endpoint.Query()
	query.Set("format", "json")
	if project != "" {
		query.Set("project", project)
	}
	if configName != "" {
		query.Set("config", configName)
	}
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Doppler request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+d.config.Token)
	req.Header.Set("Accept", "application/json")

	// URL is validated at Initialize from plugin admin config (http/https + host only).
	resp, err := d.httpClient.Do(req) // #nosec G704
	if err != nil {
		return nil, fmt.Errorf("failed to call Doppler API: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Doppler response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doppler API returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var secretsMap map[string]string
	if err := json.Unmarshal(body, &secretsMap); err != nil {
		return nil, fmt.Errorf("failed to parse Doppler response: %w", err)
	}

	return secretsMap, nil
}

func cloneSecretsMap(src map[string]string) map[string]string {
	if src == nil {
		return nil
	}
	dst := make(map[string]string, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}
