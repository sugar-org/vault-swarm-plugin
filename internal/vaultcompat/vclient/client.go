package vclient

import (
	"context"
	"errors"
	"net/http"

	vaultapi "github.com/hashicorp/vault/api"
	openbaoapi "github.com/openbao/openbao/api/v2"
)

var ErrAuthFailed = errors.New("vault authentication failed")

type Client interface {
	Read(ctx context.Context, path string) (*Secret, error)
	Write(ctx context.Context, path string, data map[string]any) (*Secret, error)
	RenewSelf(ctx context.Context, increment int) (*Auth, error)
	SetToken(token string)
	Close() error
}

type Secret struct {
	Data map[string]any
	Auth *Auth
}

type Auth struct {
	ClientToken string
	Renewable   bool
	LeaseTTL    int
}

type TLSConfig struct {
	CACert     string
	ClientCert string
	ClientKey  string
	SkipVerify bool
}

func ConfigureHashiVaultTLS(config *vaultapi.Config, tlsCfg TLSConfig) error {
	return config.ConfigureTLS(&vaultapi.TLSConfig{
		CACert:     tlsCfg.CACert,
		ClientCert: tlsCfg.ClientCert,
		ClientKey:  tlsCfg.ClientKey,
		Insecure:   tlsCfg.SkipVerify,
	})
}

func ConfigureOpenBaoTLS(config *openbaoapi.Config, tlsCfg TLSConfig) error {
	return config.ConfigureTLS(&openbaoapi.TLSConfig{
		CACert:     tlsCfg.CACert,
		ClientCert: tlsCfg.ClientCert,
		ClientKey:  tlsCfg.ClientKey,
		Insecure:   tlsCfg.SkipVerify,
	})
}

func IsAuthError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrAuthFailed) {
		return true
	}

	var vaultErr *vaultapi.ResponseError
	if errors.As(err, &vaultErr) {
		return isAuthStatus(vaultErr.StatusCode)
	}

	var openBaoErr *openbaoapi.ResponseError
	if errors.As(err, &openBaoErr) {
		return isAuthStatus(openBaoErr.StatusCode)
	}

	return false
}

func isAuthStatus(statusCode int) bool {
	return statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden
}
