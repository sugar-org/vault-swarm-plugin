package login

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/sugar-org/swarm-external-secrets/internal/vaultcompat/jwtsource"
	"github.com/sugar-org/swarm-external-secrets/internal/vaultcompat/vclient"
)

type Config struct {
	Method          string
	Token           string
	RoleID          string
	SecretID        string
	AppRoleAuthPath string
	JWTRole         string
	JWTAuthPath     string
	JWTSource       jwtsource.Source
}

type Method interface {
	Login(ctx context.Context, client vclient.Client) (*vclient.Auth, error)
}

func New(cfg Config) (Method, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Method)) {
	case "", "token":
		return tokenLogin{token: cfg.Token}, nil
	case "approle":
		return appRoleLogin{
			roleID:   cfg.RoleID,
			secretID: cfg.SecretID,
			authPath: cfg.AppRoleAuthPath,
		}, nil
	case "jwt":
		return jwtLogin{
			role:     cfg.JWTRole,
			authPath: cfg.JWTAuthPath,
			source:   cfg.JWTSource,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported authentication method: %s", cfg.Method)
	}
}

type tokenLogin struct {
	token string
}

func (t tokenLogin) Login(context.Context, vclient.Client) (*vclient.Auth, error) {
	if t.token == "" {
		return nil, fmt.Errorf("token is required")
	}

	return &vclient.Auth{ClientToken: t.token}, nil
}

type appRoleLogin struct {
	roleID   string
	secretID string
	authPath string
}

func (a appRoleLogin) Login(ctx context.Context, client vclient.Client) (*vclient.Auth, error) {
	secret, err := client.Write(ctx, loginPath(a.authPath), map[string]any{
		"role_id":   a.roleID,
		"secret_id": a.secretID,
	})
	if err != nil {
		return nil, err
	}

	return authFromSecret(secret)
}

type jwtLogin struct {
	role     string
	authPath string
	source   jwtsource.Source
}

func (j jwtLogin) Login(ctx context.Context, client vclient.Client) (*vclient.Auth, error) {
	if j.role == "" {
		return nil, fmt.Errorf("jwt role is required")
	}
	if j.source == nil {
		return nil, fmt.Errorf("jwt source is required")
	}

	token, err := j.source.Token(ctx)
	if err != nil {
		return nil, err
	}

	secret, err := client.Write(ctx, loginPath(j.authPath), map[string]any{
		"role": j.role,
		"jwt":  token,
	})
	if err != nil {
		return nil, err
	}

	return authFromSecret(secret)
}

func loginPath(authPath string) string {
	authPath = strings.Trim(authPath, "/")
	if authPath == "" {
		authPath = "token"
	}
	return path.Join("auth", authPath, "login")
}

func authFromSecret(secret *vclient.Secret) (*vclient.Auth, error) {
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return nil, fmt.Errorf("login response did not include a client token")
	}

	return secret.Auth, nil
}
