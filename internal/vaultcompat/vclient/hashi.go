package vclient

import (
	"context"

	vaultapi "github.com/hashicorp/vault/api"
)

type HashiVault struct {
	client *vaultapi.Client
}

func NewHashiVault(client *vaultapi.Client) *HashiVault {
	return &HashiVault{client: client}
}

func (h *HashiVault) Read(ctx context.Context, path string) (*Secret, error) {
	secret, err := h.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, err
	}

	return fromHashiSecret(secret), nil
}

func (h *HashiVault) Write(ctx context.Context, path string, data map[string]any) (*Secret, error) {
	secret, err := h.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return nil, err
	}

	return fromHashiSecret(secret), nil
}

func (h *HashiVault) RenewSelf(ctx context.Context, increment int) (*Auth, error) {
	secret, err := h.client.Auth().Token().RenewSelfWithContext(ctx, increment)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Auth == nil {
		return nil, nil
	}

	return &Auth{
		ClientToken: secret.Auth.ClientToken,
		Renewable:   secret.Auth.Renewable,
		LeaseTTL:    secret.Auth.LeaseDuration,
	}, nil
}

func (h *HashiVault) SetToken(token string) {
	h.client.SetToken(token)
}

func (h *HashiVault) Close() error {
	return nil
}

func fromHashiSecret(secret *vaultapi.Secret) *Secret {
	if secret == nil {
		return nil
	}

	out := &Secret{Data: secret.Data}
	if secret.Auth != nil {
		out.Auth = &Auth{
			ClientToken: secret.Auth.ClientToken,
			Renewable:   secret.Auth.Renewable,
			LeaseTTL:    secret.Auth.LeaseDuration,
		}
	}

	return out
}
