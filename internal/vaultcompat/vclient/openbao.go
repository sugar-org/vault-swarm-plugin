package vclient

import (
	"context"

	openbaoapi "github.com/openbao/openbao/api/v2"
)

type OpenBao struct {
	client *openbaoapi.Client
}

func NewOpenBao(client *openbaoapi.Client) *OpenBao {
	return &OpenBao{client: client}
}

func (o *OpenBao) Read(ctx context.Context, path string) (*Secret, error) {
	secret, err := o.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, err
	}

	return fromOpenBaoSecret(secret), nil
}

func (o *OpenBao) Write(ctx context.Context, path string, data map[string]any) (*Secret, error) {
	secret, err := o.client.Logical().WriteWithContext(ctx, path, data)
	if err != nil {
		return nil, err
	}

	return fromOpenBaoSecret(secret), nil
}

func (o *OpenBao) RenewSelf(ctx context.Context, increment int) (*Auth, error) {
	secret, err := o.client.Auth().Token().RenewSelfWithContext(ctx, increment)
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

func (o *OpenBao) SetToken(token string) {
	o.client.SetToken(token)
}

func (o *OpenBao) Close() error {
	return nil
}

func fromOpenBaoSecret(secret *openbaoapi.Secret) *Secret {
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
