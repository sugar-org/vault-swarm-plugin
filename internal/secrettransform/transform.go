package secrettransform

import (
	"context"

	"github.com/sugar-org/swarm-external-secrets/providers"
)

// Transformer can modify a provider value before Docker receives it.
type Transformer interface {
	Transform(ctx context.Context, secretInfo *providers.SecretInfo, value []byte) ([]byte, error)
}
