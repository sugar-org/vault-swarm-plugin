package jwtsource

import (
	"context"
	"errors"
)

type Chain struct {
	Sources []Source
}

func (c Chain) Token(ctx context.Context) (string, error) {
	errs := []error{}

	for _, source := range c.Sources {
		if source == nil {
			continue
		}

		token, err := source.Token(ctx)
		if err == nil {
			return token, nil
		}

		errs = append(errs, err)
	}

	if len(errs) == 0 {
		return "", errors.New("no jwt sources configured")
	}

	return "", errors.Join(errs...)
}
