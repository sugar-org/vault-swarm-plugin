package jwtsource

import (
	"context"
	"fmt"
	"os"
	"strings"
)

type Source interface {
	Token(ctx context.Context) (string, error)
}

type Static struct {
	Value string
}

func (s Static) Token(context.Context) (string, error) {
	token := strings.TrimSpace(s.Value)
	if token == "" {
		return "", fmt.Errorf("static jwt is empty")
	}
	return token, nil
}

type File struct {
	Path string
}

func (f File) Token(context.Context) (string, error) {
	data, err := os.ReadFile(f.Path) // #nosec G304 -- path is explicit plugin configuration.
	if err != nil {
		return "", fmt.Errorf("read jwt file: %w", err)
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("jwt file is empty")
	}

	return token, nil
}
