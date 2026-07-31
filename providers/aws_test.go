package providers

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
)

type contextKey struct{}

type fakeIdentityTokenSource struct {
	contextValue any
}

func (s *fakeIdentityTokenSource) FetchIdentityToken(ctx context.Context) ([]byte, error) {
	s.contextValue = ctx.Value(contextKey{})
	return []byte("signed-jwt-svid"), nil
}

type fakeWebIdentityClient struct {
	contextValue any
	input        *sts.AssumeRoleWithWebIdentityInput
}

func (c *fakeWebIdentityClient) AssumeRoleWithWebIdentity(
	ctx context.Context,
	input *sts.AssumeRoleWithWebIdentityInput,
	_ ...func(*sts.Options),
) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	c.contextValue = ctx.Value(contextKey{})
	c.input = input
	expiration := time.Now().Add(time.Hour)
	return &sts.AssumeRoleWithWebIdentityOutput{
		Credentials: &types.Credentials{
			AccessKeyId:     aws.String("access-key"),
			SecretAccessKey: aws.String("secret-key"),
			SessionToken:    aws.String("session-token"),
			Expiration:      &expiration,
		},
	}, nil
}

func TestAWSProvider_Initialize_Validation(t *testing.T) {
	clearAWSEnvironment(t)

	tests := []struct {
		name    string
		config  map[string]string
		wantErr string
	}{
		{
			name:    "unknown authentication method",
			config:  map[string]string{"AWS_AUTH_METHOD": "unknown"},
			wantErr: `unsupported AWS_AUTH_METHOD "unknown"`,
		},
		{
			name:    "partial static credentials",
			config:  map[string]string{"AWS_ACCESS_KEY_ID": "access-key"},
			wantErr: "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set together",
		},
		{
			name:    "explicit static authentication requires credentials",
			config:  map[string]string{"AWS_AUTH_METHOD": "static"},
			wantErr: "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required for static authentication",
		},
		{
			name:    "spiffe authentication requires role",
			config:  map[string]string{"AWS_AUTH_METHOD": "spiffe"},
			wantErr: "AWS_ROLE_ARN is required for spiffe authentication",
		},
		{
			name: "spiffe authentication rejects static credentials",
			config: map[string]string{
				"AWS_AUTH_METHOD":       "spiffe",
				"AWS_ROLE_ARN":          "arn:aws:iam::123456789012:role/swarm-external-secrets",
				"AWS_ACCESS_KEY_ID":     "access-key",
				"AWS_SECRET_ACCESS_KEY": "secret-key",
			},
			wantErr: "AWS_ACCESS_KEY_ID must not be set when AWS_AUTH_METHOD=spiffe",
		},
		{
			name: "spiffe authentication rejects profiles",
			config: map[string]string{
				"AWS_AUTH_METHOD": "spiffe",
				"AWS_ROLE_ARN":    "arn:aws:iam::123456789012:role/swarm-external-secrets",
				"AWS_PROFILE":     "production",
			},
			wantErr: "AWS_PROFILE must not be set when AWS_AUTH_METHOD=spiffe",
		},
		{
			name: "spiffe authentication validates socket URL",
			config: map[string]string{
				"AWS_AUTH_METHOD":        "spiffe",
				"AWS_ROLE_ARN":           "arn:aws:iam::123456789012:role/swarm-external-secrets",
				"SPIFFE_ENDPOINT_SOCKET": "tcp://127.0.0.1:8080",
			},
			wantErr: "SPIFFE_ENDPOINT_SOCKET must be a unix socket URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &AWSProvider{}
			err := provider.Initialize(tt.config)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Initialize() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestAWSProvider_Initialize_SPIFFEIsLazy(t *testing.T) {
	clearAWSEnvironment(t)

	provider := &AWSProvider{}
	err := provider.Initialize(map[string]string{
		"AWS_AUTH_METHOD":        "spiffe",
		"AWS_ROLE_ARN":           "arn:aws:iam::123456789012:role/swarm-external-secrets",
		"SPIFFE_ENDPOINT_SOCKET": "unix:///socket/that/does/not/exist.sock",
	})
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	if provider.tokenSource == nil {
		t.Fatal("Initialize() did not configure a SPIFFE token source")
	}
	if err := provider.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestAWSProvider_Initialize_LegacyStaticCredentials(t *testing.T) {
	clearAWSEnvironment(t)

	provider := &AWSProvider{}
	err := provider.Initialize(map[string]string{
		"AWS_REGION":            "us-west-2",
		"AWS_ACCESS_KEY_ID":     "legacy-access-key",
		"AWS_SECRET_ACCESS_KEY": "legacy-secret-key",
	})
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}

	cfg, err := provider.loadAWSConfig(t.Context())
	if err != nil {
		t.Fatalf("loadAWSConfig() error = %v", err)
	}
	credentials, err := cfg.Credentials.Retrieve(t.Context())
	if err != nil {
		t.Fatalf("Retrieve() error = %v", err)
	}
	if got, want := credentials.AccessKeyID, "legacy-access-key"; got != want {
		t.Fatalf("AccessKeyID = %q, want %q", got, want)
	}
	if got, want := credentials.SecretAccessKey, "legacy-secret-key"; got != want {
		t.Fatalf("SecretAccessKey = %q, want %q", got, want)
	}
	if provider.tokenSource != nil {
		t.Fatal("legacy authentication unexpectedly configured a SPIFFE token source")
	}
}

func TestSPIFFECredentialsProvider_Retrieve_PropagatesContext(t *testing.T) {
	t.Parallel()

	tokenSource := &fakeIdentityTokenSource{}
	client := &fakeWebIdentityClient{}
	provider := &spiffeCredentialsProvider{
		client:      client,
		tokenSource: tokenSource,
		roleARN:     "arn:aws:iam::123456789012:role/swarm-external-secrets",
	}
	ctx := context.WithValue(t.Context(), contextKey{}, "request")

	credentials, err := provider.Retrieve(ctx)
	if err != nil {
		t.Fatalf("Retrieve() error = %v", err)
	}
	if tokenSource.contextValue != "request" {
		t.Fatal("FetchIdentityToken() did not receive the request context")
	}
	if client.contextValue != "request" {
		t.Fatal("AssumeRoleWithWebIdentity() did not receive the request context")
	}
	if got, want := aws.ToString(client.input.WebIdentityToken), "signed-jwt-svid"; got != want {
		t.Fatalf("WebIdentityToken = %q, want %q", got, want)
	}
	if got, want := credentials.Source, spiffeCredentialSource; got != want {
		t.Fatalf("credential source = %q, want %q", got, want)
	}
}

func clearAWSEnvironment(t *testing.T) {
	t.Helper()

	for _, key := range []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_AUTH_METHOD",
		"AWS_ENDPOINT_URL",
		"AWS_JWT_AUDIENCE",
		"AWS_PROFILE",
		"AWS_REGION",
		"AWS_ROLE_ARN",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_STS_ENDPOINT_URL",
		"SPIFFE_ENDPOINT_SOCKET",
	} {
		t.Setenv(key, "")
	}
}
