package providers

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/docker/go-plugins-helpers/secrets"
)

func flociEnvOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func flociProviderSettings() map[string]string {
	return map[string]string{
		"AWS_REGION":            flociEnvOrDefault("AWS_REGION", "us-east-1"),
		"AWS_ACCESS_KEY_ID":     flociEnvOrDefault("AWS_ACCESS_KEY_ID", "test"),
		"AWS_SECRET_ACCESS_KEY": flociEnvOrDefault("AWS_SECRET_ACCESS_KEY", "test"),
		"AWS_ENDPOINT_URL":      flociEnvOrDefault("AWS_ENDPOINT_URL", "http://localhost:4566"),
	}
}

func requireFlociSecretsManager(t *testing.T) {
	t.Helper()
	if os.Getenv("FLOCI_SKIP") == "1" {
		t.Skip("FLOCI_SKIP=1 set, skipping Floci integration test")
	}
	endpoint := flociProviderSettings()["AWS_ENDPOINT_URL"]
	parsed, err := url.Parse(endpoint)
	if err != nil {
		t.Skipf("cannot parse AWS_ENDPOINT_URL %q: %v", endpoint, err)
	}
	conn, err := net.DialTimeout("tcp", parsed.Host, 2*time.Second)
	if err != nil {
		t.Skipf("floci not reachable on %s: %v", parsed.Host, err)
	}
	if cerr := conn.Close(); cerr != nil {
		t.Fatalf("close probe connection: %v", cerr)
	}
}

func newFlociSecretsClient(t *testing.T) *secretsmanager.Client {
	t.Helper()
	settings := flociProviderSettings()
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(settings["AWS_REGION"]),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			settings["AWS_ACCESS_KEY_ID"], settings["AWS_SECRET_ACCESS_KEY"], "",
		)),
	)
	if err != nil {
		t.Fatalf("load aws config: %v", err)
	}
	endpoint := settings["AWS_ENDPOINT_URL"]
	return secretsmanager.NewFromConfig(cfg, func(o *secretsmanager.Options) {
		o.BaseEndpoint = &endpoint
	})
}

func flociSecretName(prefix string) string {
	return fmt.Sprintf("floci/go-test/%s-%d", prefix, time.Now().UnixNano())
}

func flociCreateSecret(t *testing.T, client *secretsmanager.Client, name, secretString string) {
	t.Helper()
	_, err := client.CreateSecret(context.Background(), &secretsmanager.CreateSecretInput{
		Name:         &name,
		SecretString: &secretString,
	})
	if err != nil {
		t.Fatalf("create-secret %s: %v", name, err)
	}
}

func flociPutSecretValue(t *testing.T, client *secretsmanager.Client, name, secretString string) {
	t.Helper()
	_, err := client.PutSecretValue(context.Background(), &secretsmanager.PutSecretValueInput{
		SecretId:     &name,
		SecretString: &secretString,
	})
	if err != nil {
		t.Fatalf("put-secret-value %s: %v", name, err)
	}
}

func newFlociAWSProvider(t *testing.T) *AWSProvider {
	t.Helper()
	provider := &AWSProvider{}
	if err := provider.Initialize(flociProviderSettings()); err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	return provider
}

func TestFlociAWSProviderInitializeAndGetSecretJSONField(t *testing.T) {
	requireFlociSecretsManager(t)

	client := newFlociSecretsClient(t)
	name := flociSecretName("json-field")
	flociCreateSecret(t, client, name, `{"username":"admin","password":"floci-pass-v1"}`)

	provider := newFlociAWSProvider(t)
	got, err := provider.GetSecret(context.Background(), &SecretInfo{
		SecretPath:  name,
		SecretField: "password",
	})
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	if string(got) != "floci-pass-v1" {
		t.Fatalf("GetSecret() = %q, want %q", string(got), "floci-pass-v1")
	}
}

func TestFlociAWSProviderGetSecretDefaultFieldFallback(t *testing.T) {
	requireFlociSecretsManager(t)

	client := newFlociSecretsClient(t)
	name := flociSecretName("default-field")
	flociCreateSecret(t, client, name, `{"password":"default-field-pass"}`)

	provider := newFlociAWSProvider(t)
	got, err := provider.GetSecret(context.Background(), &SecretInfo{
		SecretPath: name,
	})
	if err != nil {
		t.Fatalf("GetSecret() error = %v", err)
	}
	if string(got) != "default-field-pass" {
		t.Fatalf("GetSecret() = %q, want %q", string(got), "default-field-pass")
	}
}

func TestFlociAWSProviderRotationRefetchDetectsUpdatedValue(t *testing.T) {
	requireFlociSecretsManager(t)

	client := newFlociSecretsClient(t)
	name := flociSecretName("rotation")
	flociCreateSecret(t, client, name, `{"password":"floci-pass-v1"}`)

	provider := newFlociAWSProvider(t)
	info := &SecretInfo{SecretPath: name, SecretField: "password"}

	before, err := provider.GetSecret(context.Background(), info)
	if err != nil {
		t.Fatalf("GetSecret() before rotation error = %v", err)
	}
	if string(before) != "floci-pass-v1" {
		t.Fatalf("GetSecret() before rotation = %q, want %q", string(before), "floci-pass-v1")
	}

	flociPutSecretValue(t, client, name, `{"password":"floci-pass-v2"}`)

	after, err := provider.GetSecret(context.Background(), info)
	if err != nil {
		t.Fatalf("GetSecret() after rotation error = %v", err)
	}
	if string(after) != "floci-pass-v2" {
		t.Fatalf("GetSecret() after rotation = %q, want %q", string(after), "floci-pass-v2")
	}
}

func TestFlociAWSProviderGetSecretMissingFieldReturnsError(t *testing.T) {
	requireFlociSecretsManager(t)

	client := newFlociSecretsClient(t)
	name := flociSecretName("missing-field")
	flociCreateSecret(t, client, name, `{"username":"admin"}`)

	provider := newFlociAWSProvider(t)
	_, err := provider.GetSecret(context.Background(), &SecretInfo{
		SecretPath:  name,
		SecretField: "token",
	})
	if err == nil {
		t.Fatal("GetSecret() with missing field succeeded, want error")
	}
}

func TestFlociAWSProviderGetSecretUnknownSecretReturnsError(t *testing.T) {
	requireFlociSecretsManager(t)

	provider := newFlociAWSProvider(t)
	_, err := provider.GetSecret(context.Background(), &SecretInfo{
		SecretPath: flociSecretName("does-not-exist"),
	})
	if err == nil {
		t.Fatal("GetSecret() with unknown secret succeeded, want error")
	}
}

func TestFlociAWSProviderBuildSecretPath(t *testing.T) {
	provider := &AWSProvider{}

	if got := provider.BuildSecretPath(secrets.Request{
		SecretLabels: map[string]string{"aws_secret_name": "database/mysql"},
	}); got != "database/mysql" {
		t.Fatalf("BuildSecretPath() with aws_secret_name label = %q, want %q", got, "database/mysql")
	}

	if got := provider.BuildSecretPath(secrets.Request{
		ServiceName: "app",
		SecretName:  "db_pass",
	}); got != "app/db_pass" {
		t.Fatalf("BuildSecretPath() with service name = %q, want %q", got, "app/db_pass")
	}

	if got := provider.BuildSecretPath(secrets.Request{
		SecretName: "db_pass",
	}); got != "db_pass" {
		t.Fatalf("BuildSecretPath() with secret name only = %q, want %q", got, "db_pass")
	}
}

func TestFlociAWSProviderSupportsRotationAndFieldLabel(t *testing.T) {
	provider := &AWSProvider{}
	if !provider.SupportsRotation() {
		t.Fatal("SupportsRotation() = false, want true")
	}
	if got := provider.GetSecretFieldLabel(); got != "aws_field" {
		t.Fatalf("GetSecretFieldLabel() = %q, want %q", got, "aws_field")
	}
	if got := provider.GetProviderName(); got != "aws" {
		t.Fatalf("GetProviderName() = %q, want %q", got, "aws")
	}
}
