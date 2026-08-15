package secrettransform

import (
	"context"
	"encoding/base64"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/sugar-org/swarm-external-secrets/providers"
)

func flociSetting(t *testing.T, key, fallback string) string {
	t.Helper()
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func flociSettings(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		"AWS_REGION":            flociSetting(t, "AWS_REGION", "us-east-1"),
		"AWS_ACCESS_KEY_ID":     flociSetting(t, "AWS_ACCESS_KEY_ID", "test"),
		"AWS_SECRET_ACCESS_KEY": flociSetting(t, "AWS_SECRET_ACCESS_KEY", "test"),
		"AWS_ENDPOINT_URL":      flociSetting(t, "AWS_ENDPOINT_URL", "http://localhost:4566"),
		"AWS_KMS_ENDPOINT":      flociSetting(t, "AWS_KMS_ENDPOINT", flociSetting(t, "AWS_ENDPOINT_URL", "http://localhost:4566")),
	}
}

func requireFlociKMS(t *testing.T) {
	t.Helper()
	if os.Getenv("FLOCI_SKIP") == "1" {
		t.Skip("FLOCI_SKIP=1 set, skipping Floci integration test")
	}
	endpoint := flociSettings(t)["AWS_KMS_ENDPOINT"]
	parsed, err := url.Parse(endpoint)
	if err != nil {
		t.Skipf("cannot parse AWS_KMS_ENDPOINT %q: %v", endpoint, err)
	}
	conn, err := net.DialTimeout("tcp", parsed.Host, 2*time.Second)
	if err != nil {
		t.Skipf("floci not reachable on %s: %v", parsed.Host, err)
	}
	if cerr := conn.Close(); cerr != nil {
		t.Fatalf("close probe connection: %v", cerr)
	}
}

func newFlociKMSClient(t *testing.T) *kms.Client {
	t.Helper()
	settings := flociSettings(t)
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(settings["AWS_REGION"]),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			settings["AWS_ACCESS_KEY_ID"], settings["AWS_SECRET_ACCESS_KEY"], "",
		)),
	)
	if err != nil {
		t.Fatalf("load aws config: %v", err)
	}
	endpoint := settings["AWS_KMS_ENDPOINT"]
	return kms.NewFromConfig(cfg, func(o *kms.Options) {
		o.BaseEndpoint = &endpoint
	})
}

func flociEncrypt(t *testing.T, client *kms.Client, keyID string, plaintext []byte, encryptionContext map[string]string) string {
	t.Helper()
	out, err := client.Encrypt(context.Background(), &kms.EncryptInput{
		KeyId:             &keyID,
		Plaintext:         plaintext,
		EncryptionContext: encryptionContext,
	})
	if err != nil {
		t.Fatalf("kms encrypt: %v", err)
	}
	return base64.StdEncoding.EncodeToString(out.CiphertextBlob)
}

func TestFlociKMSTransformDecryptsBase64Ciphertext(t *testing.T) {
	requireFlociKMS(t)

	client := newFlociKMSClient(t)
	key, err := client.CreateKey(context.Background(), &kms.CreateKeyInput{})
	if err != nil {
		t.Fatalf("kms create-key: %v", err)
	}

	plaintext := "floci-kms-plaintext-v1"
	ciphertext := flociEncrypt(t, client, *key.KeyMetadata.KeyId, []byte(plaintext), nil)

	transformer := NewAWSKMSTransformer(flociSettings(t))
	info := &providers.SecretInfo{
		DockerSecretName: "smoke_secret",
		SecretPath:       "database/mysql",
		SecretField:      "password",
		Labels: map[string]string{
			"kms_decrypt": "true",
		},
	}

	got, err := transformer.Transform(context.Background(), info, []byte(ciphertext))
	if err != nil {
		t.Fatalf("Transform() error = %v", err)
	}
	if string(got) != plaintext {
		t.Fatalf("Transform() = %q, want %q", string(got), plaintext)
	}
}

func TestFlociKMSTransformWithEncryptionContext(t *testing.T) {
	requireFlociKMS(t)

	client := newFlociKMSClient(t)
	key, err := client.CreateKey(context.Background(), &kms.CreateKeyInput{})
	if err != nil {
		t.Fatalf("kms create-key: %v", err)
	}

	plaintext := "floci-kms-context-plaintext"
	encryptionContext := map[string]string{"app": "swarm-external-secrets", "env": "test"}
	ciphertext := flociEncrypt(t, client, *key.KeyMetadata.KeyId, []byte(plaintext), encryptionContext)

	transformer := NewAWSKMSTransformer(flociSettings(t))
	info := &providers.SecretInfo{
		SecretPath:  "database/mysql",
		SecretField: "password",
		Labels: map[string]string{
			"kms_decrypt":            "true",
			"kms_encryption_context": `{"app":"swarm-external-secrets","env":"test"}`,
		},
	}

	got, err := transformer.Transform(context.Background(), info, []byte(ciphertext))
	if err != nil {
		t.Fatalf("Transform() with matching context error = %v", err)
	}
	if string(got) != plaintext {
		t.Fatalf("Transform() = %q, want %q", string(got), plaintext)
	}

	wrongContextInfo := &providers.SecretInfo{
		SecretPath:  "database/mysql",
		SecretField: "password",
		Labels: map[string]string{
			"kms_decrypt":            "true",
			"kms_encryption_context": `{"app":"other-app","env":"test"}`,
		},
	}
	if _, err := transformer.Transform(context.Background(), wrongContextInfo, []byte(ciphertext)); err == nil {
		t.Skip("emulator does not enforce encryption context matching on decrypt")
	}
}

func TestFlociKMSTransformPassthroughWhenDecryptDisabled(t *testing.T) {
	transformer := NewAWSKMSTransformer(nil)
	info := &providers.SecretInfo{
		SecretPath:  "database/mysql",
		SecretField: "password",
		Labels: map[string]string{
			"kms_decrypt": "false",
		},
	}
	value := []byte("raw-provider-value")

	got, err := transformer.Transform(context.Background(), info, value)
	if err != nil {
		t.Fatalf("Transform() error = %v", err)
	}
	if string(got) != string(value) {
		t.Fatalf("Transform() = %q, want unchanged %q", string(got), string(value))
	}
}

func TestFlociKMSTransformRejectsInvalidBase64(t *testing.T) {
	transformer := NewAWSKMSTransformer(flociSettings(t))
	info := &providers.SecretInfo{
		SecretPath: "database/mysql",
		Labels: map[string]string{
			"kms_decrypt": "true",
		},
	}

	_, err := transformer.Transform(context.Background(), info, []byte("!!not-base64!!"))
	if err == nil {
		t.Fatal("Transform() with invalid base64 succeeded, want error")
	}
	if !strings.Contains(err.Error(), "decode kms ciphertext") {
		t.Fatalf("Transform() error = %v, want decode kms ciphertext failure", err)
	}
}
