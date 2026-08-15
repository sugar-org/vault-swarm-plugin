# Floci AWS emulator checks

The `aws-floci-tests` workflow (`.github/workflows/aws-floci-tests.yml`) uses [Floci](https://github.com/floci-io/floci) as a lightweight AWS emulator to verify the AWS KMS + AWS Secrets Manager flow used by KMS secret transformation (`internal/secrettransform/aws_kms.go`) — the same flow the full Swarm smoke test in `smoke-test-awssm.sh` exercises end to end.

The check (`scripts/tests/floci-kms-roundtrip.sh`):

1. creates a KMS key and alias
2. encrypts a test password with KMS
3. stores the base64 ciphertext as a JSON field in Secrets Manager
4. fetches the secret back and decrypts it with KMS (without a `KeyId`, exactly like the plugin's transformer) and verifies the plaintext
5. rotates the value with `put-secret-value` and verifies again

## Run locally

Prerequisites: Docker, the `aws` CLI (v2), and `jq`.

Start Floci:

```bash
docker compose -f scripts/tests/floci-compose.yml up -d
```

Run the check (reads `AWS_ENDPOINT_URL`, `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` from the environment, defaulting to the emulator values):

```bash
bash scripts/tests/floci-kms-roundtrip.sh
```

## References

- Floci repository: https://github.com/floci-io/floci
- Docker image: `floci/floci:1.6.0@sha256:eab36252ea43a4a73928423f0372219052c5c6f87207f6c4754db14b91d6ed30`
- LocalStack Swarm smoke test: `scripts/tests/smoke-test-awssm.sh`
