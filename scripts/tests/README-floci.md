# Floci emulator checks

## AWS

The `aws-floci-tests` workflow (`.github/workflows/aws-floci-tests.yml`) uses [Floci](https://github.com/floci-io/floci) as a lightweight AWS emulator to verify the AWS KMS + AWS Secrets Manager flow used by KMS secret transformation (`internal/secrettransform/aws_kms.go`) — the same flow the full Swarm smoke test in `smoke-test-awssm.sh` exercises end to end.

The check (`scripts/tests/floci-kms-roundtrip.sh`):

1. creates a KMS key and alias
2. encrypts a test password with KMS
3. stores the base64 ciphertext as a JSON field in Secrets Manager
4. fetches the secret back and decrypts it with KMS (without a `KeyId`, exactly like the plugin's transformer) and verifies the plaintext
5. rotates the value with `put-secret-value` and verifies again

## Run locally (AWS)

Prerequisites: Docker, the `aws` CLI (v2), and `jq`.

Start Floci:

```bash
docker compose -f scripts/tests/floci-compose.yml up -d
```

Run the check (reads `AWS_ENDPOINT_URL`, `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` from the environment, defaulting to the emulator values):

```bash
bash scripts/tests/floci-kms-roundtrip.sh
```

## OCI

The `oci-floci-tests` workflow (`.github/workflows/oci-floci-tests.yml`) uses [floci-oci](https://floci.io/floci-oci/) on port 4599. The smoke test (`scripts/tests/smoke-test-oci.sh`):

1. starts `floci/floci-oci` unless `http://localhost:4599/_floci-oci/health` already succeeds
2. creates a vault, AES key, and secret (JSON `password` field)
3. fetches the secret bundle by name over REST
4. builds the plugin with `OCI_ENDPOINT=http://localhost:4599` and a throwaway API key
5. deploys a Swarm stack and verifies the mounted secret, including after rotation

```bash
bash scripts/tests/smoke-test-oci.sh
```

Health: `curl http://localhost:4599/_floci-oci/health`  
Vault/KMS/Secrets API notes: https://floci.io/floci-oci/services/kms-vault/

## References

- Floci repository: https://github.com/floci-io/floci
- floci-oci repository: https://github.com/floci-io/floci-oci
- Docker image (AWS): `floci/floci:1.6.0@sha256:eab36252ea43a4a73928423f0372219052c5c6f87207f6c4754db14b91d6ed30`
- Docker image (OCI): `floci/floci-oci:latest`
- LocalStack Swarm smoke test: `scripts/tests/smoke-test-awssm.sh`
