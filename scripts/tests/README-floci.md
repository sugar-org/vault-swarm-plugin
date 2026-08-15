# Floci AWS integration tests

These tests use [Floci](https://github.com/floci-io/floci) as a lightweight AWS emulator for fast Go tests of the AWS Secrets Manager provider and AWS KMS transformer. They complement the full Swarm + LocalStack smoke test in `smoke-test-awssm.sh`.

## Prerequisites

- Go 1.24+
- Docker (to run Floci), or an existing Floci instance on port `4566`

## Quick start

Start Floci and run the tests with one script:

```bash
bash scripts/tests/run-floci-tests.sh
```

Or start Floci manually:

```bash
docker run -d --name floci -p 4566:4566 floci/floci:1.6.0@sha256:eab36252ea43a4a73928423f0372219052c5c6f87207f6c4754db14b91d6ed30
```

Then run tests with endpoint overrides (same env vars the plugin supports):

```bash
export AWS_REGION=us-east-1
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_ENDPOINT_URL=http://localhost:4566
export AWS_KMS_ENDPOINT=http://localhost:4566

go test ./providers/... -run Floci -v
go test ./internal/secrettransform/... -run Floci -v
```

Tests are named with the `Floci` prefix so they can be filtered with `-run Floci`. If Floci is not reachable, tests are skipped (unless you set `FLOCI_SKIP=1` to skip explicitly).

## What is covered

| Test file | Covers |
|-----------|--------|
| `providers/aws_floci_test.go` | `AWSProvider.Initialize`, `GetSecret`, JSON field extraction, rotation hash detection via re-fetch |
| `internal/secrettransform/aws_kms_floci_test.go` | `AWSKMSTransformer.Transform` with `kms_decrypt=true`, base64 ciphertext, encryption context |

## CI

The `aws-floci-tests` job in `.github/workflows/aws-floci-tests.yml` starts Floci in Docker and runs `go test -run Floci` on every pull request. The LocalStack Swarm smoke test (`smoke-test-awssm`) remains unchanged for full E2E coverage.

## References

- Floci repository: https://github.com/floci-io/floci
- Docker image: `floci/floci:1.6.0@sha256:eab36252ea43a4a73928423f0372219052c5c6f87207f6c4754db14b91d6ed30`
- LocalStack smoke test: `scripts/tests/smoke-test-awssm.sh`
