# Kumo AWS integration tests

These tests use [Kumo](https://github.com/sivchari/kumo) as a lightweight AWS emulator for fast Go tests of the AWS Secrets Manager provider and AWS KMS transformer. They complement the full Swarm + LocalStack smoke test in `smoke-test-awssm.sh`.

## Prerequisites

- Go 1.24+
- Docker (to run Kumo), or an existing Kumo instance on port `4566`

## Quick start

Start Kumo and run the tests with one script:

```bash
bash scripts/tests/run-kumo-tests.sh
```

Or start Kumo manually:

```bash
docker run -d --name kumo -p 4566:4566 ghcr.io/sivchari/kumo:latest
```

Then run tests with endpoint overrides (same env vars the plugin supports):

```bash
export AWS_REGION=us-east-1
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_ENDPOINT_URL=http://localhost:4566
export AWS_KMS_ENDPOINT=http://localhost:4566

go test ./providers/... -run Kumo -v
go test ./internal/secrettransform/... -run Kumo -v
```

Tests are named with the `Kumo` prefix so they can be filtered with `-run Kumo`. If Kumo is not reachable, tests are skipped (unless you set `KUMO_SKIP=1` to skip explicitly).

## What is covered

| Test file | Covers |
|-----------|--------|
| `providers/aws_kumo_test.go` | `AWSProvider.Initialize`, `GetSecret`, JSON field extraction, rotation hash detection via re-fetch |
| `internal/secrettransform/aws_kms_kumo_test.go` | `AWSKMSTransformer.Transform` with `kms_decrypt=true`, base64 ciphertext, encryption context |

## CI

The `aws-kumo-tests` job in `.github/workflows/aws-kumo-tests.yml` starts Kumo in Docker and runs `go test -run Kumo` on every pull request. The LocalStack Swarm smoke test (`smoke-test-awssm`) remains unchanged for full E2E coverage.

## References

- Kumo repository: https://github.com/sivchari/kumo
- Docker image: `ghcr.io/sivchari/kumo:latest`
- LocalStack smoke test: `scripts/tests/smoke-test-awssm.sh`
