#!/usr/bin/env bash

set -ex
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="${GITHUB_WORKSPACE:-$(realpath -- "${SCRIPT_DIR}/../..")}" 
# shellcheck source=smoke-test-helper.sh
source "${SCRIPT_DIR}/smoke-test-helper.sh"

# Configuration
# Floci is a lightweight open-source AWS emulator (https://floci.io, https://github.com/floci-io/floci).
# It is a drop-in LocalStack replacement: same port 4566, same wire protocol, and
# needs no auth token, so the smoke test is reproducible for contributors, forks,
# and external PRs.
FLOCI_CONTAINER="smoke-floci"
# Pinned to an immutable digest (1.6.0) for reproducible CI; multi-arch (amd64/arm64).
FLOCI_IMAGE="floci/floci:1.6.0@sha256:eab36252ea43a4a73928423f0372219052c5c6f87207f6c4754db14b91d6ed30"
AWS_ENDPOINT="http://localhost:4566"
AWS_REGION="us-east-1"
AWS_ACCESS_KEY_ID="test"
AWS_SECRET_ACCESS_KEY="test"
STACK_NAME="smoke-awssm"
SECRET_NAME="smoke_secret"
SECRET_PATH="database/mysql"
SECRET_FIELD="password"
SECRET_VALUE="awssm-smoke-pass-v1"
SECRET_VALUE_ROTATED="awssm-smoke-pass-v2"
KMS_KEY_ALIAS="alias/smoke-awssm"
COMPOSE_FILE="${SCRIPT_DIR}/smoke-awssm-compose.yml"

# Helper to run the AWS CLI against the floci endpoint. Floci needs no real
# credentials, but the CLI still requires values to sign the request.
aws_cmd() {
    AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID}" \
    AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY}" \
    AWS_DEFAULT_REGION="${AWS_REGION}" \
    aws --no-cli-pager --endpoint-url "${AWS_ENDPOINT}" "$@"
}

# Cleanup trap
cleanup() {
    echo -e "${RED}Running AWS Secrets Manager smoke test cleanup...${DEF}"
    remove_stack "${STACK_NAME}"
    docker secret rm "${SECRET_NAME}" 2>/dev/null || true
    if [[ -n "${FLOCI_CONTAINER}" ]]; then
        docker stop "${FLOCI_CONTAINER}" 2>/dev/null || true
        docker rm   "${FLOCI_CONTAINER}" 2>/dev/null || true
    fi
    remove_plugin
}
trap cleanup EXIT

command -v aws >/dev/null 2>&1 || die "aws CLI is required to run the AWS Secrets Manager smoke test."

# Start floci container (skip if an emulator is already serving on 4566, e.g. in CI)
if aws_cmd secretsmanager list-secrets >/dev/null 2>&1; then
    info "AWS emulator already running on 4566, skipping container start."
    FLOCI_CONTAINER=""
else
    info "Starting floci AWS emulator container..."
    docker run -d \
        --name "${FLOCI_CONTAINER}" \
        -p 4566:4566 \
        "${FLOCI_IMAGE}"
fi

# Wait for floci to be ready. Floci's /_localstack/health response shape differs
# from LocalStack's, so we probe the Secrets Manager API directly until it answers.
info "Waiting for floci to be ready..."
elapsed=0
until aws_cmd secretsmanager list-secrets >/dev/null 2>&1; do
    sleep 2
    elapsed=$((elapsed + 2))
    [[ "${elapsed}" -lt 60 ]] || die "floci did not become ready within 60s."
done
success "floci is ready."

info "Creating test KMS key..."
KMS_KEY_ID="$(aws_cmd kms create-key \
    --region "${AWS_REGION}" \
    --description "swarm-external-secrets smoke test key" \
    --query 'KeyMetadata.KeyId' \
    --output text)"
aws_cmd kms create-alias \
    --region "${AWS_REGION}" \
    --alias-name "${KMS_KEY_ALIAS}" \
    --target-key-id "${KMS_KEY_ID}"
success "KMS key created: ${KMS_KEY_ALIAS}"

encrypt_with_kms() {
    local plaintext="$1"
    aws_cmd kms encrypt \
        --region "${AWS_REGION}" \
        --key-id "${KMS_KEY_ALIAS}" \
        --plaintext "${plaintext}" \
        --cli-binary-format raw-in-base64-out \
        --query 'CiphertextBlob' \
        --output text
}

# Write test secret
info "Writing KMS-encrypted test secret to AWS Secrets Manager..."
SECRET_CIPHERTEXT="$(encrypt_with_kms "${SECRET_VALUE}")"
aws_cmd secretsmanager create-secret \
    --region "${AWS_REGION}" \
    --name "${SECRET_PATH}" \
    --secret-string "{\"${SECRET_FIELD}\":\"${SECRET_CIPHERTEXT}\"}"
success "Encrypted secret written: ${SECRET_PATH} ${SECRET_FIELD}"

# Build plugin
info "Building plugin and setting AWS Secrets Manager config..."
build_plugin
docker plugin disable "${PLUGIN_NAME}" --force 2>/dev/null || true
docker plugin set "${PLUGIN_NAME}" \
    SECRETS_PROVIDER="aws" \
    AWS_REGION="${AWS_REGION}" \
    AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID}" \
    AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY}" \
    AWS_ENDPOINT_URL="${AWS_ENDPOINT}" \
    ENABLE_ROTATION="true" \
    ROTATION_INTERVAL="10s" \
    ENABLE_MONITORING="false"

success "Plugin configured with AWS Secrets Manager settings."

# Enable plugin
info "Enabling plugin..."
enable_plugin

# Deploy stack
info "Deploying swarm stack..."
deploy_stack "${COMPOSE_FILE}" "${STACK_NAME}" 60

# Log service output
info "Logging service output..."
sleep 10
log_stack "${STACK_NAME}" "app"
assert_no_sensitive_rotation_metadata_logs

# Compare password == logged secret
info "Verifying secret value matches expected password..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE}" 60

# Rotate the password and verify
info "Rotating secret in AWS Secrets Manager..."
SECRET_CIPHERTEXT_ROTATED="$(encrypt_with_kms "${SECRET_VALUE_ROTATED}")"
aws_cmd secretsmanager put-secret-value \
    --region "${AWS_REGION}" \
    --secret-id "${SECRET_PATH}" \
    --secret-string "{\"${SECRET_FIELD}\":\"${SECRET_CIPHERTEXT_ROTATED}\"}"
success "Secret rotated to: ${SECRET_VALUE_ROTATED}"

info "Waiting for plugin rotation interval (15s)..."
sleep 30
assert_no_sensitive_rotation_metadata_logs

info "Logging service output after rotation..."
log_stack "${STACK_NAME}" "app"

info "Verifying rotated secret value..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE_ROTATED}" 180

success "AWS Secrets Manager with AWS KMS smoke test PASSED"
