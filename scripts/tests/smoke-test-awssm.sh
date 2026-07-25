#!/usr/bin/env bash

set -ex
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(realpath -- "${SCRIPT_DIR}/../..")"
# shellcheck source=smoke-test-helper.sh
source "${SCRIPT_DIR}/smoke-test-helper.sh"

# Configuration
# Kumo is a lightweight open-source AWS emulator (https://github.com/sivchari/kumo).
# It speaks the AWS Secrets Manager API on port 4566 and needs no auth token,
# so the smoke test is reproducible for contributors, forks, and external PRs.
KUMO_CONTAINER="smoke-kumo"
# Pinned to an immutable digest (0.26.0) for reproducible CI; multi-arch (amd64/arm64).
KUMO_IMAGE="ghcr.io/sivchari/kumo:0.26.0@sha256:e63054fbe10eb17b0c9142e937e11b3f4ee2709ac1c80035f3220542f3e5b045"
KUMO_ENDPOINT="http://localhost:4566"
AWS_REGION="us-east-1"
AWS_ACCESS_KEY_ID="test"
AWS_SECRET_ACCESS_KEY="test"
STACK_NAME="smoke-awssm"
SECRET_NAME="smoke_secret"
SECRET_PATH="database/mysql"
SECRET_FIELD="password"
SECRET_VALUE="awssm-smoke-pass-v1"
SECRET_VALUE_ROTATED="awssm-smoke-pass-v2"
COMPOSE_FILE="${SCRIPT_DIR}/smoke-awssm-compose.yml"

# Helper to run the AWS CLI against the Kumo endpoint. Kumo needs no real
# credentials, but the CLI still requires values to sign the request.
aws_cmd() {
    AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID}" \
    AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY}" \
    AWS_DEFAULT_REGION="${AWS_REGION}" \
    aws --endpoint-url "${KUMO_ENDPOINT}" "$@"
}

# Cleanup trap
cleanup() {
    echo -e "${RED}Running AWS Secrets Manager smoke test cleanup...${DEF}"
    remove_stack "${STACK_NAME}"
    docker secret rm "${SECRET_NAME}" 2>/dev/null || true
    if [[ -n "${KUMO_CONTAINER}" ]]; then
        docker stop "${KUMO_CONTAINER}" 2>/dev/null || true
        docker rm   "${KUMO_CONTAINER}" 2>/dev/null || true
    fi
    remove_plugin
}
trap cleanup EXIT

command -v aws >/dev/null 2>&1 || die "aws CLI is required to run the AWS Secrets Manager smoke test."

# Start Kumo container (skip if an emulator is already serving on 4566, e.g. in CI)
if aws_cmd secretsmanager list-secrets >/dev/null 2>&1; then
    info "AWS emulator already running on 4566, skipping container start."
    KUMO_CONTAINER=""
else
    info "Starting Kumo AWS emulator container..."
    docker run -d \
        --name "${KUMO_CONTAINER}" \
        -p 4566:4566 \
        "${KUMO_IMAGE}"
fi

# Wait for Kumo to be ready. Kumo has no dedicated health endpoint, so we probe
# the Secrets Manager API directly until it answers.
info "Waiting for Kumo to be ready..."
elapsed=0
until aws_cmd secretsmanager list-secrets >/dev/null 2>&1; do
    sleep 2
    elapsed=$((elapsed + 2))
    [[ "${elapsed}" -lt 60 ]] || die "Kumo did not become ready within 60s."
done
success "Kumo is ready."

# Write test secret
info "Writing test secret to AWS Secrets Manager..."
aws_cmd secretsmanager create-secret \
    --region "${AWS_REGION}" \
    --name "${SECRET_PATH}" \
    --secret-string "{\"${SECRET_FIELD}\":\"${SECRET_VALUE}\"}"
success "Secret written: ${SECRET_PATH} ${SECRET_FIELD}=${SECRET_VALUE}"

# Build plugin
info "Building plugin and setting AWS Secrets Manager config..."
build_plugin
docker plugin disable "${PLUGIN_NAME}" --force 2>/dev/null || true
docker plugin set "${PLUGIN_NAME}" \
    SECRETS_PROVIDER="aws" \
    AWS_REGION="${AWS_REGION}" \
    AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID}" \
    AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY}" \
    AWS_ENDPOINT_URL="${KUMO_ENDPOINT}" \
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
aws_cmd secretsmanager put-secret-value \
    --region "${AWS_REGION}" \
    --secret-id "${SECRET_PATH}" \
    --secret-string "{\"${SECRET_FIELD}\":\"${SECRET_VALUE_ROTATED}\"}"
success "Secret rotated to: ${SECRET_VALUE_ROTATED}"

info "Waiting for plugin rotation interval (15s)..."
sleep 30
assert_no_sensitive_rotation_metadata_logs

info "Logging service output after rotation..."
log_stack "${STACK_NAME}" "app"

info "Verifying rotated secret value..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE_ROTATED}" 180

success "AWS Secrets Manager smoke test PASSED"
