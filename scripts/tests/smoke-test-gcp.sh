#!/usr/bin/env bash

set -ex
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="${GITHUB_WORKSPACE:-$(realpath -- "${SCRIPT_DIR}/../..")}"
# shellcheck source=smoke-test-helper.sh
source "${SCRIPT_DIR}/smoke-test-helper.sh"

# Configuration
# floci-gcp is a lightweight open-source GCP emulator (https://floci.io/floci-gcp/).
# Secret Manager is on port 4588 (gRPC + REST), needs no auth token or license.
FLOCI_CONTAINER="smoke-floci-gcp"
FLOCI_IMAGE="floci/floci-gcp:latest"
GCP_ENDPOINT="http://localhost:4588"
GCP_EMULATOR_HOST="localhost:4588"
GCP_PROJECT_ID="floci-local"
STACK_NAME="smoke-gcp"
SECRET_NAME="smoke_secret"
SECRET_PATH="smoke-test-secret"
SECRET_FIELD="password"
SECRET_VALUE="gcp-smoke-pass-v1"
SECRET_VALUE_ROTATED="gcp-smoke-pass-v2"
COMPOSE_FILE="${SCRIPT_DIR}/smoke-gcp-compose.yml"
SECRET_PARENT="projects/${GCP_PROJECT_ID}/secrets/${SECRET_PATH}"

# Helper to call floci-gcp Secret Manager REST.
sm_api() {
    curl -sf \
        -H "Content-Type: application/json" \
        "$@"
}

json_payload() {
    local value="$1"
    printf '{"%s":"%s"}' "${SECRET_FIELD}" "${value}" | base64 -w0 2>/dev/null || printf '{"%s":"%s"}' "${SECRET_FIELD}" "${value}" | base64
}

# Cleanup trap
cleanup() {
    echo -e "${RED}Running GCP Secret Manager smoke test cleanup...${DEF}"
    remove_stack "${STACK_NAME}"
    docker secret rm "${SECRET_NAME}" 2>/dev/null || true
    if [[ -n "${FLOCI_CONTAINER}" ]]; then
        echo -e "${RED}floci-gcp logs:${DEF}"
        docker logs "${FLOCI_CONTAINER}" 2>/dev/null || true
        docker stop "${FLOCI_CONTAINER}" 2>/dev/null || true
        docker rm   "${FLOCI_CONTAINER}" 2>/dev/null || true
    fi
    remove_plugin
}
trap cleanup EXIT

command -v curl >/dev/null 2>&1 || die "curl is required to run the GCP Secret Manager smoke test."

# Start floci-gcp container (skip if an emulator is already serving on 4588)
if sm_api "${GCP_ENDPOINT}/v1/projects/${GCP_PROJECT_ID}/secrets" >/dev/null 2>&1; then
    info "GCP emulator already running on 4588, skipping container start."
    FLOCI_CONTAINER=""
else
    info "Starting floci-gcp emulator container..."
    docker run -d \
        --name "${FLOCI_CONTAINER}" \
        -p 4588:4588 \
        "${FLOCI_IMAGE}"
fi

info "Waiting for floci-gcp to be ready..."
elapsed=0
until sm_api "${GCP_ENDPOINT}/v1/projects/${GCP_PROJECT_ID}/secrets" >/dev/null 2>&1; do
    sleep 2
    elapsed=$((elapsed + 2))
    [[ "${elapsed}" -lt 60 ]] || die "floci-gcp did not become ready within 60s."
done
success "floci-gcp is ready."

info "Creating test secret in floci-gcp Secret Manager..."
sm_api -X POST \
    "${GCP_ENDPOINT}/v1/projects/${GCP_PROJECT_ID}/secrets?secretId=${SECRET_PATH}" \
    -d '{"replication":{"automatic":{}}}' >/dev/null || true
sm_api -X POST \
    "${GCP_ENDPOINT}/v1/${SECRET_PARENT}:addVersion" \
    -d "{\"payload\":{\"data\":\"$(json_payload "${SECRET_VALUE}")\"}}" >/dev/null
success "Secret written: ${SECRET_PATH}"

info "Building plugin and setting GCP Secret Manager config..."
build_plugin
docker plugin disable "${PLUGIN_NAME}" --force 2>/dev/null || true
docker plugin set "${PLUGIN_NAME}" \
    SECRETS_PROVIDER="gcp" \
    GCP_PROJECT_ID="${GCP_PROJECT_ID}" \
    SECRET_MANAGER_EMULATOR_HOST="${GCP_EMULATOR_HOST}" \
    ENABLE_ROTATION="true" \
    ROTATION_INTERVAL="10s" \
    ENABLE_MONITORING="false"

success "Plugin configured with GCP Secret Manager settings."

info "Enabling plugin..."
enable_plugin

info "Deploying swarm stack..."
deploy_stack "${COMPOSE_FILE}" "${STACK_NAME}" 60

info "Logging service output..."
sleep 10
log_stack "${STACK_NAME}" "app"
assert_no_sensitive_rotation_metadata_logs

info "Verifying secret value matches expected password..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE}" 60

info "Rotating secret in GCP Secret Manager..."
sm_api -X POST \
    "${GCP_ENDPOINT}/v1/${SECRET_PARENT}:addVersion" \
    -d "{\"payload\":{\"data\":\"$(json_payload "${SECRET_VALUE_ROTATED}")\"}}" >/dev/null
success "Secret rotated to: ${SECRET_VALUE_ROTATED}"

info "Waiting for plugin rotation interval..."
sleep 30
assert_no_sensitive_rotation_metadata_logs

info "Logging service output after rotation..."
log_stack "${STACK_NAME}" "app"

info "Verifying rotated secret value..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE_ROTATED}" 180

success "GCP Secret Manager smoke test PASSED"
