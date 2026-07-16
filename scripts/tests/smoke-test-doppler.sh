#!/usr/bin/env bash

set -ex
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(realpath -- "${SCRIPT_DIR}/../..")"

# shellcheck source=smoke-test-helper.sh
source "${SCRIPT_DIR}/smoke-test-helper.sh"

# Configuration
MOCK_PORT="18080"
MOCK_URL="http://127.0.0.1:${MOCK_PORT}"
DOPPLER_TOKEN="dp.st.smoke-test"
STACK_NAME="smoke-doppler"
SECRET_NAME="smoke_secret"
SECRET_KEY="SMOKE_TEST_PASSWORD"
SECRET_VALUE="doppler-smoke-pass-v1"
SECRET_VALUE_ROTATED="doppler-smoke-pass-v2"
COMPOSE_FILE="${SCRIPT_DIR}/smoke-doppler-compose.yml"
MOCK_SERVER_PID=""
EXIT_CODE=0

cleanup() {
    echo -e "${RED}Running Doppler smoke test cleanup...${DEF}"
    remove_stack "${STACK_NAME}"
    docker secret rm "${SECRET_NAME}" 2>/dev/null || true
    if [[ -n "${MOCK_SERVER_PID}" ]]; then
        kill "${MOCK_SERVER_PID}" 2>/dev/null || true
        wait "${MOCK_SERVER_PID}" 2>/dev/null || true
    fi
    remove_plugin
    exit "${EXIT_CODE}"
}
trap cleanup EXIT

info "Starting Doppler API mock server..."
go run "${REPO_ROOT}/scripts/tests/mock-doppler-server" &
MOCK_SERVER_PID=$!

elapsed=0
until curl -fsS \
    -H "Authorization: Bearer ${DOPPLER_TOKEN}" \
    "${MOCK_URL}/v3/configs/config/secrets/download?format=json" \
    | grep -q "${SECRET_VALUE}"; do
    sleep 1
    elapsed=$((elapsed + 1))
    [[ "${elapsed}" -lt 15 ]] || die "Doppler mock server did not become ready within 15s."
done
success "Doppler mock server is ready."

info "Building plugin and setting Doppler config..."
build_plugin

docker plugin set "${PLUGIN_NAME}" \
    SECRETS_PROVIDER="doppler" \
    DOPPLER_TOKEN="${DOPPLER_TOKEN}" \
    DOPPLER_API_URL="${MOCK_URL}" \
    DOPPLER_CACHE_TTL="5s" \
    ENABLE_ROTATION="true" \
    ROTATION_INTERVAL="10s" \
    ENABLE_MONITORING="false"
success "Plugin configured with Doppler settings."

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

info "Rotating secret in Doppler mock..."
curl -fsS -X POST "${MOCK_URL}/mock/set-secret" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"${SECRET_KEY}\",\"value\":\"${SECRET_VALUE_ROTATED}\"}"
success "Secret rotated to: ${SECRET_VALUE_ROTATED}"

info "Waiting for plugin rotation interval (15s)..."
sleep 15

info "Logging service output after rotation..."
log_stack "${STACK_NAME}" "app"
assert_no_sensitive_rotation_metadata_logs

info "Verifying rotated secret value..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE_ROTATED}" 180

success "Doppler smoke test PASSED"
