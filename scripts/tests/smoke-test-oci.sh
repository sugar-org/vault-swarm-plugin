#!/usr/bin/env bash

set -ex
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="${GITHUB_WORKSPACE:-$(realpath -- "${SCRIPT_DIR}/../..")}"
# shellcheck source=smoke-test-helper.sh
source "${SCRIPT_DIR}/smoke-test-helper.sh"

# floci-oci is a lightweight open-source OCI emulator (https://floci.io/floci-oci/).
# Vault, KMS, and Secrets share port 4599. Signatures are parsed for tenancy
# context but never verified, so a throwaway RSA key is enough for the plugin.
FLOCI_CONTAINER="smoke-floci-oci"
FLOCI_IMAGE="floci/floci-oci:latest"
OCI_ENDPOINT="${OCI_ENDPOINT:-http://localhost:4599}"
OCI_REGION="${OCI_REGION:-us-ashburn-1}"
OCI_TENANCY_OCID="${OCI_TENANCY_OCID:-ocid1.tenancy.oc1..flocilocaltenancy0000000000000000000000000000000000000000}"
OCI_USER_OCID="${OCI_USER_OCID:-ocid1.user.oc1..flocilocaluser0000000000000000000000000000000000000000000000}"
OCI_FINGERPRINT="${OCI_FINGERPRINT:-aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99}"
OCI_AUTH_METHOD="${OCI_AUTH_METHOD:-api_key}"
RUN_ID="${GITHUB_RUN_ID:-local-$(date +%s)}"
STACK_NAME="smoke-oci"
SECRET_NAME="smoke_secret"
SECRET_PATH="smoke-test-secret-${RUN_ID}"
SECRET_FIELD="password"
SECRET_VALUE="oci-smoke-pass-v1"
SECRET_VALUE_ROTATED="oci-smoke-pass-v2"
VAULT_NAME="smoke-vault-${RUN_ID}"
KEY_NAME="smoke-key-${RUN_ID}"
COMPOSE_FILE="${SCRIPT_DIR}/smoke-oci-compose.yml"
KEY_FILE="$(mktemp /tmp/floci-oci-key.XXXXXX.pem)"

export OCI_SMOKE_SECRET_NAME="${SECRET_PATH}"

oci_api() {
    curl -sf \
        -H "Content-Type: application/json" \
        "$@"
}

json_payload() {
    local value="$1"
    printf '{"%s":"%s"}' "${SECRET_FIELD}" "${value}" | base64 -w0 2>/dev/null \
        || printf '{"%s":"%s"}' "${SECRET_FIELD}" "${value}" | base64 | tr -d '\n'
}

wait_for_field() {
    local url="$1"
    local expected="$2"
    local elapsed=0
    until [[ "$(oci_api "${url}" | jq -r '.lifecycleState // empty')" == "${expected}" ]]; do
        sleep 2
        elapsed=$((elapsed + 2))
        [[ "${elapsed}" -lt 60 ]] || die "Resource at ${url} did not reach ${expected} within 60s."
    done
}

cleanup() {
    echo -e "${RED}Running OCI Vault smoke test cleanup...${DEF}"
    remove_stack "${STACK_NAME}"
    docker secret rm "${SECRET_NAME}" 2>/dev/null || true
    if [[ -n "${FLOCI_CONTAINER}" ]]; then
        echo -e "${RED}floci-oci logs:${DEF}"
        docker logs "${FLOCI_CONTAINER}" 2>/dev/null || true
        docker stop "${FLOCI_CONTAINER}" 2>/dev/null || true
        docker rm   "${FLOCI_CONTAINER}" 2>/dev/null || true
    fi
    rm -f "${KEY_FILE}"
    remove_plugin
}
trap cleanup EXIT

command -v curl >/dev/null 2>&1 || die "curl is required to run the OCI Vault smoke test."
command -v jq >/dev/null 2>&1 || die "jq is required to run the OCI Vault smoke test."
command -v openssl >/dev/null 2>&1 || die "openssl is required to generate a throwaway OCI API key."

if curl -sf "${OCI_ENDPOINT}/_floci-oci/health" >/dev/null 2>&1; then
    info "OCI emulator already running on 4599, skipping container start."
    FLOCI_CONTAINER=""
else
    info "Starting floci-oci emulator container..."
    docker run -d \
        --name "${FLOCI_CONTAINER}" \
        -p 4599:4599 \
        "${FLOCI_IMAGE}"
fi

info "Waiting for floci-oci to be ready..."
elapsed=0
until curl -sf "${OCI_ENDPOINT}/_floci-oci/health" >/dev/null 2>&1; do
    sleep 2
    elapsed=$((elapsed + 2))
    [[ "${elapsed}" -lt 60 ]] || die "floci-oci did not become ready within 60s."
done
success "floci-oci is ready."

info "Creating vault ${VAULT_NAME}..."
VAULT_OCID="$(oci_api -X POST "${OCI_ENDPOINT}/20180608/vaults" \
    -d "{\"compartmentId\":\"${OCI_TENANCY_OCID}\",\"displayName\":\"${VAULT_NAME}\",\"vaultType\":\"DEFAULT\"}" \
    | jq -r '.id')"
[[ -n "${VAULT_OCID}" && "${VAULT_OCID}" != "null" ]] || die "Failed to create vault."
wait_for_field "${OCI_ENDPOINT}/20180608/vaults/${VAULT_OCID}" "ACTIVE"
success "Vault created: ${VAULT_OCID}"

info "Creating AES master key ${KEY_NAME}..."
KEY_OCID="$(oci_api -X POST "${OCI_ENDPOINT}/20180608/keys" \
    -d "{\"compartmentId\":\"${OCI_TENANCY_OCID}\",\"displayName\":\"${KEY_NAME}\",\"protectionMode\":\"SOFTWARE\",\"keyShape\":{\"algorithm\":\"AES\",\"length\":32}}" \
    | jq -r '.id')"
[[ -n "${KEY_OCID}" && "${KEY_OCID}" != "null" ]] || die "Failed to create key."
wait_for_field "${OCI_ENDPOINT}/20180608/keys/${KEY_OCID}" "ENABLED"
success "Key created: ${KEY_OCID}"

info "Creating secret ${SECRET_PATH}..."
SECRET_OCID="$(oci_api -X POST "${OCI_ENDPOINT}/20180608/secrets" \
    -d "{\"compartmentId\":\"${OCI_TENANCY_OCID}\",\"vaultId\":\"${VAULT_OCID}\",\"keyId\":\"${KEY_OCID}\",\"secretName\":\"${SECRET_PATH}\",\"secretContent\":{\"contentType\":\"BASE64\",\"content\":\"$(json_payload "${SECRET_VALUE}")\"}}" \
    | jq -r '.id')"
[[ -n "${SECRET_OCID}" && "${SECRET_OCID}" != "null" ]] || die "Failed to create secret."
success "Secret written: ${SECRET_PATH}"

info "Verifying secret bundle by name (no plugin)..."
BUNDLE_B64="$(oci_api -X POST \
    "${OCI_ENDPOINT}/20190301/secretbundles/actions/getByName?secretName=${SECRET_PATH}&vaultId=${VAULT_OCID}" \
    | jq -r '.secretBundleContent.content')"
ACTUAL_FIELD="$(printf '%s' "${BUNDLE_B64}" | base64 -d | jq -r --arg f "${SECRET_FIELD}" '.[$f]')"
[[ "${ACTUAL_FIELD}" == "${SECRET_VALUE}" ]] || die "Bundle roundtrip expected ${SECRET_VALUE}, got ${ACTUAL_FIELD}"
success "Secret bundle roundtrip OK."

info "Generating throwaway OCI API key..."
openssl genrsa -out "${KEY_FILE}" 2048 >/dev/null 2>&1
OCI_KEY="$(base64 -w0 "${KEY_FILE}" 2>/dev/null || base64 "${KEY_FILE}" | tr -d '\n')"

info "Building plugin and setting OCI Vault config..."
build_plugin
docker plugin disable "${PLUGIN_NAME}" --force 2>/dev/null || true
docker plugin set "${PLUGIN_NAME}" \
    SECRETS_PROVIDER="oci" \
    OCI_AUTH_METHOD="${OCI_AUTH_METHOD}" \
    OCI_REGION="${OCI_REGION}" \
    OCI_TENANCY_OCID="${OCI_TENANCY_OCID}" \
    OCI_USER_OCID="${OCI_USER_OCID}" \
    OCI_FINGERPRINT="${OCI_FINGERPRINT}" \
    OCI_PRIVATE_KEY="${OCI_KEY}" \
    OCI_VAULT_OCID="${VAULT_OCID}" \
    OCI_ENDPOINT="${OCI_ENDPOINT}" \
    ENABLE_ROTATION="true" \
    ROTATION_INTERVAL="10s" \
    ENABLE_MONITORING="false"

success "Plugin configured with OCI Vault settings."

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

info "Rotating secret in OCI Vault..."
oci_api -X PUT "${OCI_ENDPOINT}/20180608/secrets/${SECRET_OCID}" \
    -d "{\"secretContent\":{\"contentType\":\"BASE64\",\"content\":\"$(json_payload "${SECRET_VALUE_ROTATED}")\"}}" >/dev/null
success "Secret rotated to: ${SECRET_VALUE_ROTATED}"

info "Waiting for plugin rotation interval..."
sleep 30
assert_no_sensitive_rotation_metadata_logs

info "Logging service output after rotation..."
log_stack "${STACK_NAME}" "app"

info "Verifying rotated secret value..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE_ROTATED}" 180

success "OCI Vault smoke test PASSED"
