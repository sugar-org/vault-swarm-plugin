#!/usr/bin/env bash

set -e
SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(realpath -- "${SCRIPT_DIR}/../..")"

# shellcheck source=smoke-test-helper.sh
source "${SCRIPT_DIR}/smoke-test-helper.sh"

command -v openssl >/dev/null 2>&1 || die "openssl is required for the Vault mTLS smoke test"
command -v jq >/dev/null 2>&1 || die "jq is required for the Vault mTLS smoke test"

# --- mTLS-only helpers (kept in this script, not smoke-test-helper.sh) ---
mtls_plugin_mount_source_dir() {
    if [[ "$(uname -s)" == "Darwin" ]]; then
        echo "${HOME}/.swarm-external-secrets"
    else
        echo "/run/swarm-external-secrets"
    fi
}

mtls_plugin_mount_dest_dir() {
    echo "/run/swarm-external-secrets"
}

mtls_plugin_tls_host_dir() {
    echo "$(mtls_plugin_mount_source_dir)/mtls"
}

mtls_plugin_tls_dir() {
    echo "$(mtls_plugin_mount_dest_dir)/mtls"
}

mtls_write_plugin_config() {
    local output_file="$1"
    local mount_source="${2:-$(mtls_plugin_mount_source_dir)}"

    if [[ "${mount_source}" == "/run/swarm-external-secrets" ]]; then
        cp "${REPO_ROOT}/config.json" "${output_file}"
        return 0
    fi

    awk -v src="${mount_source}" '
        $0 ~ /"source": "\/run\/swarm-external-secrets"/ && !replaced {
            sub(/"source": "\/run\/swarm-external-secrets"/, "\"source\": \"" src "\"")
            replaced = 1
        }
        { print }
    ' "${REPO_ROOT}/config.json" > "${output_file}"
}

generate_vault_mtls_certs() {
    local dest_dir="$1"
    mkdir -p "${dest_dir}"

    openssl genrsa -out "${dest_dir}/ca.key" 4096
    openssl req -x509 -new -nodes \
        -key "${dest_dir}/ca.key" \
        -sha256 -days 1 \
        -out "${dest_dir}/ca.crt" \
        -subj "/CN=Smoke Test CA"

    openssl genrsa -out "${dest_dir}/vault.key" 2048
    openssl req -new \
        -key "${dest_dir}/vault.key" \
        -out "${dest_dir}/vault.csr" \
        -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
    openssl x509 -req \
        -in "${dest_dir}/vault.csr" \
        -CA "${dest_dir}/ca.crt" \
        -CAkey "${dest_dir}/ca.key" \
        -CAcreateserial \
        -out "${dest_dir}/vault.crt" \
        -days 1 \
        -sha256 \
        -copy_extensions copyall

    openssl genrsa -out "${dest_dir}/client.key" 2048
    openssl req -new \
        -key "${dest_dir}/client.key" \
        -out "${dest_dir}/client.csr" \
        -subj "/CN=swarm-external-secrets-plugin"
    openssl x509 -req \
        -in "${dest_dir}/client.csr" \
        -CA "${dest_dir}/ca.crt" \
        -CAkey "${dest_dir}/ca.key" \
        -CAcreateserial \
        -out "${dest_dir}/client.crt" \
        -days 1 \
        -sha256

    chmod 644 "${dest_dir}/ca.crt" "${dest_dir}/vault.crt" "${dest_dir}/vault.key" \
        "${dest_dir}/client.crt" "${dest_dir}/client.key"
}

install_plugin_mtls_certs() {
    local cert_dir="$1"
    local plugin_cert_dir="${2:-$(mtls_plugin_tls_host_dir)}"
    local state_dir
    state_dir="$(mtls_plugin_mount_source_dir)"

    if [[ -d "${state_dir}" && ! -w "${state_dir}" ]]; then
        die "Plugin state dir ${state_dir} is not writable. Remove it and retry."
    fi

    mkdir -p "${plugin_cert_dir}"

    if [[ "$(uname -s)" == "Darwin" ]]; then
        /bin/cp -f "${cert_dir}/ca.crt" "${cert_dir}/client.crt" "${cert_dir}/client.key" \
            "${plugin_cert_dir}/"
    elif command -v sudo >/dev/null 2>&1; then
        sudo mkdir -p "${plugin_cert_dir}"
        sudo /bin/cp -f "${cert_dir}/ca.crt" "${cert_dir}/client.crt" "${cert_dir}/client.key" \
            "${plugin_cert_dir}/"
        sudo chmod 644 "${plugin_cert_dir}/ca.crt" "${plugin_cert_dir}/client.crt" \
            "${plugin_cert_dir}/client.key"
        return 0
    else
        /bin/cp -f "${cert_dir}/ca.crt" "${cert_dir}/client.crt" "${cert_dir}/client.key" \
            "${plugin_cert_dir}/"
    fi

    chmod 644 "${plugin_cert_dir}/ca.crt" "${plugin_cert_dir}/client.crt" \
        "${plugin_cert_dir}/client.key"
}

# Save the full cert set for manual Vault restarts (includes vault.crt/vault.key).
persist_mtls_cert_bundle() {
    local cert_dir="$1"
    local bundle_dir
    bundle_dir="$(mtls_plugin_mount_source_dir)/bundle"

    mkdir -p "${bundle_dir}"
    /bin/cp -f "${cert_dir}/ca.crt" "${cert_dir}/ca.key" \
        "${cert_dir}/vault.crt" "${cert_dir}/vault.key" \
        "${cert_dir}/client.crt" "${cert_dir}/client.key" \
        "${bundle_dir}/"
    chmod 644 "${bundle_dir}/ca.crt" "${bundle_dir}/vault.crt" \
        "${bundle_dir}/client.crt"
    chmod 600 "${bundle_dir}/ca.key" "${bundle_dir}/vault.key" \
        "${bundle_dir}/client.key" 2>/dev/null || true
}

remove_plugin_mtls_certs() {
    local state_dir
    state_dir="$(mtls_plugin_mount_source_dir)"

    if [[ "$(uname -s)" == "Darwin" ]]; then
        rm -rf "${state_dir}/mtls" "${state_dir}/bundle" 2>/dev/null || true
        return 0
    fi

    if command -v sudo >/dev/null 2>&1; then
        sudo rm -rf "${state_dir}/mtls" "${state_dir}/bundle" 2>/dev/null || true
    else
        rm -rf "${state_dir}/mtls" "${state_dir}/bundle" 2>/dev/null || true
    fi
}

build_plugin_mtls() {
    if docker plugin inspect "${PLUGIN_NAME}" &>/dev/null; then
        docker plugin disable "${PLUGIN_NAME}" --force 2>/dev/null || true
        docker plugin rm "${PLUGIN_NAME}" --force 2>/dev/null || true
    fi

    docker build -f "${REPO_ROOT}/Dockerfile" -t swarm-external-secrets:temp "${REPO_ROOT}"
    mkdir -p "${REPO_ROOT}/plugin/rootfs"

    if docker ps -a --format '{{.Names}}' | grep -q '^temp-container$'; then
        docker rm -f temp-container || true
    fi

    docker create --name temp-container swarm-external-secrets:temp
    docker export temp-container | tar -x -C "${REPO_ROOT}/plugin/rootfs"
    docker rm temp-container
    docker rmi swarm-external-secrets:temp

    mkdir -p "${REPO_ROOT}/plugin"
    mtls_write_plugin_config "${REPO_ROOT}/plugin/config.json"
    docker plugin create "${PLUGIN_NAME}" "${REPO_ROOT}/plugin"
    rm -rf "${REPO_ROOT}/plugin"

    success "Plugin built: ${PLUGIN_NAME}"
}

# --- test configuration ---
VAULT_IMAGE="hashicorp/vault:1.19"
VAULT_CONTAINER="smoke-vault-mtls"
VAULT_ADDR="https://127.0.0.1:8200"
VAULT_TLS_DIR="/vault/tls"
PLUGIN_TLS_DIR="$(mtls_plugin_tls_dir)"
STACK_NAME="smoke-vault-mtls"
SECRET_NAME="smoke_secret"
SECRET_PATH="database/mysql"
SECRET_FIELD="password"
SECRET_VALUE="vault-smoke-pass-v1"
SECRET_VALUE_ROTATED="vault-smoke-pass-v2"
COMPOSE_FILE="${SCRIPT_DIR}/smoke-vault-compose.yml"
POLICY_FILE="${REPO_ROOT}/vault_conf/admin.hcl"
VAULT_CONFIG_FILE="${REPO_ROOT}/vault_conf/smoke-mtls.hcl"
CERT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/vault-mtls-certs.XXXXXX")"
EXIT_CODE=0

vault_mtls_exec() {
    docker exec \
        -e VAULT_ADDR="${VAULT_ADDR}" \
        -e VAULT_CACERT="${VAULT_TLS_DIR}/ca.crt" \
        -e VAULT_CLIENT_CERT="${VAULT_TLS_DIR}/client.crt" \
        -e VAULT_CLIENT_KEY="${VAULT_TLS_DIR}/client.key" \
        "${VAULT_CONTAINER}" "$@"
}

wait_for_vault_api() {
    local elapsed=0
    local status_output=""

    while [ "${elapsed}" -lt 30 ]; do
        status_output="$(vault_mtls_exec vault status 2>&1 || true)"
        if echo "${status_output}" | grep -qiE 'initialized|sealed'; then
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done

    die "Vault did not become reachable within 30s."
}

wait_for_vault_unsealed() {
    local root_token="$1"
    local elapsed=0

    while [ "${elapsed}" -lt 30 ]; do
        if vault_mtls_exec env VAULT_TOKEN="${root_token}" vault status -format=json \
            | jq -e '.sealed == false' >/dev/null; then
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done

    die "Vault did not unseal within 30s."
}

cleanup() {
    echo -e "${RED}Running Vault mTLS smoke test cleanup...${DEF}"
    remove_stack "${STACK_NAME}"
    docker secret rm "${SECRET_NAME}" 2>/dev/null || true
    docker stop "${VAULT_CONTAINER}" 2>/dev/null || true
    docker rm "${VAULT_CONTAINER}" 2>/dev/null || true
    remove_plugin
    remove_plugin_mtls_certs
    rm -rf "${CERT_DIR}"
    exit "${EXIT_CODE}"
}
trap cleanup EXIT

info "Generating temporary mTLS certificates with OpenSSL..."
generate_vault_mtls_certs "${CERT_DIR}" 2>/dev/null
persist_mtls_cert_bundle "${CERT_DIR}"
install_plugin_mtls_certs "${CERT_DIR}"
success "Vault server certs: $(mtls_plugin_mount_source_dir)/bundle | Plugin client certs: $(mtls_plugin_tls_host_dir)"

info "Starting HashiCorp Vault ${VAULT_IMAGE} with HTTPS and required client certificates..."
docker run -d \
    --name "${VAULT_CONTAINER}" \
    --entrypoint vault \
    --cap-add=IPC_LOCK \
    -p 8200:8200 \
    -v "${CERT_DIR}:${VAULT_TLS_DIR}:ro" \
    -v "${VAULT_CONFIG_FILE}:/vault/config/vault.hcl:ro" \
    "${VAULT_IMAGE}" server -config=/vault/config/vault.hcl

info "Waiting for Vault API to become reachable..."
wait_for_vault_api

info "Initializing and unsealing Vault..."
init_output="$(vault_mtls_exec vault operator init -key-shares=1 -key-threshold=1 -format=json)"
VAULT_UNSEAL_KEY="$(echo "${init_output}" | jq -r '.unseal_keys_b64[0]')"
VAULT_ROOT_TOKEN="$(echo "${init_output}" | jq -r '.root_token')"
vault_mtls_exec vault operator unseal "${VAULT_UNSEAL_KEY}" >/dev/null
wait_for_vault_unsealed "${VAULT_ROOT_TOKEN}"
success "Vault is initialized, unsealed, and serving HTTPS with mTLS."

info "Enabling KV v2 engine at mount path 'secret'..."
vault_mtls_exec env VAULT_TOKEN="${VAULT_ROOT_TOKEN}" \
    vault secrets enable -version=2 -path=secret kv
success "KV v2 engine enabled."

info "Applying policy to Vault..."
docker cp "${POLICY_FILE}" "${VAULT_CONTAINER}:/tmp/admin.hcl"
vault_mtls_exec env VAULT_TOKEN="${VAULT_ROOT_TOKEN}" \
    vault policy write smoke-policy /tmp/admin.hcl
success "Policy applied."

info "Writing test secret to Vault..."
vault_mtls_exec env VAULT_TOKEN="${VAULT_ROOT_TOKEN}" \
    vault kv put \
    "secret/${SECRET_PATH}" \
    "${SECRET_FIELD}=${SECRET_VALUE}"
success "Secret written: secret/${SECRET_PATH} ${SECRET_FIELD}=<redacted>"

info "Creating scoped Vault token..."
VAULT_TOKEN="$(vault_mtls_exec env VAULT_TOKEN="${VAULT_ROOT_TOKEN}" \
    vault token create \
        -policy="smoke-policy" \
        -field=token)"
success "Got auth token for plugin."

info "Building plugin and configuring Vault mTLS transport..."
build_plugin_mtls

docker plugin set "${PLUGIN_NAME}" \
    SECRETS_PROVIDER="vault" \
    VAULT_ADDR="${VAULT_ADDR}" \
    VAULT_AUTH_METHOD="token" \
    VAULT_TOKEN="${VAULT_TOKEN}" \
    VAULT_MOUNT_PATH="secret" \
    VAULT_CACERT="${PLUGIN_TLS_DIR}/ca.crt" \
    VAULT_CLIENT_CERT="${PLUGIN_TLS_DIR}/client.crt" \
    VAULT_CLIENT_KEY="${PLUGIN_TLS_DIR}/client.key" \
    ENABLE_ROTATION="true" \
    ROTATION_INTERVAL="10s" \
    VAULT_SKIP_VERIFY="false" \
    ENABLE_MONITORING="false"
success "Plugin configured for Vault mTLS."

info "Enabling plugin..."
enable_plugin

info "Deploying swarm stack..."
deploy_stack "${COMPOSE_FILE}" "${STACK_NAME}" 60

info "Logging service output..."
sleep 10
log_stack "${STACK_NAME}" "app"
assert_no_sensitive_rotation_metadata_logs

info "Verifying secret value matches expected password over mTLS..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE}" 60

info "Capturing running container ID before rotation..."
APP_CONTAINER_ID=$(get_running_container_id "${STACK_NAME}" "app")
success "Container to watch: ${APP_CONTAINER_ID:0:12}"

info "Rotating secret in Vault..."
vault_mtls_exec env VAULT_TOKEN="${VAULT_ROOT_TOKEN}" \
    vault kv put \
    "secret/${SECRET_PATH}" \
    "${SECRET_FIELD}=${SECRET_VALUE_ROTATED}"
success "Secret rotated."

info "Waiting for plugin rotation interval (15s)..."
sleep 15

info "Waiting for service to pick up rotated secret (10s)..."
sleep 10
assert_no_sensitive_rotation_metadata_logs

info "Logging service output after rotation..."
log_stack "${STACK_NAME}" "app"

info "Verifying rotated secret value over mTLS (up to 180s)..."
verify_secret "${STACK_NAME}" "app" "${SECRET_NAME}" "${SECRET_VALUE_ROTATED}" 180

success "Vault mTLS smoke test PASSED (secret retrieval and rotation over mTLS)"
