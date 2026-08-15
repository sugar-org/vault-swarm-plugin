#!/usr/bin/env bash
# floci-oci-roundtrip.sh
# Verifies OCI Vault + KMS + Secrets against a running floci-oci emulator
# (https://floci.io/floci-oci/services/kms-vault/). Mirrors floci-kms-roundtrip.sh:
# create vault and AES key, encrypt a value, store it as a JSON field in a vault
# secret, fetch the bundle, decrypt without a keyVersionId (ciphertext envelope
# carries it), rotate the secret, and confirm old ciphertext still decrypts after
# a key-version rotation.

set -euo pipefail

OCI_ENDPOINT="${OCI_ENDPOINT:-http://localhost:4599}"
OCI_TENANCY_OCID="${OCI_TENANCY_OCID:-ocid1.tenancy.oc1..flocilocaltenancy0000000000000000000000000000000000000000}"
RUN_ID="${GITHUB_RUN_ID:-local-$(date +%s)}"
VAULT_NAME="floci-ci-vault-${RUN_ID}"
KEY_NAME="floci-ci-key-${RUN_ID}"
SECRET_NAME="floci-ci-secret-${RUN_ID}"
PLAINTEXT="oci-kms-pass-v1"
PLAINTEXT_ROTATED="oci-kms-pass-v2"

oci_api() {
    curl -sf -H "Content-Type: application/json" "$@"
}

wait_for_state() {
    local url="$1" expected="$2" elapsed=0
    until [[ "$(oci_api "${url}" | jq -r '.lifecycleState // empty')" == "${expected}" ]]; do
        sleep 2
        elapsed=$((elapsed + 2))
        if [[ "${elapsed}" -ge 60 ]]; then
            echo "::error::${url} did not reach ${expected} within 60s" >&2
            exit 1
        fi
    done
}

b64() {
    if [[ $# -gt 0 ]]; then
        printf '%s' "$1" | base64 -w0 2>/dev/null || printf '%s' "$1" | base64 | tr -d '\n'
    else
        base64 -w0 2>/dev/null || base64 | tr -d '\n'
    fi
}

encrypt() {
    jq -nc --arg keyId "${KEY_OCID}" --arg plaintext "$(b64 "$1")" \
        '{keyId:$keyId,plaintext:$plaintext,encryptionAlgorithm:"AES_256_GCM"}' \
        | oci_api -X POST "${OCI_ENDPOINT}/20180608/encrypt" -d @- \
        | jq -r '.ciphertext'
}

decrypt() {
    local ciphertext="$1"
    local plaintext_b64
    plaintext_b64="$(jq -nc --arg keyId "${KEY_OCID}" --arg ciphertext "${ciphertext}" \
        '{keyId:$keyId,ciphertext:$ciphertext}' \
        | oci_api -X POST "${OCI_ENDPOINT}/20180608/decrypt" -d @- \
        | jq -r '.plaintext')"
    printf '%s' "${plaintext_b64}" | base64 -d
}

json_secret() {
    jq -nc --arg password "$1" '{password:$password}' | b64
}

fetch_bundle_by_name() {
    local stage="${1:-}"
    local url="${OCI_ENDPOINT}/20190301/secretbundles/actions/getByName?secretName=${SECRET_NAME}&vaultId=${VAULT_OCID}"
    if [[ -n "${stage}" ]]; then
        url="${url}&stage=${stage}"
    fi
    oci_api -X POST "${url}" | jq -r '.secretBundleContent.content'
}

fetch_bundle_by_id() {
    oci_api "${OCI_ENDPOINT}/20190301/secretbundles/${SECRET_OCID}" \
        | jq -r '.secretBundleContent.content'
}

roundtrip() {
    local label="$1" expected="$2" fetched_b64="$3"
    local ciphertext decrypted
    ciphertext="$(printf '%s' "${fetched_b64}" | base64 -d | jq -r '.password')"
    decrypted="$(decrypt "${ciphertext}")"
    if [[ "${decrypted}" != "${expected}" ]]; then
        echo "::error::${label}: decrypted '${decrypted}', expected '${expected}'" >&2
        return 1
    fi
    echo "${label}: OK"
}

echo "Creating KMS vault ${VAULT_NAME}..."
VAULT_OCID="$(oci_api -X POST "${OCI_ENDPOINT}/20180608/vaults" \
    -d "{\"compartmentId\":\"${OCI_TENANCY_OCID}\",\"displayName\":\"${VAULT_NAME}\",\"vaultType\":\"DEFAULT\"}" \
    | jq -r '.id')"
wait_for_state "${OCI_ENDPOINT}/20180608/vaults/${VAULT_OCID}" "ACTIVE"
echo "Vault: ${VAULT_OCID}"

echo "Creating AES key ${KEY_NAME}..."
KEY_OCID="$(oci_api -X POST "${OCI_ENDPOINT}/20180608/keys" \
    -d "{\"compartmentId\":\"${OCI_TENANCY_OCID}\",\"displayName\":\"${KEY_NAME}\",\"protectionMode\":\"SOFTWARE\",\"keyShape\":{\"algorithm\":\"AES\",\"length\":32}}" \
    | jq -r '.id')"
wait_for_state "${OCI_ENDPOINT}/20180608/keys/${KEY_OCID}" "ENABLED"
echo "Key: ${KEY_OCID}"

echo "Encrypting and storing secret ${SECRET_NAME}..."
SECRET_OCID="$(oci_api -X POST "${OCI_ENDPOINT}/20180608/secrets" \
    -d "{\"compartmentId\":\"${OCI_TENANCY_OCID}\",\"vaultId\":\"${VAULT_OCID}\",\"keyId\":\"${KEY_OCID}\",\"secretName\":\"${SECRET_NAME}\",\"secretContent\":{\"contentType\":\"BASE64\",\"content\":\"$(json_secret "$(encrypt "${PLAINTEXT}")")\"}}" \
    | jq -r '.id')"
echo "Secret: ${SECRET_OCID}"

roundtrip "GetSecretBundleByName" "${PLAINTEXT}" "$(fetch_bundle_by_name)"
roundtrip "GetSecretBundle by OCID" "${PLAINTEXT}" "$(fetch_bundle_by_id)"

echo "Rotating secret value..."
oci_api -X PUT "${OCI_ENDPOINT}/20180608/secrets/${SECRET_OCID}" \
    -d "{\"secretContent\":{\"contentType\":\"BASE64\",\"content\":\"$(json_secret "$(encrypt "${PLAINTEXT_ROTATED}")")\"}}" >/dev/null

roundtrip "rotated CURRENT" "${PLAINTEXT_ROTATED}" "$(fetch_bundle_by_name CURRENT)"
roundtrip "rotated PREVIOUS" "${PLAINTEXT}" "$(fetch_bundle_by_name PREVIOUS)"

echo "Rotating key version (old ciphertext must still decrypt)..."
OLD_CIPHERTEXT="$(printf '%s' "$(fetch_bundle_by_name CURRENT)" | base64 -d | jq -r '.password')"
oci_api -X POST "${OCI_ENDPOINT}/20180608/keys/${KEY_OCID}/keyVersions" -d '{}' >/dev/null
DECRYPTED_AFTER_KEY_ROTATE="$(decrypt "${OLD_CIPHERTEXT}")"
if [[ "${DECRYPTED_AFTER_KEY_ROTATE}" != "${PLAINTEXT_ROTATED}" ]]; then
    echo "::error::post-key-rotation decrypt: '${DECRYPTED_AFTER_KEY_ROTATE}', expected '${PLAINTEXT_ROTATED}'" >&2
    exit 1
fi
echo "key-version rotation: OK"

echo "OCI KMS Vault + Secrets roundtrip PASSED"
