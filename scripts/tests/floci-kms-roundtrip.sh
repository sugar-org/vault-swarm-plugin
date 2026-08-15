#!/usr/bin/env bash
# floci-kms-roundtrip.sh
# Verifies the AWS KMS + Secrets Manager flow the plugin relies on against a
# running Floci emulator (https://github.com/floci-io/floci). Mirrors the E2E
# path in smoke-test-awssm.sh: KMS-encrypt a value, store the base64 ciphertext
# as a JSON field in Secrets Manager, fetch it back, decrypt it with KMS (no
# KeyId, exactly like the plugin's transformer), and verify the plaintext —
# including after a rotation via put-secret-value.

set -euo pipefail

export AWS_REGION="${AWS_REGION:-us-east-1}"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_ENDPOINT_URL="${AWS_ENDPOINT_URL:-http://localhost:4566}"

RUN_ID="${GITHUB_RUN_ID:-local-$(date +%s)}"
SECRET_NAME="floci-ci/database/mysql-${RUN_ID}"
KEY_ALIAS="alias/floci-ci-${RUN_ID}"
PLAINTEXT="awssm-kms-pass-v1"
PLAINTEXT_ROTATED="awssm-kms-pass-v2"

encrypt() {
    aws --no-cli-pager kms encrypt \
        --key-id "${KEY_ALIAS}" \
        --plaintext "$1" \
        --cli-binary-format raw-in-base64-out \
        --query 'CiphertextBlob' --output text
}

fetch_password_field() {
    aws --no-cli-pager secretsmanager get-secret-value \
        --secret-id "${SECRET_NAME}" \
        --query 'SecretString' --output text | jq -r '.password'
}

roundtrip() {
    local label="$1" expected="$2" fetched="$3" blob decrypted
    blob="$(mktemp /tmp/floci-ciphertext.XXXXXX)"
    printf '%s' "${fetched}" | base64 -d > "${blob}"
    decrypted="$(aws --no-cli-pager kms decrypt \
        --ciphertext-blob "fileb://${blob}" \
        --query 'Plaintext' --output text | base64 -d)"
    rm -f "${blob}"
    if [[ "${decrypted}" != "${expected}" ]]; then
        echo "::error::${label}: decrypted '${decrypted}', expected '${expected}'" >&2
        return 1
    fi
    echo "${label}: OK"
}

echo "Creating KMS key and alias..."
KEY_ID="$(aws --no-cli-pager kms create-key \
    --description 'swarm-external-secrets floci CI key' \
    --query 'KeyMetadata.KeyId' --output text)"
aws --no-cli-pager kms create-alias \
    --alias-name "${KEY_ALIAS}" --target-key-id "${KEY_ID}"

echo "Storing KMS-encrypted secret in Secrets Manager..."
aws --no-cli-pager secretsmanager create-secret \
    --name "${SECRET_NAME}" \
    --secret-string "{\"password\":\"$(encrypt "${PLAINTEXT}")\"}"

roundtrip "initial roundtrip" "${PLAINTEXT}" "$(fetch_password_field)"

echo "Rotating secret value..."
aws --no-cli-pager secretsmanager put-secret-value \
    --secret-id "${SECRET_NAME}" \
    --secret-string "{\"password\":\"$(encrypt "${PLAINTEXT_ROTATED}")\"}"

roundtrip "rotated roundtrip" "${PLAINTEXT_ROTATED}" "$(fetch_password_field)"

echo "AWS KMS + Secrets Manager roundtrip PASSED"
