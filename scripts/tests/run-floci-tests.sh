#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(realpath -- "${SCRIPT_DIR}/../..")"

FLOCI_IMAGE="floci/floci:1.6.0@sha256:eab36252ea43a4a73928423f0372219052c5c6f87207f6c4754db14b91d6ed30"
FLOCI_CONTAINER="floci-go-tests"
HEALTH_URL="http://localhost:4566/_localstack/health"

started=0

cleanup() {
    if [[ "${started}" = "1" ]]; then
        docker rm -f "${FLOCI_CONTAINER}" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

if curl -sf "${HEALTH_URL}" >/dev/null 2>&1; then
    echo "Floci already running on 4566, reusing it."
else
    echo "Starting Floci emulator..."
    docker run -d --name "${FLOCI_CONTAINER}" -p 4566:4566 "${FLOCI_IMAGE}" >/dev/null
    started=1
    elapsed=0
    until curl -sf "${HEALTH_URL}" >/dev/null 2>&1; do
        sleep 2
        elapsed=$((elapsed + 2))
        if [[ "${elapsed}" -ge 30 ]]; then
            echo "Floci did not become healthy within 30s" >&2
            docker logs "${FLOCI_CONTAINER}" || true
            exit 1
        fi
    done
fi

echo "Floci is ready."

export AWS_REGION="${AWS_REGION:-us-east-1}"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_ENDPOINT_URL="${AWS_ENDPOINT_URL:-http://localhost:4566}"
export AWS_KMS_ENDPOINT="${AWS_KMS_ENDPOINT:-http://localhost:4566}"

cd "${REPO_ROOT}"
go test ./providers/... ./internal/secrettransform/... -run Floci -count=1 -v
