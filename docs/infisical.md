# Infisical

This document describes how to use [Infisical](https://infisical.com) as a first-class secrets provider with Swarm External Secrets.

## Overview

The Infisical provider fetches secret values from an Infisical project/environment (and optional folder path) using either:

1. **Universal Auth** (recommended for production) — machine identity `Client ID` + `Client Secret`
2. **Bearer access token** — a pre-issued Infisical access token (`INFISICAL_TOKEN`)

When a Docker service requests a secret, the plugin calls Infisical's Secrets API (`GET /api/v4/secrets/{secretName}`) and returns the plaintext value to Swarm. With rotation enabled, the plugin periodically re-reads the secret and cutovers Swarm secret versions when the value changes.

## Configuration

| Variable | Description | Default |
|---|---|---|
| `INFISICAL_CLIENT_ID` | Machine identity Client ID (Universal Auth) | — |
| `INFISICAL_CLIENT_SECRET` | Machine identity Client Secret (Universal Auth) | — |
| `INFISICAL_TOKEN` | Pre-issued bearer/access token (optional alternative to Universal Auth) | — |
| `INFISICAL_PROJECT_ID` | Infisical project ID (**required**) | — |
| `INFISICAL_ENVIRONMENT` | Environment slug (`dev`, `staging`, `prod`, …) | `dev` |
| `INFISICAL_SECRET_PATH` | Default folder path for secrets | `/` |
| `INFISICAL_SITE_URL` | Infisical site/API base URL | `https://app.infisical.com` |

You must set either `INFISICAL_TOKEN` **or** both `INFISICAL_CLIENT_ID` and `INFISICAL_CLIENT_SECRET`.

### Site URL

Choose the correct base URL for your deployment:

- Infisical Cloud US: `https://app.infisical.com` (also `https://us.infisical.com`)
- Infisical Cloud EU: `https://eu.infisical.com`
- Self-hosted: your Infisical origin (for example `https://infisical.example.com`)

### Example (Universal Auth)

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="infisical" \
    INFISICAL_CLIENT_ID="..." \
    INFISICAL_CLIENT_SECRET="..." \
    INFISICAL_PROJECT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
    INFISICAL_ENVIRONMENT="prod" \
    INFISICAL_SECRET_PATH="/" \
    ENABLE_ROTATION="true" \
    ROTATION_INTERVAL="30s"
```

### Example (access token)

```bash
docker plugin set swarm-external-secrets:latest \
    SECRETS_PROVIDER="infisical" \
    INFISICAL_TOKEN="eyJ..." \
    INFISICAL_PROJECT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
    INFISICAL_ENVIRONMENT="dev"
```

## Secret labels

| Label | Description |
|---|---|
| `infisical_secret_name` | Infisical secret key (e.g. `MYSQL_PASSWORD`) |
| `infisical_field` | Optional JSON field to extract when the Infisical value is a JSON object |
| `infisical_project_id` | Optional per-secret project override |
| `infisical_environment` | Optional per-secret environment override |
| `infisical_secret_path` | Optional per-secret folder path override |

If `infisical_secret_name` is omitted, the Docker secret name is uppercased (`mysql_password` → `MYSQL_PASSWORD`).

### Compose example

```yaml
version: "3.8"

services:
  api:
    image: myorg/api:latest
    secrets:
      - mysql_password
    deploy:
      replicas: 1

secrets:
  mysql_password:
    driver: swarm-external-secrets:latest
    labels:
      infisical_secret_name: "MYSQL_PASSWORD"
      # Optional overrides:
      # infisical_environment: "prod"
      # infisical_secret_path: "/database"
```

## Machine identity setup

1. In Infisical, create a **Machine Identity** and enable **Universal Auth**.
2. Generate a Client Secret for the identity.
3. Add the identity to your project with a role that can read the secrets you need.
4. Copy the Client ID, Client Secret, and Project ID into the plugin settings above.

See Infisical's [Universal Auth](https://infisical.com/docs/documentation/platform/identities/universal-auth) docs for details.

## Rotation

Rotation uses the same poll-based path as other providers:

1. On first `Get`, the plugin tracks the secret hash.
2. Every `ROTATION_INTERVAL`, it re-fetches from Infisical.
3. On change, it creates a new Swarm secret version and updates referencing services.

Universal Auth access tokens are cached in-process and refreshed before expiry (and retried once on HTTP 401).

## Implementation notes

- Uses the Infisical REST API directly (no SDK dependency).
- Login: `POST /api/v1/auth/universal-auth/login`
- Read: `GET /api/v4/secrets/{secretName}?projectId=...&environment=...&secretPath=...`
- Secret path encoding for tracking: `{projectID}/{environment}[/{folders...}]/{secretName}`
