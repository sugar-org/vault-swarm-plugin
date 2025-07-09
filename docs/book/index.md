---
name: Getting Started
---

### Vault Swarm Plugin

A Docker Swarm secrets plugin that integrates with HashiCorp Vault for secure secret management.

## Features

- **Vault Integration**: Retrieve secrets from HashiCorp Vault
- **Multiple Auth Methods**: Support for token and AppRole authentication
- **Automatic Secret Rotation**: Monitor Vault for changes and automatically update Docker secrets and services
- **Flexible Path Mapping**: Customize Vault paths and field extraction
- **Production Ready**: Includes proper error handling, logging, and cleanup

## New: Automatic Secret Rotation

The plugin now automatically monitors secrets in Vault and updates Docker Swarm secrets and services when changes are detected. See [ROTATION.md](ROTATION.md) for detailed documentation.

### Quick Example
```bash
# Enable rotation with 2-minute check interval
docker plugin set vault-secrets-plugin:latest \
    VAULT_ENABLE_ROTATION="true" \
    VAULT_ROTATION_INTERVAL="2m"
```

## Installation

1. Build and enable the plugin:
   ```bash
   ./build.sh
   ```

2. Configure the plugin:
   ```bash
   docker plugin set vault-secrets-plugin:latest \
       VAULT_ADDR="https://your-vault-server:8200" \
       VAULT_AUTH_METHOD="token" \
       VAULT_TOKEN="your-vault-token" \
       VAULT_ENABLE_ROTATION="true"
   ```

3. Use in docker-compose.yml:
   ```yaml
   secrets:
     mysql_password:
       driver: vault-secrets-plugin:latest
       labels:
         vault_path: "database/mysql"
         vault_field: "password"
   ```
start the server
```bash
vault server -dev
```

create a vault role
```bash
vault write auth/approle/role/my-role \
    token_policies="default,web-app" \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=24h \
    secret_id_num_uses=10

```

retrieve the role id 
```
vault read auth/approle/role/my-role/role-id
```
(or) 

for automation
```bash
vault read -format=json auth/approle/role/my-role/role-id \
  | jq -r .data.role_id

```
get the secret id
```bash
vault write -f auth/approle/role/my-role/secret-id

```
login with approle 
```bash
vault write auth/approle/login \
    role_id="192e9220-f35c-c2e9-2931-464696e0ff24" \
    secret_id="4e46a226-fdd5-5ed1-f7bb-7b92a0013cad"
```

write and attach policy for the approle 

```bash
vault policy write db-policy ./db-policy.hcl
```
```bash
vault write auth/approle/role/my-role \
    token_policies="db-policy" 
```

set and get the kv secrets 
```bash
vault kv put secret/database/mysql \
    root_password=admin \
    user_password=admin
```

```bash
vault kv get secret/database/mysql 
```

---
debug the plugin 

```bash
sudo journalctl -u docker.service -f \
  | grep plugin_id
```