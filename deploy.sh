#!/bin/bash

RED='\033[0;31m'
BLU='\e[34m'
GRN='\e[32m'
DEF='\e[0m'

echo -e ${RED}Remove existing plugin if it exists and stop
docker plugin disable vault-secrets-plugin:latest --force 2>/dev/null || true
docker plugin rm vault-secrets-plugin:latest --force 2>/dev/null || true

echo -e ${RED}Build the plugin
docker build -t vault-secrets-plugin:temp .

echo -e ${RED}Create plugin rootfs
mkdir -p ./plugin/rootfs
docker create --name temp-container vault-secrets-plugin:temp
docker export temp-container | tar -x -C ./plugin/rootfs
docker rm temp-container
docker rmi vault-secrets-plugin:temp

echo -e ${RED}Copy config to plugin directory
cp config.json ./plugin/

go run plugin_installer/installer.go

echo -e ${RED}Create the plugin
docker plugin create vault-secrets-plugin:latest ./plugin

echo -e ${RED}Clean up plugin directory
rm -rf ./plugin

echo -e ${RED}Enable the plugin
docker plugin enable vault-secrets-plugin:latest


# echo -e ${RED}Set plugin configuration
docker plugin set vault-secrets-plugin:latest \
    VAULT_ADDR="https://152.53.244.80:8200" \
    VAULT_AUTH_METHOD="approle" \
    VAULT_ROLE_ID="8ff294a6-9d5c-c5bb-b494-bc0bfe02a97e" \
    VAULT_SECRET_ID="aedde801-0616-18a5-a62d-c6d7eb483cff" \
    VAULT_MOUNT_PATH="secret"

export VAULT_ROLE_ID="8ff294a6-9d5c-c5bb-b494-bc0bfe02a97e"
export VAULT_SECRET_ID="aedde801-0616-18a5-a62d-c6d7eb483cff"

# echo -e ${RED}Enable the plugin compose service
# docker compose up -d  vault-secrets-plugin

echo -e ${RED}Verify the plugin is enabled
docker plugin ls

echo -e ${RED}Create secrets in Vault first before deploying
echo "Please ensure the following secrets exist in Vault:"
echo "- secret/database/mysql (with root_password and user_password fields)"
# echo "- secret/application/api (with key field)"

echo -e ${RED}Deploy the stack
docker stack deploy -c docker-compose.yml myapp

echo -e ${RED}Verify the deployment
docker stack services myapp