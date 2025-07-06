#!/bin/bash

RED='\033[0;31m'
BLU='\e[34m'
GRN='\e[32m'
DEF='\e[0m'

echo -e ${RED}Remove existing plugin if it exists
docker plugin rm vault-secrets-plugin:latest --force 2>/dev/null || true

echo -e ${RED}Build the plugin
docker build -t vault-secrets-plugin:temp .

echo -e ${RED}Create plugin from image
docker create --name temp-container vault-secrets-plugin:temp
docker export temp-container | docker import - vault-secrets-plugin:rootfs
docker rm temp-container
docker rmi vault-secrets-plugin:temp

echo -e ${RED}Create the plugin
docker plugin create vault-secrets-plugin:latest .

echo -e ${RED}Enable the plugin
docker plugin enable vault-secrets-plugin:latest

echo -e ${RED}Set environment variables
export VAULT_ROLE_ID="192e9220-f35c-c2e9-2931-464696e0ff24"
export VAULT_SECRET_ID="fdb1fed7-a843-55ce-d7e2-22b03da31dfb"

echo -e ${RED}Deploy the stack
docker stack deploy -c docker-compose.yml myapp

echo -e ${RED}Verify the deployment
docker stack services myapp
docker service logs myapp_vault-secrets-plugin 2>/dev/null || echo "Service logs not available yet"