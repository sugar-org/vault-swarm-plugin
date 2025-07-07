#!/bin/bash

set -e  # Exit on any error

RED='\033[0;31m'
BLU='\e[34m'
GRN='\e[32m'
DEF='\e[0m'

echo -e "${RED}Remove existing plugin if it exists${DEF}"
docker plugin disable sanjay7178/vault-secrets-plugin:latest --force 2>/dev/null || true
docker plugin rm sanjay7178/vault-secrets-plugin:latest --force 2>/dev/null || true

echo -e "${RED}Build the plugin${DEF}"
docker build -t vault-secrets-plugin:temp .

echo -e "${RED}Create plugin rootfs${DEF}"
mkdir -p ./plugin/rootfs
docker create --name temp-container vault-secrets-plugin:temp
docker export temp-container | tar -x -C ./plugin/rootfs
docker rm temp-container
docker rmi vault-secrets-plugin:temp

echo -e "${RED}Copy config to plugin directory${DEF}"
cp config.json ./plugin/

echo -e "${RED}Create the plugin${DEF}"
docker plugin create sanjay7178/vault-secrets-plugin:latest ./plugin

echo -e "${RED}Clean up plugin directory${DEF}"
rm -rf ./plugin

# Use docker plugin push, not docker push
echo -e "${RED}Pushing plugin to registry${DEF}"
if docker plugin push sanjay7178/vault-secrets-plugin:latest; then
    echo -e "${GRN}Successfully pushed plugin to Docker Hub${DEF}"
else
    echo -e "${RED}Failed to push plugin. Make sure you're logged in with 'docker login'${DEF}"
    echo "Run: docker login -u sanjay7178"
    exit 1
fi

echo -e "${GRN}Plugin build, enable, and push completed successfully${DEF}"
echo -e "You can now use this plugin with: docker plugin install sanjay7178/vault-secrets-plugin:latest"


# Important: Enable the plugin before pushing
echo -e "${RED}Enable the plugin${DEF}"
docker plugin enable sanjay7178/vault-secrets-plugin:latest

# Set privileges if needed
echo -e "${RED}Setting plugin permissions${DEF}"
docker plugin set sanjay7178/vault-secrets-plugin:latest gid=0 uid=0 || echo "Skipping permission setting (plugin may already be enabled)"