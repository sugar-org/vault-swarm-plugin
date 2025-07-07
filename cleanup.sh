#!/bin/bash

# Cleanup script for the Vault Secrets Plugin
docker plugin disable vault-secrets-plugin:latest --force 2>/dev/null || true
docker plugin rm vault-secrets-plugin:latest --force 2>/dev/null || true    
docker swarm leave --force 2>/dev/null || true
docker swarm init --force 2>/dev/null || true