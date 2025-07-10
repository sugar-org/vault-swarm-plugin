#!/bin/bash

# Vault Swarm Plugin Multi-Provider Demo Script
# This script demonstrates the new multi-provider functionality

echo "🔐 Vault Swarm Plugin Multi-Provider Demo"
echo "=========================================="

# Build the plugin
echo "📦 Building plugin..."
go build -o vault-swarm-plugin .

# Show supported providers
echo ""
echo "🌐 Supported Providers:"
echo "- HashiCorp Vault (vault)"
echo "- AWS Secrets Manager (aws)"  
echo "- Azure Key Vault (azure)"
echo "- OpenBao (openbao)"
echo "- GCP Secret Manager (gcp) [placeholder]"

# Show provider information
echo ""
echo "ℹ️  Provider Information:"
echo ""

# Test provider factory
echo "Testing provider factory..."
./vault-swarm-plugin -version 2>/dev/null || echo "Plugin binary ready"

# Show monitoring capabilities
echo ""
echo "📊 Monitoring Features:"
echo "- Real-time system metrics"
echo "- Web dashboard at configurable port"
echo "- Prometheus-compatible metrics"
echo "- Health checks and error tracking"
echo "- Goroutine and memory monitoring"

# Example configurations
echo ""
echo "🔧 Example Configurations:"
echo ""

echo "HashiCorp Vault:"
cat << 'EOF'
docker plugin set vault-secrets-plugin:latest \
    SECRETS_PROVIDER="vault" \
    VAULT_ADDR="https://vault.example.com:8200" \
    VAULT_TOKEN="hvs.example-token"
EOF

echo ""
echo "AWS Secrets Manager:"
cat << 'EOF'
docker plugin set vault-secrets-plugin:latest \
    SECRETS_PROVIDER="aws" \
    AWS_REGION="us-west-2" \
    AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
EOF

echo ""
echo "Azure Key Vault:"
cat << 'EOF'
docker plugin set vault-secrets-plugin:latest \
    SECRETS_PROVIDER="azure" \
    AZURE_VAULT_URL="https://myvault.vault.azure.net/"
EOF

echo ""
echo "OpenBao:"
cat << 'EOF'
docker plugin set vault-secrets-plugin:latest \
    SECRETS_PROVIDER="openbao" \
    OPENBAO_ADDR="https://openbao.example.com:8200"
EOF

# Example docker-compose
echo ""
echo "📋 Docker Compose Example:"
cat << 'EOF'
version: '3.8'
services:
  app:
    image: nginx
    secrets:
      - api_key
    deploy:
      replicas: 2

secrets:
  api_key:
    driver: vault-secrets-plugin:latest
    labels:
      # For Vault
      vault_path: "app/secrets"
      vault_field: "api_key"
      
      # For AWS  
      # aws_secret_name: "prod/api/key"
      # aws_field: "api_key"
      
      # For Azure
      # azure_secret_name: "api-key-secret"
EOF

echo ""
echo "🚀 Monitoring Dashboard:"
echo "Access at: http://localhost:8080 (default)"
echo "- /metrics    - JSON metrics"
echo "- /health     - Health check"
echo "- /api/metrics - Prometheus format"

echo ""
echo "✅ Demo complete! The plugin is ready with multi-provider support."
echo "📚 See docs/MULTI_PROVIDER.md and docs/MONITORING.md for detailed guides."