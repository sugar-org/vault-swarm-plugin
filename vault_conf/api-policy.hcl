path "secret/data/application/api" {
  capabilities = ["create", "update", "read", "list"]
}

# Allow listing metadata (for UI or CLI list commands)
path "secret/metadata/application/api" {
  capabilities = ["list"]
}
