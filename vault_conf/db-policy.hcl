# Allow reading, creating, updating the data at secret/data/database/mysql
path "secret/data/database/mysql" {
  capabilities = ["create", "update", "read", "list"]
}

# Allow listing metadata (for UI or CLI list commands)
path "secret/metadata/database/mysql" {
  capabilities = ["list"]
}
