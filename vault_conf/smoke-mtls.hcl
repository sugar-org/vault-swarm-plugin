ui            = false
disable_mlock = true // turn of for this for local testing

storage "inmem" {}

listener "tcp" {
  address                            = "0.0.0.0:8200"
  tls_cert_file                      = "/vault/tls/vault.crt"
  tls_key_file                       = "/vault/tls/vault.key"
  tls_client_ca_file                 = "/vault/tls/ca.crt"
  tls_require_and_verify_client_cert = true
}

api_addr = "https://127.0.0.1:8200"
