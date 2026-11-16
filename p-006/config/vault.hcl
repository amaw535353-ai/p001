storage "inmem" {}
listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = true
}
disable_mlock = true
ui = false
log_level = "error"
