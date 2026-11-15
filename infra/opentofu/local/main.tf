terraform {
  required_version = "= 1.13.9"
  required_providers {
    aws        = { source = "registry.terraform.io/hashicorp/aws", version = "= 6.25.0" }
    kubernetes = { source = "registry.terraform.io/hashicorp/kubernetes", version = "= 2.38.0" }
  }
}
provider "aws" {
  access_key                  = "test"
  secret_key                  = "test"
  region                      = "us-east-1"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  s3_use_path_style           = true
  endpoints { s3 = "http://127.0.0.1:4566" }
}
provider "kubernetes" {
  config_path    = "../../../.runtime/kubeconfig"
  config_context = "kind-p001"
}
module "synthetic_storage" {
  source = "../modules/synthetic-storage"
}

locals {
  manifests = jsondecode(file("../../kubernetes/resources.json"))
}
resource "kubernetes_manifest" "lab" {
  for_each = { for v in local.manifests : "${v.kind}-${v.metadata.namespace}-${v.metadata.name}" => v }
  manifest = each.value
}
