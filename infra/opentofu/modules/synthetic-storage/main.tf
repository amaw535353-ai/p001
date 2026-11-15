terraform {
  required_providers {
    aws = { source = "registry.terraform.io/hashicorp/aws", version = "= 6.25.0" }
  }
}
resource "aws_s3_bucket" "tenant" {
  for_each      = toset(["tenant-a", "tenant-b"])
  bucket        = "p001-${each.key}"
  force_destroy = true
  tags          = { project = "p001", tenant = each.key, classification = "synthetic" }
}
output "buckets" {
  value = { for k, b in aws_s3_bucket.tenant : k => b.id }
}
