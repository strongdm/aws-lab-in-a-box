resource "sdm_secret_store" "awssecretsmanager" {
  aws {
    name   = "${var.name}awssecretsmanager"
    region = data.aws_region.current.name
  }
}