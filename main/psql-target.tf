module "psql-target" {
  source    = "../rds"
  count     = var.create_rds_postgresql == false ? 0 : 1
  subnet_id = [coalesce(var.relay_subnet, one(module.network[*].relay_subnet)), coalesce(var.relay_subnet-b, one(module.network[*].relay_subnet-b)), coalesce(var.relay_subnet-c, one(module.network[*].relay_subnet-c))]
  tagset    = var.tagset
  name      = var.name
  sg        = coalesce(var.public_sg, module.network[0].private_sg)

}

resource "sdm_resource" "rds-psql-target" {
  count = var.create_rds_postgresql == false ? 0 : 1
  postgres {
    database        = one(module.psql-target[*].db_name)
    name            = "${var.name}-postgresql-target"
    hostname        = one(module.psql-target[*].target_hostname)
    port            = one(module.psql-target[*].target_port)
    username        = "${one(module.psql-target[*].secret_arn)}?key=username"
    password        = "${one(module.psql-target[*].secret_arn)}?key=password"
    secret_store_id = sdm_secret_store.awssecretsmanager.id
    tags            = one(module.psql-target[*].thistagset)

  }
}