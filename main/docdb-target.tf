// filepath: /Users/stokvis/dev/sdm/aws-lab-in-a-box/main/docdb-target.tf

#-------------------------------------------------------
# DocumentDB Integration with StrongDM
#
# This file integrates the DocumentDB module with StrongDM,
# creating a secure access pathway to MongoDB-compatible 
# database instances. It demonstrates how to:
#
# 1. Create the underlying DocumentDB infrastructure
# 2. Register it as a target resource in StrongDM
# 3. Configure authentication via StrongDM
#-------------------------------------------------------

# Create the DocumentDB cluster using our reusable module
module "docdb-target" {
  source    = "../docdb"
  count     = var.create_docdb == false ? 0 : 1
  subnet_id = [coalesce(var.relay_subnet, one(module.network[*].relay_subnet)), coalesce(var.relay_subnet-b, one(module.network[*].relay_subnet-b)), coalesce(var.relay_subnet-c, one(module.network[*].relay_subnet-c))]
  tagset    = var.tagset
  name      = var.name
  sg        = coalesce(var.public_sg, module.network[0].private_sg)
}

# Register the DocumentDB cluster in StrongDM as a managed resource
# This creates a MongoDB-compatible resource in StrongDM for access control
resource "sdm_resource" "docdb-target" {
  count = var.create_docdb == false ? 0 : 1
  document_db_replica_set {
    name          = "${var.name}-docdb-target"
    hostname      = one(module.docdb-target[*].docdb_endpoint)
    username      = one(module.docdb-target[*].docdb_username)
    password      = one(module.docdb-target[*].docdb_password)
    auth_database = "admin"                                # Default authentication database
    replica_set   = "rs0"                                  # Default replica set name
    tags          = one(module.docdb-target[*].thistagset) # Apply consistent tagging
  }
}