resource "aws_db_instance" "rds_target" {
  instance_class                = "db.t3.micro"
  allocated_storage             = 5
  engine                        = "postgres"
  engine_version                = "17.1"
  manage_master_user_password   = true
  multi_az                      = false
  username                      = "dba"

  db_subnet_group_name   = aws_db_subnet_group.rds_target.name
  skip_final_snapshot    = true
  tags = local.thistagset
}

resource "aws_db_subnet_group" "rds_target" {
  name       = "main"
  subnet_ids = var.subnet_id

  tags = local.thistagset
}

locals {
  thistagset = merge (var.tagset, {
    network = "Private"
    class   = "target"
    }
  )  
}