resource "aws_db_instance" "rds_target" {
  instance_class                = "db.t3.micro"
  identifier_prefix             = "lab"
  allocated_storage             = 5
  engine                        = "postgres"
  engine_version                = "16.3"
  manage_master_user_password   = true
  multi_az                      = false
  username                      = "dba"
  vpc_security_group_ids        = [var.sg]
  db_name                       = var.db_name
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