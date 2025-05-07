#--------------------------------------------------------------
# AWS Read-Only Role Module Variables
#
# These variables control the behavior of the AWS Read-Only access module,
# which creates IAM roles and policies for secure AWS resource access via StrongDM.
#--------------------------------------------------------------

variable "tagset" {
  description = "Set of Tags to apply to StrongDM resources"
  type        = map(string)
}

variable "role" {
  description = "ARN of the gateway role that will be allowed to assume this read-only role"
  type        = string
}