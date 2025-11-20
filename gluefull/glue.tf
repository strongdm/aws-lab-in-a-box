resource "aws_iam_role" "glue_full_role" {
  name               = "glueFullRole"
  assume_role_policy = data.aws_iam_policy_document.glue_assume_role_policy.json
  tags = var.tagset
}

data "aws_iam_policy_document" "glue_assume_role_policy" {
  statement {
    actions   = ["sts:AssumeRole"]
    effect    = "Allow"
  principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }

  principals {
      type        = "AWS"
      identifiers = [var.role]
    }
  }
}

resource "aws_iam_role_policy_attachment" "glue_access_attachment" {
  role       = aws_iam_role.glue_full_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSGlueConsoleFullAccess"  # This is the managed policy for read-only access to most AWS services
}
