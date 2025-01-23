resource "aws_iam_role" "ec2_read_only_role" {
  name               = "EC2ReadOnlyRole"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role_policy.json
  tags = var.tagset
}

data "aws_iam_policy_document" "ec2_assume_role_policy" {
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

resource "aws_iam_role_policy_attachment" "read_only_access_attachment" {
  role       = aws_iam_role.ec2_read_only_role.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"  # This is the managed policy for read-only access to most AWS services
}
