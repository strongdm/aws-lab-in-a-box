resource "aws_iam_role" "s3_read_only_role" {
  name               = "S3ReadOnlyRole"
  assume_role_policy = data.aws_iam_policy_document.s3_assume_role_policy.json
  tags = var.tagset
}

data "aws_iam_policy_document" "s3_assume_role_policy" {
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

resource "aws_iam_role_policy_attachment" "s3ro_access_attachment" {
  role       = aws_iam_role.s3_read_only_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"  # This is the managed policy for read-only access to most AWS services
}
