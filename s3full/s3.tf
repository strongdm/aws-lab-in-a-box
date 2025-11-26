resource "aws_iam_role" "s3_full_role" {
  name               = "${var.name}-S3FullRole"
  assume_role_policy = data.aws_iam_policy_document.s3f_assume_role_policy.json
  tags = var.tagset
}

data "aws_iam_policy_document" "s3f_assume_role_policy" {
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

resource "aws_iam_role_policy_attachment" "s3full_access_attachment" {
  role       = aws_iam_role.s3_full_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"  # This is the managed policy for read-only access to most AWS services
}
