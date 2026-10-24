resource "aws_iam_policy" "admin_jsonencode" {
  name = "admin"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy" "all_service_actions" {
  name = "all"
  role = "r"
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = ["*:*"]
      Resource = "arn:aws:s3:::bucket/*"
    }]
  })
}

data "aws_iam_policy_document" "admin_doc" {
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "scoped" {
  name = "scoped"
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::bucket/*"
    }]
  })
}

data "aws_iam_policy_document" "scoped_doc" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::bucket/*"]
  }
}
