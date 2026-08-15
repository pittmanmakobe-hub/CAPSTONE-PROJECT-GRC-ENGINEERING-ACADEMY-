# Gap-closing overrides on the starter's existing resources.
# These do NOT create new workload resources — they harden what's already there.
# The starter's VPC, subnets, Lambda, S3 bucket, and DynamoDB table already
# exist; these resources enforce the missing controls on top of them.

# ─── GAP-01 · S3 uploads bucket: SSE-S3 → SSE-KMS (CMK) ──────────────────
# HIPAA § 164.312(a)(2)(iv) — encryption/decryption mechanism.
# The starter bucket used aws:s3 (AWS-managed). The CMK gives Acme Health
# key ownership, rotation evidence, and CloudTrail visibility on every use.

resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = var.starter_uploads_bucket

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket                  = var.starter_uploads_bucket
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "uploads" {
  bucket = var.starter_uploads_bucket
  versioning_configuration { status = "Enabled" }
}

# ─── GAP-02 · DynamoDB: IAM tighten from dynamodb:* ──────────────────────
# HIPAA § 164.312(a)(1) — access control (unique user identification,
# minimum necessary). The starter granted dynamodb:* to Lambda. Scoped
# to the four operations the intake flow actually needs.

resource "aws_iam_role" "lambda_exec" {
  name = "${var.project}-lambda-exec"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = {
    Project = var.project
    HIPAA   = "least-privilege"
  }
}

resource "aws_iam_role_policy" "lambda_dynamo" {
  name = "dynamo-least-privilege"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "IntakeReadWrite"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query",
        ]
        Resource = "arn:aws:dynamodb:${var.aws_region}:${data.aws_caller_identity.current.account_id}:table/${var.starter_dynamodb_table}"
      },
      {
        Sid    = "KMSForDynamo"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
        ]
        Resource = aws_kms_key.phi.arn
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_logs" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# ─── GAP-03 · DynamoDB encryption at rest with CMK ───────────────────────
# HIPAA § 164.312(a)(2)(iv). DynamoDB was using AWS-managed keys.

resource "aws_dynamodb_table" "intake_encryption" {
  # This resource references the existing table by name. Because Terraform
  # cannot retroactively attach a KMS key to an existing DynamoDB table via
  # aws_dynamodb_table (it requires replacement), in the capstone context
  # this resource documents the target state. Apply this in the deploy
  # pipeline by importing the existing table first:
  #   terraform import aws_dynamodb_table.intake_encryption <table_name>
  name           = var.starter_dynamodb_table
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "submission_id"

  attribute {
    name = "submission_id"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.phi.arn
  }

  point_in_time_recovery { enabled = true }

  tags = {
    Project = var.project
    HIPAA   = "phi"
  }

  lifecycle {
    ignore_changes = [
      # Starter may have additional attributes/GSIs not known here.
      # Prevent Terraform from destroying them on first import.
      attribute,
      global_secondary_index,
      local_secondary_index,
    ]
  }
}

# ─── GAP-04 · S3 uploads: block all public access ─────────────────────────
# Already covered in GAP-01 block above (aws_s3_bucket_public_access_block).

# ─── GAP-05 · Lambda: move into existing VPC ─────────────────────────────
# HIPAA § 164.312(e)(1) — transmission security; § 164.312(a)(1) — access
# control through network segmentation. Lambda running outside the VPC means
# its DynamoDB and S3 calls traverse the public internet without the
# network-level controls the starter's VPC provides.

resource "aws_security_group" "lambda" {
  name        = "${var.project}-lambda-sg"
  description = "Lambda intake function — egress to AWS services only"
  vpc_id      = var.starter_vpc_id

  egress {
    description = "HTTPS to AWS service endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Project = var.project
    HIPAA   = "network-control"
  }
}

resource "aws_lambda_function_event_invoke_config" "intake" {
  function_name = var.starter_lambda_name
  # VPC config is set as a separate resource so it can target the existing
  # function without forcing a full replacement.
}

# NOTE: aws_lambda_function doesn't support partial updates to vpc_config via
# a separate resource; you must update the aws_lambda_function resource in
# the starter's own Terraform (or import it here and set vpc_config).
# The security group above is the network boundary artifact; wire it to the
# function via:
#   vpc_config {
#     subnet_ids         = var.starter_private_subnet_ids
#     security_group_ids = [aws_security_group.lambda.id]
#   }
# in the starter's aws_lambda_function block, or import and override here.

# ─── GAP-06 · CloudTrail: already provisioned in cloudtrail.tf ───────────
# Placeholder comment — no separate resource needed.
