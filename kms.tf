# KMS Customer-Managed Key with automatic annual rotation.
# Closes GAP-01: starter resources used default SSE-S3 and DynamoDB
# AWS-managed keys, not CMKs. HIPAA § 164.312(a)(2)(iv) requires
# encryption/decryption mechanisms; using a CMK gives Acme Health
# key-ownership evidence an auditor can point to.

resource "aws_kms_key" "phi" {
  description             = "CMK for PHI data at rest — uploads bucket and DynamoDB table"
  deletion_window_in_days = 30
  enable_key_rotation     = true   # HIPAA § 164.312(e)(2)(ii): auto-rotate annually

  policy = data.aws_iam_policy_document.kms_phi.json

  tags = {
    Project     = var.project
    Environment = var.environment
    HIPAA       = "phi"
  }
}

resource "aws_kms_alias" "phi" {
  name          = "alias/${var.project}-phi"
  target_key_id = aws_kms_key.phi.key_id
}

data "aws_iam_policy_document" "kms_phi" {
  # Root account full access (required; without this, key becomes unmanageable)
  statement {
    sid     = "RootFullAccess"
    effect  = "Allow"
    actions = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  # Lambda execution role can encrypt/decrypt PHI
  statement {
    sid    = "LambdaEncryptDecrypt"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
      "kms:DescribeKey",
    ]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.lambda_exec.arn]
    }
  }

  # CloudTrail needs to encrypt its log files
  statement {
    sid    = "CloudTrailEncrypt"
    effect = "Allow"
    actions = [
      "kms:GenerateDataKey*",
      "kms:Decrypt",
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

# KMS key for the evidence vault (separate from PHI key so audit logs
# and PHI data have independent key ownership — defense-in-depth).
resource "aws_kms_key" "vault" {
  description             = "CMK for evidence vault S3 bucket"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Project     = var.project
    Environment = var.environment
    Purpose     = "evidence-vault"
  }
}

resource "aws_kms_alias" "vault" {
  name          = "alias/${var.project}-vault"
  target_key_id = aws_kms_key.vault.key_id
}
