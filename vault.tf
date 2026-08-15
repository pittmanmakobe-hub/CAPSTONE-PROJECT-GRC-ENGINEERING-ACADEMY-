# Evidence vault: immutable, versioned, encrypted, Object Lock COMPLIANCE mode.
#
# COMPLIANCE vs GOVERNANCE choice: COMPLIANCE mode is used here because
# HIPAA requires that audit records be retained and protected from alteration
# or destruction (§ 164.312(b)). GOVERNANCE mode allows org admins to shorten
# retention; COMPLIANCE mode does not — not even the root account can delete
# a locked object before its RetainUntilDate. For a healthcare company under
# HIPAA, the inability to bypass retention is a feature, not a limitation.

resource "aws_s3_bucket" "vault" {
  bucket        = "${var.project}-evidence-vault-${random_id.suffix.hex}"
  force_destroy = false  # never allow terraform destroy to wipe evidence

  object_lock_enabled = true

  tags = {
    Project     = var.project
    Environment = var.environment
    HIPAA       = "audit-evidence"
  }
}

resource "aws_s3_bucket_versioning" "vault" {
  bucket = aws_s3_bucket.vault.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_object_lock_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 365   # HIPAA § 164.530(j): 6 years; start with 1 year for the pilot
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.vault.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "vault" {
  bucket                  = aws_s3_bucket.vault.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id

  rule {
    id     = "transition-to-glacier"
    status = "Enabled"
    filter { prefix = "runs/" }
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
  }
}
