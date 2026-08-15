package hipaa.s3_cmk_encryption_test

import data.hipaa.s3_cmk_encryption

# ── PASS: aws:kms with explicit CMK ─────────────────────────────────────────
test_pass_kms_with_cmk {
  count(s3_cmk_encryption.deny) == 0 with input as {
    "resource_changes": [{
      "address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
      "type":    "aws_s3_bucket_server_side_encryption_configuration",
      "change":  {
        "actions": ["create"],
        "after": {
          "bucket": "my-phi-bucket",
          "rule": [{
            "apply_server_side_encryption_by_default": [{
              "sse_algorithm":     "aws:kms",
              "kms_master_key_id": "arn:aws:kms:us-east-1:123456789012:key/abc123",
            }],
          }],
        },
      },
    }],
  }
}

# ── FAIL: SSE-S3 (not a CMK) ────────────────────────────────────────────────
test_fail_sse_s3 {
  count(s3_cmk_encryption.deny) == 1 with input as {
    "resource_changes": [{
      "address": "aws_s3_bucket_server_side_encryption_configuration.bad",
      "type":    "aws_s3_bucket_server_side_encryption_configuration",
      "change":  {
        "actions": ["create"],
        "after": {
          "bucket": "bad-bucket",
          "rule": [{
            "apply_server_side_encryption_by_default": [{
              "sse_algorithm":     "AES256",
              "kms_master_key_id": null,
            }],
          }],
        },
      },
    }],
  }
}

# ── FAIL: aws:kms but no CMK specified ──────────────────────────────────────
test_fail_kms_no_key_id {
  count(s3_cmk_encryption.deny) == 1 with input as {
    "resource_changes": [{
      "address": "aws_s3_bucket_server_side_encryption_configuration.no_key",
      "type":    "aws_s3_bucket_server_side_encryption_configuration",
      "change":  {
        "actions": ["create"],
        "after": {
          "bucket": "no-key-bucket",
          "rule": [{
            "apply_server_side_encryption_by_default": [{
              "sse_algorithm":     "aws:kms",
              "kms_master_key_id": null,
            }],
          }],
        },
      },
    }],
  }
}
