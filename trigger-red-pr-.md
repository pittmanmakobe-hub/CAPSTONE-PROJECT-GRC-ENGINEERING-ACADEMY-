# How to trigger the red PR (required by the capstone checklist)

The capstone requires one green PR (passed and merged) and one red PR
(failed the policy gate, blocked). The red PR is not a mistake — it is
evidence the gate actually works.

## What to do

1. Create a branch called `test/intentional-policy-violation`.
2. Add the file below as `terraform/intentional_violation.tf`.
3. Open a PR from that branch to `main`.
4. The policy gate will fire on `s3_cmk_encryption` and `s3_public_access_block`
   because the resource uses AES256 with no KMS key and has public access enabled.
5. Screenshot or copy the failed workflow run URL. Reference it in WRITEUP.md.
6. **Do not merge this PR.** Close it without merging after the gate fires red.

## The violation file

```hcl
# terraform/intentional_violation.tf
# DO NOT MERGE — intentional policy violation for capstone red-PR evidence.

resource "aws_s3_bucket_server_side_encryption_configuration" "bad_example" {
  bucket = "some-unprotected-bucket"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"   # FAILS: hipaa.s3_cmk_encryption — not a CMK
    }
  }
}

resource "aws_s3_bucket_public_access_block" "bad_example" {
  bucket = "some-unprotected-bucket"

  block_public_acls       = false  # FAILS: hipaa.s3_public_access_block
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
```

## Expected gate output

```
FAIL - evidence/plan.json - hipaa.s3_cmk_encryption
  [HIPAA 164.312(a)(2)(iv)] S3 bucket encryption config
  'aws_s3_bucket_server_side_encryption_configuration.bad_example' uses
  'AES256' instead of 'aws:kms'. All PHI buckets must use a CMK. Control: 164.312(a)(2)(iv)

FAIL - evidence/plan.json - hipaa.s3_public_access_block
  [HIPAA 164.312(e)(1)] Public access block
  'aws_s3_bucket_public_access_block.bad_example': block_public_acls must be true. Control: 164.312(e)(1)
```
