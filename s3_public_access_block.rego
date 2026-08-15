package hipaa.s3_public_access_block

# HIPAA Security Rule § 164.312(e)(1) — Transmission Security
# Severity: CRITICAL
# Remediation: Add aws_s3_bucket_public_access_block with all four flags = true
#   for every S3 bucket that may hold PHI.

metadata := {
  "framework":   "HIPAA Security Rule",
  "control_id":  "164.312(e)(1)",
  "severity":    "CRITICAL",
  "remediation": "Set block_public_acls, block_public_policy, ignore_public_acls, and restrict_public_buckets to true.",
}

public_access_blocks[block] {
  block := input.resource_changes[_]
  block.type == "aws_s3_bucket_public_access_block"
  block.change.actions[_] != "delete"
}

# Collect bucket names that have a public access block configured.
blocked_buckets[bucket_name] {
  block := public_access_blocks[_]
  bucket_name := block.change.after.bucket
}

deny[msg] {
  block := public_access_blocks[_]
  after := block.change.after
  not after.block_public_acls
  msg := sprintf(
    "[HIPAA %s] Public access block '%s': block_public_acls must be true. Control: %s",
    [metadata.control_id, block.address, metadata.control_id],
  )
}

deny[msg] {
  block := public_access_blocks[_]
  after := block.change.after
  not after.block_public_policy
  msg := sprintf(
    "[HIPAA %s] Public access block '%s': block_public_policy must be true. Control: %s",
    [metadata.control_id, block.address, metadata.control_id],
  )
}

deny[msg] {
  block := public_access_blocks[_]
  after := block.change.after
  not after.ignore_public_acls
  msg := sprintf(
    "[HIPAA %s] Public access block '%s': ignore_public_acls must be true. Control: %s",
    [metadata.control_id, block.address, metadata.control_id],
  )
}

deny[msg] {
  block := public_access_blocks[_]
  after := block.change.after
  not after.restrict_public_buckets
  msg := sprintf(
    "[HIPAA %s] Public access block '%s': restrict_public_buckets must be true. Control: %s",
    [metadata.control_id, block.address, metadata.control_id],
  )
}
