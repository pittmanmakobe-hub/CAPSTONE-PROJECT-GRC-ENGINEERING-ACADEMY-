package hipaa.s3_cmk_encryption

# HIPAA Security Rule § 164.312(a)(2)(iv) — Encryption and Decryption
# Severity: CRITICAL
# Remediation: Set sse_algorithm = "aws:kms" and provide a kms_master_key_id
#   pointing to a customer-managed key (not the default aws/s3 managed key).

metadata := {
  "framework":   "HIPAA Security Rule",
  "control_id":  "164.312(a)(2)(iv)",
  "severity":    "CRITICAL",
  "remediation": "Use aws:kms with a customer-managed KMS key on all S3 buckets holding PHI.",
}

# Collect every S3 bucket encryption configuration block in the plan.
s3_encryption_configs[config] {
  config := input.resource_changes[_]
  config.type == "aws_s3_bucket_server_side_encryption_configuration"
  config.change.actions[_] != "delete"
}

# Deny if any S3 encryption config is NOT using aws:kms.
deny[msg] {
  cfg := s3_encryption_configs[_]
  rule := cfg.change.after.rule[_]
  algo := rule.apply_server_side_encryption_by_default[_].sse_algorithm
  algo != "aws:kms"
  msg := sprintf(
    "[HIPAA %s] S3 bucket encryption config '%s' uses '%s' instead of 'aws:kms'. All PHI buckets must use a CMK. Control: %s",
    [metadata.control_id, cfg.address, algo, metadata.control_id],
  )
}

# Deny if aws:kms is set but no kms_master_key_id is provided
# (that would fall back to the AWS-managed aws/s3 key, not a CMK you own).
deny[msg] {
  cfg := s3_encryption_configs[_]
  rule := cfg.change.after.rule[_]
  defaults := rule.apply_server_side_encryption_by_default[_]
  defaults.sse_algorithm == "aws:kms"
  not defaults.kms_master_key_id
  msg := sprintf(
    "[HIPAA %s] S3 bucket encryption config '%s' uses aws:kms but no kms_master_key_id is set. Specify a CMK ARN. Control: %s",
    [metadata.control_id, cfg.address, metadata.control_id],
  )
}
