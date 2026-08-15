package hipaa.cloudtrail_integrity

# HIPAA Security Rule § 164.312(b) — Audit Controls
# HIPAA Security Rule § 164.312(c)(1) — Integrity (detect unauthorized alteration)
# Severity: HIGH
# Remediation: Set enable_log_file_validation = true and is_multi_region_trail = true
#   on all aws_cloudtrail resources. Log-file validation produces hourly digest
#   files that detect log tampering. Multi-region ensures no region's activity
#   is invisible.

metadata := {
  "framework":   "HIPAA Security Rule",
  "control_id":  "164.312(b), 164.312(c)(1)",
  "severity":    "HIGH",
  "remediation": "Set enable_log_file_validation = true and is_multi_region_trail = true on aws_cloudtrail.",
}

trails[trail] {
  trail := input.resource_changes[_]
  trail.type == "aws_cloudtrail"
  trail.change.actions[_] != "delete"
}

deny[msg] {
  trail := trails[_]
  not trail.change.after.enable_log_file_validation
  msg := sprintf(
    "[HIPAA %s] CloudTrail '%s' does not have enable_log_file_validation = true. Without it, log tampering is undetectable. Control: %s",
    [metadata.control_id, trail.address, metadata.control_id],
  )
}

deny[msg] {
  trail := trails[_]
  not trail.change.after.is_multi_region_trail
  msg := sprintf(
    "[HIPAA %s] CloudTrail '%s' is not a multi-region trail. Activity in any non-home region would be unaudited. Control: %s",
    [metadata.control_id, trail.address, metadata.control_id],
  )
}
