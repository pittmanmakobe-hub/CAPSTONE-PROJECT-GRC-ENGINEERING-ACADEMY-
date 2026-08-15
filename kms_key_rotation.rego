package hipaa.kms_key_rotation

# HIPAA Security Rule § 164.312(e)(2)(ii) — Encryption and Decryption
# Severity: HIGH
# Remediation: Set enable_key_rotation = true on every aws_kms_key resource.
#   AWS rotates the key material annually. Without rotation, a compromised
#   key persists indefinitely.

metadata := {
  "framework":   "HIPAA Security Rule",
  "control_id":  "164.312(e)(2)(ii)",
  "severity":    "HIGH",
  "remediation": "Set enable_key_rotation = true on all aws_kms_key resources.",
}

kms_keys[key] {
  key := input.resource_changes[_]
  key.type == "aws_kms_key"
  key.change.actions[_] != "delete"
}

deny[msg] {
  key := kms_keys[_]
  not key.change.after.enable_key_rotation
  msg := sprintf(
    "[HIPAA %s] KMS key '%s' does not have enable_key_rotation = true. Automatic annual rotation is required for PHI encryption keys. Control: %s",
    [metadata.control_id, key.address, metadata.control_id],
  )
}
