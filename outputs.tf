output "evidence_vault_bucket" {
  description = "S3 bucket name for the evidence vault. Set as repo variable EVIDENCE_VAULT."
  value       = aws_s3_bucket.vault.id
}

output "phi_kms_key_arn" {
  description = "ARN of the CMK used for PHI data at rest."
  value       = aws_kms_key.phi.arn
}

output "vault_kms_key_arn" {
  description = "ARN of the CMK used for the evidence vault."
  value       = aws_kms_key.vault.arn
}

output "cloudtrail_arn" {
  description = "ARN of the multi-region management CloudTrail."
  value       = aws_cloudtrail.mgmt.arn
}

output "lambda_security_group_id" {
  description = "Security group to attach to the starter Lambda for GAP-05."
  value       = aws_security_group.lambda.id
}
