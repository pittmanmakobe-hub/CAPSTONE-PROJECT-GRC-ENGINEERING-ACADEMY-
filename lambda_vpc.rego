package hipaa.lambda_vpc

# HIPAA Security Rule § 164.312(e)(1) — Transmission Security (network controls)
# Severity: HIGH
# Remediation: Add a vpc_config block to the aws_lambda_function resource with
#   subnet_ids and security_group_ids pointing at private subnets in the
#   existing VPC. Lambda outside a VPC makes DynamoDB and S3 calls over
#   the public internet, bypassing network-level access controls.

metadata := {
  "framework":   "HIPAA Security Rule",
  "control_id":  "164.312(e)(1)",
  "severity":    "HIGH",
  "remediation": "Add vpc_config { subnet_ids = [...] security_group_ids = [...] } to the Lambda function.",
}

lambda_functions[fn] {
  fn := input.resource_changes[_]
  fn.type == "aws_lambda_function"
  fn.change.actions[_] != "delete"
}

deny[msg] {
  fn := lambda_functions[_]
  vpc_configs := fn.change.after.vpc_config
  count(vpc_configs) == 0
  msg := sprintf(
    "[HIPAA %s] Lambda function '%s' has no vpc_config. PHI-processing functions must run inside the VPC. Control: %s",
    [metadata.control_id, fn.address, metadata.control_id],
  )
}

deny[msg] {
  fn := lambda_functions[_]
  vpc_cfg := fn.change.after.vpc_config[_]
  count(vpc_cfg.subnet_ids) == 0
  msg := sprintf(
    "[HIPAA %s] Lambda function '%s' has an empty vpc_config.subnet_ids. Specify private subnet IDs. Control: %s",
    [metadata.control_id, fn.address, metadata.control_id],
  )
}
