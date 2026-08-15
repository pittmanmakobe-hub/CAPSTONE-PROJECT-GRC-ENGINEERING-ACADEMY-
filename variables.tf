variable "aws_region" {
  description = "Primary AWS region for all resources."
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment (dev, prod)."
  type        = string
  default     = "dev"
}

variable "project" {
  description = "Project name tag applied to all resources."
  type        = string
  default     = "acme-health-intake"
}

# Pass in from your sandbox — these reference existing starter resources.
variable "starter_uploads_bucket" {
  description = "Name of the starter's existing S3 uploads bucket (the one receiving PHI intake files). Used to bring it under the CMK."
  type        = string
}

variable "starter_dynamodb_table" {
  description = "Name of the starter's existing DynamoDB table. Used to tighten IAM and enable encryption."
  type        = string
}

variable "starter_lambda_name" {
  description = "Name of the starter's Lambda function. Used to apply VPC config (GAP-05)."
  type        = string
}

variable "starter_vpc_id" {
  description = "VPC ID the starter already created. Lambda is moved into this — don't build a second VPC."
  type        = string
}

variable "starter_private_subnet_ids" {
  description = "Private subnet IDs inside the starter VPC for the Lambda VPC config."
  type        = list(string)
