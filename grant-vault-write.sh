#!/usr/bin/env bash
# scripts/grant-vault-write.sh <vault-bucket> <sandbox-profile> <owner/repo>
#
# Grants the Lab 4.3 OIDC role (cgep-grc-gate) a tight inline policy that
# allows it to write evidence bundles to the Lab 2.5 vault, and records the
# vault name as a repo variable so the workflow can read it.

set -euo pipefail
VAULT="${1:?usage: grant-vault-write.sh <vault-bucket> <sandbox-profile> <owner/repo>}"
PROFILE="${2:?usage: grant-vault-write.sh <vault-bucket> <sandbox-profile> <owner/repo>}"
REPO="${3:?usage: grant-vault-write.sh <vault-bucket> <sandbox-profile> <owner/repo>}"

eval "$(aws configure export-credentials --profile "${PROFILE}" --format env)"

aws iam put-role-policy \
  --role-name cgep-grc-gate \
  --policy-name vault-write \
  --policy-document "$(cat <<EOF
{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Action":["s3:PutObject","s3:GetObject","s3:GetBucketLocation"],
    "Resource":["arn:aws:s3:::${VAULT}","arn:aws:s3:::${VAULT}/*"]
  }]
}
EOF
)"

gh variable set EVIDENCE_VAULT --body "${VAULT}" --repo "${REPO}"

echo "Granted s3:PutObject/GetObject/GetBucketLocation on ${VAULT} to role cgep-grc-gate."
echo "Set EVIDENCE_VAULT=${VAULT} as a repo variable on ${REPO}."
