Acme Health Patient Intake API — GRC Baseline

Capstone project for the CGEP course. Fork of GRCEngClub/cgep-app-starter. Primary framework: HIPAA Security Rule.

Quick start
bash
git clone <this-repo>
cd <this-repo>
make deploy AWS_PROFILE=<your-sandbox>
make test   AWS_PROFILE=<your-sandbox>
# Expect: {"submission_id": "...", "status": "received"}
Grader verification
1. Verify a signed evidence bundle
bash
EVIDENCE_VAULT=<bucket-from-outputs> \
  bash scripts/verify-evidence.sh <run_id> --profile <your-sandbox>
# Expected: CHAIN INTACT for run <run_id>
2. Confirm policy gate works
bash
opa test ./policies -v
# All tests pass.
3. Confirm CloudTrail is logging
bash
aws cloudtrail get-trail-status --name acme-health-intake-mgmt \
  --region us-east-1 --query '{IsLogging:IsLogging}'
# Expect: {"IsLogging": true}
4. Confirm vault Object Lock retention
bash
aws s3api get-object-retention \
  --bucket <vault-bucket> \
  --key runs/<run_id>/evidence-<run_id>-<sha>.tar.gz \
  --query 'Retention'
# Expect: {"Mode": "COMPLIANCE", "RetainUntilDate": "..."}
Repo layout
terraform/          Layer 1 — KMS, vault, CloudTrail, gap overrides
policies/           Layer 2 — 5 HIPAA Rego policies + tests
.github/workflows/  Layer 3 — grc-gate.yml (Plan→Policy→Apply→Sign→Upload)
oscal/components/   Layer 4 — acme-health-intake.json component definition
scripts/            verify-evidence.sh, grant-vault-write.sh
docs/               trigger-red-pr.md
WRITEUP.md          Design decisions, trade-offs, gap mapping
One green PR, one red PR

See repo PR history. The red PR is on branch test/intentional-policy-violation — it violated hipaa.s3_cmk_encryption and hipaa.s3_public_access_block and was blocked by the gate. It was closed without merging.
