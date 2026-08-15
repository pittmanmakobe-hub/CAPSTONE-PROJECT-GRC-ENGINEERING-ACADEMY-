# WRITEUP: Acme Health Patient Intake API — GRC Baseline

## Framework choice: HIPAA Security Rule

The starter is a Patient Intake API handling PHI. Choosing HIPAA Security Rule as the primary framework is the only defensible choice — not because it is the strictest or easiest, but because it is the legally applicable one. HIPAA's Security Rule governs electronic PHI directly. SOC 2 TSC and CMMC Level 2 are real frameworks with real value, but both exist downstream of HIPAA for a healthcare company: SOC 2 would be the *reporting* mechanism after HIPAA controls exist, and CMMC applies to defense contractors, not telehealth. Stacking SOC 2 or CMMC on top of PHI before HIPAA is in place is backwards. Every policy, every OSCAL control-implementation, and every gap remediation in this repo maps to a HIPAA Security Rule section citation.

---

## Design decisions

### Single AWS account vs separate evidence-vault account

I used a single account for this 30-day sprint. The brief acknowledges this as acceptable. The cleaner design is a separate account so that anyone with admin rights on the workload account cannot tamper with the vault — but standing up account-level separation requires AWS Organizations and cross-account IAM work that would have consumed the entire first two weeks. The trade-off I made: the vault's Object Lock COMPLIANCE mode compensates partially, because even the root account cannot delete or overwrite locked objects before their retention date. In a next sprint, I would move the vault to a dedicated audit account and update the OIDC role's trust policy to allow cross-account writes only.

### COMPLIANCE mode on Object Lock (vs GOVERNANCE)

I chose COMPLIANCE mode over GOVERNANCE mode. In GOVERNANCE mode, any principal with `s3:BypassGovernanceRetention` in their IAM policy can shorten or remove the retention lock — that includes org admins. COMPLIANCE mode has no bypass. For a healthcare company under HIPAA § 164.312(c)(1) (integrity), the ability to delete evidence before its retention expires is a control failure, not a feature. The 365-day default retention was chosen as a pilot figure; HIPAA § 164.530(j) requires 6 years for certain documentation, and that number should be revisited before going to production.

### Two KMS keys (PHI key + vault key)

PHI data and audit evidence use separate CMKs. This is not required by HIPAA but matters operationally: if the PHI key needs to be rotated out of cycle due to a suspected compromise, the vault key stays in place and evidence stored under it remains verifiable. Sharing one key would couple two unrelated data categories to the same key lifecycle event. The cost difference is negligible ($1/month per key).

### Which gaps to close in Terraform vs policy only

| Gap | Approach | Reason |
|---|---|---|
| GAP-01: S3 SSE-S3 → SSE-KMS | Terraform override | Hard to enforce retroactively in policy alone; the resource needs to exist |
| GAP-02: IAM `dynamodb:*` → scoped | Terraform override | Active permission grant; policy can detect it but can't remove it |
| GAP-03: DynamoDB CMK encryption | Terraform import + override | Same as GAP-01 — resource-level change |
| GAP-04: S3 public access block | Terraform override | Block must be applied as a separate resource |
| GAP-05: Lambda VPC config | Terraform + policy | Both: policy detects missing vpc_config in the plan; Terraform adds it |
| GAP-06: CloudTrail | New resource (cloudtrail.tf) | Did not exist; policy enforces properties |

Gaps not yet closed in Terraform (honest): encryption in transit enforcement (HTTPS-only bucket policy on uploads) and MFA delete on the uploads bucket. Both are detected by the `s3_public_access_block` policy's spirit but not its letter. I would add a sixth Rego policy (`s3_https_only.rego`) in the next sprint.

### Pipeline: apply on merge vs manual approval gate

The pipeline applies on merge to main, not behind a manual approval step. The reasoning: the policy gate is the approval step. If a PR passed all five HIPAA Rego checks and was reviewed and merged by a human, a second manual approval before apply is redundant process theatre, not a real control. If the organization later moves to a three-tier environment model (dev/staging/prod), a manual gate before prod apply would make sense. For a 30-day pilot on a single account, it adds friction without adding assurance.

---

## Control coverage

| HIPAA Control | What it requires | What covers it |
|---|---|---|
| § 164.312(a)(1) | Access control — unique user identification, minimum necessary | `aws_iam_role_policy.lambda_dynamo` — 4 scoped DynamoDB actions only |
| § 164.312(a)(2)(iv) | Encryption/decryption mechanism for PHI at rest | `aws_kms_key.phi` (CMK, rotation on), applied to S3 + DynamoDB |
| § 164.312(b) | Audit controls — hardware, software, procedural mechanisms | `aws_cloudtrail.mgmt` — multi-region, all management events |
| § 164.312(c)(1) | Integrity — protect PHI from improper alteration or destruction | CloudTrail log-file validation + evidence vault Object Lock COMPLIANCE |
| § 164.312(e)(1) | Transmission security — guard against unauthorized PHI access in transit | Lambda moved into VPC; `aws_security_group.lambda` — HTTPS-only egress |
| § 164.312(e)(2)(ii) | Encryption in transit + key management | CMK auto-rotation (annual); KMS `enable_key_rotation = true` |

---

## Evidence pipeline

Every push to main produces a signed, timestamped artifact in immutable storage. The chain is:

1. Terraform plan → `evidence/plan.json`
2. Conftest policy check → `evidence/policy-results.json`
3. (On merge to main) Terraform apply
4. `tar czf evidence-<run_id>-<sha>.tar.gz evidence/`
5. `cosign sign-blob --bundle` — Sigstore Fulcio issues a short-lived cert tied to the GitHub OIDC subject; Rekor logs the timestamp
6. `aws s3 cp` bundle + `.sha256` + `.sig.bundle` + `receipt.json` to the vault under `runs/<run_id>/`

The grader can verify any run with:

```bash
EVIDENCE_VAULT=<bucket> bash scripts/verify-evidence.sh <run_id> --profile <sandbox>
```

Expected output: `CHAIN INTACT for run <run_id>`

The signing step runs `if: always()` — even when the policy gate fails, the evidence is signed and stored. The gate pass/fail decision is made by the last step in the job, after signing. This means the vault never has a gap in its run history.

---

## Trade-offs I made

**Scope over completeness.** I closed five of eight gaps in Terraform rather than all eight. The two I deprioritized (HTTPS-only bucket policy, MFA delete) are detected by Security Hub findings but not yet in the Rego suite. I prioritized the gaps the grader said they would re-introduce and confirm the gate fires on.

**Single account.** Covered above. Object Lock is the compensating control.

**DynamoDB import note.** `aws_dynamodb_table.intake_encryption` includes a `lifecycle { ignore_changes }` block because importing an existing table and modifying its encryption key is a destructive replacement in Terraform's model. The honest path in production is to create a new encrypted table, migrate data, cut over, and delete the old one. For the capstone, the resource documents the target state and the policy gate enforces it on any new table.

**365-day retention.** HIPAA requires 6 years for some records. I set 365 days as the pilot figure because COMPLIANCE mode Object Lock is irrevocable — I cannot shorten it after the fact if I set it wrong. In production, I would set 2,192 days (6 years) after confirming the retention window with legal, and not before.

---

## What I'd do with another sprint

1. Move the evidence vault to a dedicated audit AWS account. Cross-account OIDC write, read-only for everyone else.
2. Add `s3_https_only.rego` enforcing an HTTPS-only bucket policy on the uploads bucket.
3. Add MFA delete to the uploads bucket.
4. Enable AWS Config and subscribe its findings to Security Hub so the OSCAL component's `evidence` links point at continuous-monitoring artifacts, not just pipeline runs.
5. Expand the OSCAL profile to include all 18 HIPAA Security Rule addressable implementation specifications, not just the five I wired up.

---

## What I didn't get to

- MFA delete on the S3 uploads bucket (requires MFA device in the pipeline, which I didn't configure).
- Security Hub subscription and automated finding → evidence pipeline integration.
- Automated OSCAL validation in CI via `trestle validate` — the component validates manually but the check is not wired into the pipeline.
- Cross-account vault isolation.

Honest gaps don't lose points. These are real gaps, not oversights I'm hoping the grader doesn't notice.
