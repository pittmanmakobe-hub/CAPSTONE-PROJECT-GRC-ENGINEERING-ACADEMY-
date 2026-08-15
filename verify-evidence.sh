#!/usr/bin/env bash
# scripts/verify-evidence.sh <run_id>
#
# Verifies the full chain of custody for a signed evidence bundle stored
# in the Lab 2.5 vault:
#   1. Integrity   - recomputed SHA-256 matches the .sha256 sidecar
#   2. Authenticity/timestamp - Cosign signature verifies against Sigstore
#   3. Preservation - S3 Object Lock retention is still in force
#
# Usage:
#   EVIDENCE_VAULT=<bucket> ./verify-evidence.sh <run_id> [--profile <p>]
#   ./verify-evidence.sh <run_id> --vault <bucket> [--profile <p>]

set -euo pipefail
RUN_ID="${1:?usage: verify-evidence.sh <run_id> [--vault <bucket>] [--profile <p>]}"
shift || true
VAULT="${EVIDENCE_VAULT:-}"
PROFILE_ARG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vault)   VAULT="$2"; shift 2 ;;
    --profile) PROFILE_ARG="--profile $2"; shift 2 ;;
    *) echo "Unknown argument: $1"; exit 2 ;;
  esac
done
[[ -z "$VAULT" ]] && { echo "Set --vault or EVIDENCE_VAULT"; exit 2; }

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT; cd "$WORK"
PREFIX="runs/${RUN_ID}"

aws $PROFILE_ARG s3 cp "s3://${VAULT}/${PREFIX}/" . --recursive \
  --exclude "*" --include "evidence-*.tar.gz*" --include "receipt.json"

BUNDLE=$(ls evidence-*.tar.gz | head -1)

echo "=== 1. Integrity (SHA-256) ==="
EXPECTED=$(cat "${BUNDLE}.sha256")
ACTUAL=$(shasum -a 256 "${BUNDLE}" | awk '{print $1}')
if [[ "$EXPECTED" == "$ACTUAL" ]]; then
  echo "  OK (${ACTUAL})"
else
  echo "FAIL: SHA mismatch"
  exit 1
fi

echo "=== 2. Authenticity + timestamp (Cosign + Sigstore Rekor) ==="
cosign verify-blob \
  --bundle "${BUNDLE}.sig.bundle" \
  --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${BUNDLE}"
echo "  OK (Cosign verified, Rekor entry exists)"

echo "=== 3. Preservation (Object Lock retention) ==="
RETAIN_UNTIL=$(aws $PROFILE_ARG s3api get-object-retention \
  --bucket "${VAULT}" --key "${PREFIX}/${BUNDLE}" \
  --query 'Retention.RetainUntilDate' --output text)
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
if [[ "$RETAIN_UNTIL" > "$NOW" ]]; then
  echo "  OK (retain until ${RETAIN_UNTIL})"
else
  echo "FAIL: retention expired"
  exit 1
fi

echo ""
echo "CHAIN INTACT for run ${RUN_ID}"
