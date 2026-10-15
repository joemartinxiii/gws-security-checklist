#!/usr/bin/env bash
# Shared helpers for deploy/bootstrap scripts.

set -euo pipefail

log() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

# App-level auth is the gate. Do not let this SA invoke every Cloud Run
# service in a shared project (including a sibling Admin Assist service).
revoke_project_run_invoker() {
  local project="$1"
  local member="$2"
  gcloud projects remove-iam-policy-binding "${project}" \
    --member="${member}" \
    --role="roles/run.invoker" \
    --quiet >/dev/null 2>&1 || true
}

# Private bucket with object versioning so a bad latest.json can be restored.
ensure_checklist_bucket() {
  local project="$1"
  local bucket="$2"
  local region="$3"
  local member="$4"
  if ! gcloud storage buckets describe "gs://${bucket}" --project="${project}" >/dev/null 2>&1; then
    gcloud storage buckets create "gs://${bucket}" \
      --project="${project}" \
      --location="${region}" \
      --uniform-bucket-level-access \
      --public-access-prevention
  fi
  gcloud storage buckets update "gs://${bucket}" \
    --public-access-prevention \
    --versioning \
    --quiet >/dev/null
  gcloud storage buckets add-iam-policy-binding "gs://${bucket}" \
    --member="${member}" \
    --role="roles/storage.objectAdmin" \
    --quiet >/dev/null
}
