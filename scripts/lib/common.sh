#!/usr/bin/env bash
# Shared helpers for deploy/bootstrap scripts.

set -euo pipefail

log() { printf '%s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

# A service account can be missing from IAM for several seconds after create.
wait_for_service_account() {
  local email="$1"
  local project="$2"
  local attempt
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if gcloud iam service-accounts describe "${email}" --project="${project}" >/dev/null 2>&1; then
      return 0
    fi
    log "Waiting for ${email} to become visible (${attempt}/10)..."
    sleep 3
  done
  die "Service account ${email} is not visible yet. Re-run this script."
}

# IAM bindings return "does not exist" until the new account propagates.
retry_iam() {
  local attempt
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    log "IAM is not ready yet. Retrying (${attempt}/10)..."
    sleep 3
  done
  "$@"
}

# New projects do not let the default Cloud Build account read its own source bucket.
ensure_cloud_build_access() {
  local project="$1"
  local number member
  number="$(gcloud projects describe "${project}" --format='value(projectNumber)')"
  member="serviceAccount:${number}-compute@developer.gserviceaccount.com"
  log "Granting Cloud Build access to ${member}..."
  retry_iam gcloud projects add-iam-policy-binding "${project}" \
    --member="${member}" \
    --role="roles/cloudbuild.builds.builder" \
    --quiet
  retry_iam gcloud projects add-iam-policy-binding "${project}" \
    --member="${member}" \
    --role="roles/artifactregistry.writer" \
    --quiet
}

# App-level auth is the gate. Do not let this SA invoke every Cloud Run
# service in the project.
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
  retry_iam gcloud storage buckets add-iam-policy-binding "gs://${bucket}" \
    --member="${member}" \
    --role="roles/storage.objectAdmin" \
    --quiet
}
