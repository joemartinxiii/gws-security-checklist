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

# Cloud Build runs as DEPLOY_SA, not the default compute account. The account
# gets only what it needs to build and push this one image:
#   - logging.logWriter on the project (build logs go to Cloud Logging only)
#   - artifactregistry.writer on the one repository
#   - storage.objectViewer on the source staging bucket
# The person who runs deploy.sh needs iam.serviceAccountUser on it.
ensure_source_staging_bucket() {
  local project="$1"
  local region="$2"
  local bucket="${project}_cloudbuild"
  if ! gcloud storage buckets describe "gs://${bucket}" --project="${project}" >/dev/null 2>&1; then
    log "Creating source staging bucket gs://${bucket}..."
    gcloud storage buckets create "gs://${bucket}" \
      --project="${project}" \
      --location="${region}" \
      --uniform-bucket-level-access \
      --public-access-prevention
  fi
}

ensure_deploy_sa() {
  local project="$1"
  local region="$2"
  local email="${DEPLOY_SA}@${project}.iam.gserviceaccount.com"
  local member="serviceAccount:${email}"
  local bucket="${project}_cloudbuild"
  local account operator

  if ! gcloud iam service-accounts describe "${email}" --project="${project}" >/dev/null 2>&1; then
    log "Creating build service account ${email}..."
    gcloud iam service-accounts create "${DEPLOY_SA}" \
      --display-name="Security Checklist Cloud Build" \
      --project="${project}"
  fi
  wait_for_service_account "${email}" "${project}"

  ensure_source_staging_bucket "${project}" "${region}"

  log "Granting build access to ${email}..."
  retry_iam gcloud projects add-iam-policy-binding "${project}" \
    --member="${member}" \
    --role="roles/logging.logWriter" \
    --condition=None \
    --quiet
  retry_iam gcloud artifacts repositories add-iam-policy-binding "${ARTIFACT_REPO}" \
    --location="${region}" \
    --project="${project}" \
    --member="${member}" \
    --role="roles/artifactregistry.writer" \
    --quiet
  retry_iam gcloud storage buckets add-iam-policy-binding "gs://${bucket}" \
    --member="${member}" \
    --role="roles/storage.objectViewer" \
    --quiet

  account="$(gcloud config get-value account 2>/dev/null || true)"
  if [[ -n "${account}" && "${account}" != "(unset)" ]]; then
    if [[ "${account}" == *.gserviceaccount.com ]]; then
      operator="serviceAccount:${account}"
    else
      operator="user:${account}"
    fi
    retry_iam gcloud iam service-accounts add-iam-policy-binding "${email}" \
      --member="${operator}" \
      --role="roles/iam.serviceAccountUser" \
      --project="${project}" \
      --quiet
  else
    log "No active gcloud account. Grant roles/iam.serviceAccountUser on ${email} to whoever runs deploy.sh."
  fi
}

# deploy.sh stops early when bootstrap has not created the build account yet.
require_deploy_sa() {
  local project="$1"
  local email="${DEPLOY_SA}@${project}.iam.gserviceaccount.com"
  gcloud iam service-accounts describe "${email}" --project="${project}" >/dev/null 2>&1 \
    || die "Build service account ${email} does not exist. Run scripts/bootstrap.sh first (it is safe to re-run)."
}

# Creates the IAP service agent. Running it again changes nothing.
# Older gcloud releases have this command only in the beta track.
ensure_iap_service_agent() {
  local project="$1"
  gcloud services identity create \
    --service=iap.googleapis.com \
    --project="${project}" \
    --quiet >/dev/null 2>&1 \
    || gcloud beta services identity create \
      --service=iap.googleapis.com \
      --project="${project}" \
      --quiet >/dev/null
}

# Prints the number of the newest enabled version of a secret.
# Cloud Run takes only a version number or "latest", so strip the resource path.
latest_secret_version() {
  local name="$1"
  local project="$2"
  local resource version
  resource="$(gcloud secrets versions list "${name}" --project="${project}" --filter='state:enabled' --sort-by=~createTime --format='value(name)' --limit=1)"
  version="${resource##*/}"
  [[ "${version}" =~ ^[0-9]+$ ]] || die "Secret ${name} has no enabled version. Run scripts/bootstrap.sh, or add a version with gcloud secrets versions add."
  printf '%s' "${version}"
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
# A lifecycle rule deletes noncurrent versions after 30 days.
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
  local lifecycle
  lifecycle="$(mktemp)"
  cat >"${lifecycle}" <<'JSON'
{"rule":[{"action":{"type":"Delete"},"condition":{"daysSinceNoncurrentTime":30,"isLive":false}}]}
JSON
  gcloud storage buckets update "gs://${bucket}" \
    --lifecycle-file="${lifecycle}" \
    --quiet >/dev/null
  rm -f "${lifecycle}"
  retry_iam gcloud storage buckets add-iam-policy-binding "gs://${bucket}" \
    --member="${member}" \
    --role="roles/storage.objectAdmin" \
    --quiet
}

# Keep the 3 newest image versions and delete older ones.
# Keep policies win over delete policies. Artifact Registry applies the policy
# in a background job, so deletes can take about a day.
ensure_artifact_cleanup() {
  local project="$1"
  local region="$2"
  local policy
  policy="$(mktemp)"
  cat >"${policy}" <<'JSON'
[
  {"name": "delete-old-images", "action": {"type": "Delete"}, "condition": {"tagState": "any"}},
  {"name": "keep-3-newest", "action": {"type": "Keep"}, "mostRecentVersions": {"keepCount": 3}}
]
JSON
  gcloud artifacts repositories set-cleanup-policies "${ARTIFACT_REPO}" \
    --location="${region}" \
    --project="${project}" \
    --policy="${policy}" \
    --quiet >/dev/null
  rm -f "${policy}"
}
