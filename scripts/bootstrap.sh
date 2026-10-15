#!/usr/bin/env bash
# First-time GCP bootstrap for GWS Security.
#
# Creates: APIs, runtime SA, build SA, Artifact Registry (keeps the 3 newest images),
# GCS bucket (deletes noncurrent versions after 30 days), the IAP service agent,
# and Secret Manager entries. Safe to re-run.
# You still must create a new OAuth Web client and authorize DWD for the new SA.
#
# Usage:
#   PROJECT_ID=your-gcp-project-id \
#   WORKSPACE_DOMAIN=yourcompany.com \
#   ALLOWED_DOMAINS=yourcompany.com \
#   bash scripts/bootstrap.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "${ROOT}/scripts/lib/common.sh"
# shellcheck source=scripts/lib/scopes.sh
source "${ROOT}/scripts/lib/scopes.sh"

require_cmd gcloud
require_cmd openssl

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || true)}"
[[ -n "${PROJECT_ID}" && "${PROJECT_ID}" != "(unset)" ]] || die "Set PROJECT_ID"
REGION="${REGION:-${DEFAULT_REGION}}"
WORKSPACE_DOMAIN="${WORKSPACE_DOMAIN:-}"
ALLOWED_DOMAINS="${ALLOWED_DOMAINS:-${WORKSPACE_DOMAIN}}"
[[ -n "${WORKSPACE_DOMAIN}" ]] || die "Set WORKSPACE_DOMAIN=yourcompany.com"

RUNTIME_SA_EMAIL="${RUNTIME_SA}@${PROJECT_ID}.iam.gserviceaccount.com"
CHECKLIST_BUCKET="${CHECKLIST_BUCKET:-${PROJECT_ID}-security-checklist}"

log "Enabling APIs..."
gcloud services enable "${GCP_APIS[@]}" --project="${PROJECT_ID}" --quiet

if ! gcloud iam service-accounts describe "${RUNTIME_SA_EMAIL}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud iam service-accounts create "${RUNTIME_SA}" \
    --display-name="Security Checklist runtime" \
    --project="${PROJECT_ID}"
fi

wait_for_service_account "${RUNTIME_SA_EMAIL}" "${PROJECT_ID}"

retry_iam gcloud iam service-accounts add-iam-policy-binding "${RUNTIME_SA_EMAIL}" \
  --member="serviceAccount:${RUNTIME_SA_EMAIL}" \
  --role="roles/iam.serviceAccountTokenCreator" \
  --project="${PROJECT_ID}" \
  --quiet

revoke_project_run_invoker "${PROJECT_ID}" "serviceAccount:${RUNTIME_SA_EMAIL}"

if ! gcloud artifacts repositories describe "${ARTIFACT_REPO}" --location="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  gcloud artifacts repositories create "${ARTIFACT_REPO}" \
    --repository-format=docker \
    --location="${REGION}" \
    --project="${PROJECT_ID}" \
    --quiet
fi

ensure_artifact_cleanup "${PROJECT_ID}" "${REGION}"

ensure_checklist_bucket "${PROJECT_ID}" "${CHECKLIST_BUCKET}" "${REGION}" "serviceAccount:${RUNTIME_SA_EMAIL}"

ensure_deploy_sa "${PROJECT_ID}" "${REGION}"

log "Creating the IAP service agent..."
ensure_iap_service_agent "${PROJECT_ID}"

# Creates a secret with an initial value. It never updates an existing secret.
# To change a value, add a version: gcloud secrets versions add NAME --data-file=-
ensure_secret() {
  local name="$1"
  local value="$2"
  if ! gcloud secrets describe "${name}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    echo -n "${value}" | gcloud secrets create "${name}" --project="${PROJECT_ID}" --data-file=- --quiet
  fi
  retry_iam gcloud secrets add-iam-policy-binding "${name}" \
    --member="serviceAccount:${RUNTIME_SA_EMAIL}" \
    --role="roles/secretmanager.secretAccessor" \
    --project="${PROJECT_ID}" \
    --quiet
}

JWT="$(openssl rand -hex 32)"
ensure_secret checklist-oauth-client-id "PLACEHOLDER"
ensure_secret checklist-oauth-client-secret "PLACEHOLDER"
ensure_secret checklist-jwt-secret "${JWT}"
ensure_secret checklist-workspace-domain "${WORKSPACE_DOMAIN}"
ensure_secret checklist-allowed-domains "${ALLOWED_DOMAINS}"

SA_CLIENT_ID="$(gcloud iam service-accounts describe "${RUNTIME_SA_EMAIL}" --project="${PROJECT_ID}" --format='value(uniqueId)')"

log ""
log "Bootstrap complete."
log "Runtime SA:     ${RUNTIME_SA_EMAIL}"
log "Build SA:       ${DEPLOY_SA}@${PROJECT_ID}.iam.gserviceaccount.com"
log "SA client ID:   ${SA_CLIENT_ID}"
log "Bucket:         gs://${CHECKLIST_BUCKET}"
log ""
log "Next (manual, once):"
log "  1. Create an OAuth Web client for this app (internal consent, identity scopes only)."
log "  2. Store client id/secret in checklist-oauth-client-id / checklist-oauth-client-secret."
log "  3. Authorize DWD for SA client ID ${SA_CLIENT_ID} with:"
log "       ${DWD_SCOPES}"
log "  4. Create a Google Group for people who may reach the app (IAP). Add the super admins who run the checklist."
log "  5. Run: PROJECT_ID=${PROJECT_ID} IAP_ACCESS_GROUP=group@yourcompany.com bash scripts/deploy.sh"
log "  6. Add the printed /api/auth/callback URL to the OAuth client."
log ""
log "Upgrading from 1.0.0? After the first successful deploy with this script, clean up the old project setup."
log "See docs/DEPLOY.md (Upgrade from 1.0.0)."
