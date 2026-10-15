#!/usr/bin/env bash
# Build the container with Cloud Build and deploy the security-checklist Cloud Run service.
#
# Usage:
#   PROJECT_ID=your-gcp-project-id bash scripts/deploy.sh
#
# Optional:
#   REGION=us-central1
#   CHECKLIST_BUCKET=<project>-security-checklist

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "${ROOT}/scripts/lib/common.sh"
# shellcheck source=scripts/lib/scopes.sh
source "${ROOT}/scripts/lib/scopes.sh"

require_cmd gcloud

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || true)}"
[[ -n "${PROJECT_ID}" && "${PROJECT_ID}" != "(unset)" ]] || die "Set PROJECT_ID or gcloud config set project"
REGION="${REGION:-${DEFAULT_REGION}}"
RUNTIME_SA_EMAIL="${RUNTIME_SA}@${PROJECT_ID}.iam.gserviceaccount.com"
CHECKLIST_BUCKET="${CHECKLIST_BUCKET:-${PROJECT_ID}-security-checklist}"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${ARTIFACT_REPO}/${CLOUD_RUN_SERVICE}:$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || echo latest)"

log "Project: ${PROJECT_ID}"
log "Region:  ${REGION}"
log "Service: ${CLOUD_RUN_SERVICE}"
log "Image:   ${IMAGE}"
log "Bucket:  ${CHECKLIST_BUCKET}"

gcloud services enable "${GCP_APIS[@]}" --project="${PROJECT_ID}" --quiet

if ! gcloud artifacts repositories describe "${ARTIFACT_REPO}" --location="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  log "Creating Artifact Registry repo ${ARTIFACT_REPO}..."
  gcloud artifacts repositories create "${ARTIFACT_REPO}" \
    --repository-format=docker \
    --location="${REGION}" \
    --project="${PROJECT_ID}" \
    --quiet
fi

if ! gcloud iam service-accounts describe "${RUNTIME_SA_EMAIL}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  log "Creating runtime service account ${RUNTIME_SA_EMAIL}..."
  gcloud iam service-accounts create "${RUNTIME_SA}" \
    --display-name="Security Checklist runtime" \
    --project="${PROJECT_ID}"
fi

# Keyless DWD: the runtime SA must be able to signJwt as itself.
gcloud iam service-accounts add-iam-policy-binding "${RUNTIME_SA_EMAIL}" \
  --member="serviceAccount:${RUNTIME_SA_EMAIL}" \
  --role="roles/iam.serviceAccountTokenCreator" \
  --project="${PROJECT_ID}" \
  --quiet >/dev/null

revoke_project_run_invoker "${PROJECT_ID}" "serviceAccount:${RUNTIME_SA_EMAIL}"

log "Ensuring bucket gs://${CHECKLIST_BUCKET}..."
ensure_checklist_bucket "${PROJECT_ID}" "${CHECKLIST_BUCKET}" "${REGION}" "serviceAccount:${RUNTIME_SA_EMAIL}"

log "Building image..."
gcloud builds submit "${ROOT}" \
  --project="${PROJECT_ID}" \
  --tag "${IMAGE}" \
  --quiet

log "Deploying Cloud Run service..."
gcloud run deploy "${CLOUD_RUN_SERVICE}" \
  --image "${IMAGE}" \
  --platform managed \
  --region "${REGION}" \
  --project="${PROJECT_ID}" \
  --memory 1Gi \
  --cpu 1 \
  --min-instances 0 \
  --max-instances 2 \
  --timeout 300 \
  --service-account "${RUNTIME_SA_EMAIL}" \
  --set-env-vars "NODE_ENV=production,GCP_PROJECT_ID=${PROJECT_ID},SERVICE_ACCOUNT_EMAIL=${RUNTIME_SA_EMAIL},CHECKLIST_BUCKET=${CHECKLIST_BUCKET}" \
  --set-secrets "GOOGLE_CLIENT_ID=checklist-oauth-client-id:latest,GOOGLE_CLIENT_SECRET=checklist-oauth-client-secret:latest,GOOGLE_REDIRECT_URI=checklist-oauth-redirect-uri:latest,JWT_SECRET=checklist-jwt-secret:latest,WORKSPACE_DOMAIN=checklist-workspace-domain:latest,GWS_ALLOWED_DOMAINS=checklist-allowed-domains:latest" \
  --allow-unauthenticated \
  --quiet

SERVICE_URL="$(gcloud run services describe "${CLOUD_RUN_SERVICE}" --region "${REGION}" --project="${PROJECT_ID}" --format='value(status.url)')"
REDIRECT_URI="${SERVICE_URL}/api/auth/callback"

if gcloud secrets describe checklist-oauth-redirect-uri --project="${PROJECT_ID}" >/dev/null 2>&1; then
  echo -n "${REDIRECT_URI}" | gcloud secrets versions add checklist-oauth-redirect-uri --project="${PROJECT_ID}" --data-file=- --quiet
  # value(name) is the full resource name (projects/.../versions/N). Cloud Run
  # accepts only the version number or "latest".
  REDIRECT_RESOURCE="$(gcloud secrets versions list checklist-oauth-redirect-uri --project="${PROJECT_ID}" --filter='state:enabled' --sort-by=~createTime --format='value(name)' --limit=1)"
  REDIRECT_VER="${REDIRECT_RESOURCE##*/}"
  [[ "${REDIRECT_VER}" =~ ^[0-9]+$ ]] || die "Could not resolve checklist-oauth-redirect-uri version from '${REDIRECT_RESOURCE}'"
  log "Updating service with CORS_ORIGIN and redirect secret version ${REDIRECT_VER}..."
  if ! gcloud run services update "${CLOUD_RUN_SERVICE}" \
    --region "${REGION}" --project="${PROJECT_ID}" \
    --set-env-vars "NODE_ENV=production,GCP_PROJECT_ID=${PROJECT_ID},SERVICE_ACCOUNT_EMAIL=${RUNTIME_SA_EMAIL},CORS_ORIGIN=${SERVICE_URL},CHECKLIST_BUCKET=${CHECKLIST_BUCKET}" \
    --update-secrets "GOOGLE_REDIRECT_URI=checklist-oauth-redirect-uri:${REDIRECT_VER}" \
    --quiet; then
    die "Cloud Run is up, but sign-in is not configured. CORS_ORIGIN and the callback secret were not applied. Re-run deploy.sh."
  fi
else
  die "Secret checklist-oauth-redirect-uri is missing. Run scripts/bootstrap.sh first."
fi

log ""
log "Deployed: ${SERVICE_URL}"
log "Health:   ${SERVICE_URL}/health"
log ""
log "DWD scopes (paste in admin.google.com → Security → API controls → Domain-wide delegation):"
log "  ${DWD_SCOPES}"
log "OAuth redirect URI to add on the Web client:"
log "  ${REDIRECT_URI}"
