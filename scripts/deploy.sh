#!/usr/bin/env bash
# Build the container with Cloud Build and deploy the security-checklist Cloud Run service.
#
# Usage:
#   PROJECT_ID=your-gcp-project-id \
#   IAP_ACCESS_GROUP=checklist-admins@yourcompany.com \
#   bash scripts/deploy.sh
#
# Access control (set exactly one):
#   IAP_ACCESS_GROUP=<group email>  Identity-Aware Proxy (IAP) sits in front of the
#                                   service. Members of this Google Group can reach
#                                   the app. They still need to be Workspace admins
#                                   to sign in.
#   ALLOW_PUBLIC_INGRESS=1          No IAP. Anyone on the internet can reach the
#                                   sign-in page. Use only to roll back or to test.
#
# Optional:
#   REGION=us-central1
#   CHECKLIST_BUCKET=<project>-security-checklist
#   GWS_AUDIT_READERS=a@example.com,b@example.com   Emails that may read stored
#                                   results besides super admins
#   DKIM_SELECTORS=google,selector1   DKIM selectors to check (default: google)
#
# GWS_AUDIT_READERS and DKIM_SELECTORS are replaced on every deploy. Set them
# each time, or the service loses them.
#
# Secrets are pinned to the newest enabled version at deploy time. After you add
# a version with `gcloud secrets versions add`, run this script again.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
source "${ROOT}/scripts/lib/common.sh"
# shellcheck source=scripts/lib/scopes.sh
source "${ROOT}/scripts/lib/scopes.sh"

require_cmd gcloud

IAP_ACCESS_GROUP="${IAP_ACCESS_GROUP:-}"
ALLOW_PUBLIC_INGRESS="${ALLOW_PUBLIC_INGRESS:-}"

if [[ -n "${ALLOW_PUBLIC_INGRESS}" && "${ALLOW_PUBLIC_INGRESS}" != "1" ]]; then
  die "ALLOW_PUBLIC_INGRESS must be 1 or unset."
fi
if [[ "${ALLOW_PUBLIC_INGRESS}" == "1" && -n "${IAP_ACCESS_GROUP}" ]]; then
  die "Set IAP_ACCESS_GROUP or ALLOW_PUBLIC_INGRESS=1, not both."
fi
if [[ "${ALLOW_PUBLIC_INGRESS}" != "1" ]]; then
  [[ -n "${IAP_ACCESS_GROUP}" ]] || die "Access control is not set. Set IAP_ACCESS_GROUP=<group email> to put Identity-Aware Proxy in front of the service. To skip IAP and leave the service open to the internet, set ALLOW_PUBLIC_INGRESS=1. Nothing was built or deployed."
  [[ "${IAP_ACCESS_GROUP}" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || die "IAP_ACCESS_GROUP must be a Google Group email address, got '${IAP_ACCESS_GROUP}'."
fi

# Optional service env vars. Their values contain commas, so the deploy uses
# gcloud's alternate delimiter ("^|^", see `gcloud topic escaping`).
for optional in GWS_AUDIT_READERS DKIM_SELECTORS; do
  [[ "${!optional:-}" != *"|"* ]] || die "${optional} must not contain the '|' character."
done

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || true)}"
[[ -n "${PROJECT_ID}" && "${PROJECT_ID}" != "(unset)" ]] || die "Set PROJECT_ID or gcloud config set project"
REGION="${REGION:-${DEFAULT_REGION}}"
RUNTIME_SA_EMAIL="${RUNTIME_SA}@${PROJECT_ID}.iam.gserviceaccount.com"
DEPLOY_SA_EMAIL="${DEPLOY_SA}@${PROJECT_ID}.iam.gserviceaccount.com"
CHECKLIST_BUCKET="${CHECKLIST_BUCKET:-${PROJECT_ID}-security-checklist}"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${ARTIFACT_REPO}/${CLOUD_RUN_SERVICE}:$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || echo latest)"

log "Project: ${PROJECT_ID}"
log "Region:  ${REGION}"
log "Service: ${CLOUD_RUN_SERVICE}"
log "Image:   ${IMAGE}"
log "Bucket:  ${CHECKLIST_BUCKET}"
if [[ "${ALLOW_PUBLIC_INGRESS}" == "1" ]]; then
  log "Access:  PUBLIC (no IAP)"
  log ""
  log "WARNING: ALLOW_PUBLIC_INGRESS=1 turns IAP off and disables the Cloud Run invoker check."
  log "WARNING: Anyone on the internet can reach the sign-in page of this service."
  log "WARNING: Only the app's own admin sign-in stands between the internet and your tenant data."
  log ""
else
  log "Access:  IAP, group ${IAP_ACCESS_GROUP}"
fi

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

wait_for_service_account "${RUNTIME_SA_EMAIL}" "${PROJECT_ID}"

# Keyless DWD: the runtime SA must be able to signJwt as itself.
retry_iam gcloud iam service-accounts add-iam-policy-binding "${RUNTIME_SA_EMAIL}" \
  --member="serviceAccount:${RUNTIME_SA_EMAIL}" \
  --role="roles/iam.serviceAccountTokenCreator" \
  --project="${PROJECT_ID}" \
  --quiet

revoke_project_run_invoker "${PROJECT_ID}" "serviceAccount:${RUNTIME_SA_EMAIL}"

log "Ensuring bucket gs://${CHECKLIST_BUCKET}..."
ensure_checklist_bucket "${PROJECT_ID}" "${CHECKLIST_BUCKET}" "${REGION}" "serviceAccount:${RUNTIME_SA_EMAIL}"

require_deploy_sa "${PROJECT_ID}"

# Resolve secret versions before building, so a missing secret stops the run early.
SECRET_REFS=()
for entry in "${APP_SECRETS[@]}"; do
  env_name="${entry%%:*}"
  secret_name="${entry#*:}"
  secret_version="$(latest_secret_version "${secret_name}" "${PROJECT_ID}")"
  log "Secret:  ${env_name} = ${secret_name} version ${secret_version}"
  SECRET_REFS+=("${env_name}=${secret_name}:${secret_version}")
done
SECRETS_ARG="$(IFS=','; printf '%s' "${SECRET_REFS[*]}")"

# The redirect URI is the service URL plus /api/auth/callback. It is not a
# secret, so it is a plain env var. A service that already exists has a URL we
# can read now. On a first deploy, the app needs a value to start, so it gets a
# placeholder and the follow-up update below sets the real one.
EXISTING_URL="$(gcloud run services describe "${CLOUD_RUN_SERVICE}" --region "${REGION}" --project="${PROJECT_ID}" --format='value(status.url)' 2>/dev/null || true)"
ENV_VARS=(
  "NODE_ENV=production"
  "GCP_PROJECT_ID=${PROJECT_ID}"
  "SERVICE_ACCOUNT_EMAIL=${RUNTIME_SA_EMAIL}"
  "CHECKLIST_BUCKET=${CHECKLIST_BUCKET}"
)
if [[ -n "${EXISTING_URL}" ]]; then
  ENV_VARS+=("GOOGLE_REDIRECT_URI=${EXISTING_URL}/api/auth/callback" "CORS_ORIGIN=${EXISTING_URL}")
else
  ENV_VARS+=("GOOGLE_REDIRECT_URI=https://placeholder.invalid/api/auth/callback")
fi
[[ -z "${GWS_AUDIT_READERS:-}" ]] || ENV_VARS+=("GWS_AUDIT_READERS=${GWS_AUDIT_READERS}")
[[ -z "${DKIM_SELECTORS:-}" ]] || ENV_VARS+=("DKIM_SELECTORS=${DKIM_SELECTORS}")
ENV_ARG="^|^$(IFS='|'; printf '%s' "${ENV_VARS[*]}")"

log "Building image as ${DEPLOY_SA_EMAIL}..."
gcloud builds submit "${ROOT}" \
  --project="${PROJECT_ID}" \
  --config "${ROOT}/cloudbuild.yaml" \
  --substitutions "_IMAGE=${IMAGE}" \
  --service-account "projects/${PROJECT_ID}/serviceAccounts/${DEPLOY_SA_EMAIL}" \
  --gcs-source-staging-dir "gs://${PROJECT_ID}_cloudbuild/source" \
  --quiet

# Access control. The default is Identity-Aware Proxy (IAP) on the Cloud Run
# service, with the Cloud Run invoker IAM check on. IAP admits only the members
# of IAP_ACCESS_GROUP, and the app still requires a Workspace admin session.
# Pass --invoker-iam-check explicitly: a service deployed by an older version of
# this script has the check turned off, and a deploy does not turn it back on.
# ALLOW_PUBLIC_INGRESS=1 keeps the old public behavior (IAP off, invoker check
# off). It does not grant allUsers roles/run.invoker, which domain restricted
# sharing blocks.
if [[ "${ALLOW_PUBLIC_INGRESS}" == "1" ]]; then
  ACCESS_FLAGS=(--no-iap --no-invoker-iam-check)
else
  ACCESS_FLAGS=(--iap --invoker-iam-check --no-allow-unauthenticated)
fi

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
  --set-env-vars "${ENV_ARG}" \
  --set-secrets "${SECRETS_ARG}" \
  "${ACCESS_FLAGS[@]}" \
  --quiet

SERVICE_URL="$(gcloud run services describe "${CLOUD_RUN_SERVICE}" --region "${REGION}" --project="${PROJECT_ID}" --format='value(status.url)')"
[[ -n "${SERVICE_URL}" ]] || die "Could not read the service URL."
REDIRECT_URI="${SERVICE_URL}/api/auth/callback"

if [[ "${SERVICE_URL}" != "${EXISTING_URL}" ]]; then
  log "Setting GOOGLE_REDIRECT_URI and CORS_ORIGIN for ${SERVICE_URL}..."
  if ! gcloud run services update "${CLOUD_RUN_SERVICE}" \
    --region "${REGION}" --project="${PROJECT_ID}" \
    --update-env-vars "GOOGLE_REDIRECT_URI=${REDIRECT_URI},CORS_ORIGIN=${SERVICE_URL}" \
    --quiet; then
    die "Cloud Run is up, but sign-in is not configured. GOOGLE_REDIRECT_URI and CORS_ORIGIN were not applied. Re-run deploy.sh."
  fi
fi

if [[ "${ALLOW_PUBLIC_INGRESS}" != "1" ]]; then
  PROJECT_NUMBER="$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)')"
  IAP_AGENT="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-iap.iam.gserviceaccount.com"

  # The agent exists after bootstrap. Create it here too, in case bootstrap ran
  # before IAP support was added. Creating it again changes nothing.
  ensure_iap_service_agent "${PROJECT_ID}"

  log "Letting IAP invoke the service..."
  retry_iam gcloud run services add-iam-policy-binding "${CLOUD_RUN_SERVICE}" \
    --region "${REGION}" \
    --project="${PROJECT_ID}" \
    --member="${IAP_AGENT}" \
    --role="roles/run.invoker" \
    --quiet

  log "Letting group ${IAP_ACCESS_GROUP} through IAP..."
  retry_iam gcloud iap web add-iam-policy-binding \
    --resource-type=cloud-run \
    --service="${CLOUD_RUN_SERVICE}" \
    --region="${REGION}" \
    --project="${PROJECT_ID}" \
    --member="group:${IAP_ACCESS_GROUP}" \
    --role="roles/iap.httpsResourceAccessor" \
    --quiet
fi

log ""
log "Deployed: ${SERVICE_URL}"
log "Health:   ${SERVICE_URL}/health"
if [[ "${ALLOW_PUBLIC_INGRESS}" == "1" ]]; then
  log "Access:   PUBLIC. Re-run with IAP_ACCESS_GROUP set to put IAP back in front."
else
  log "Access:   IAP, group ${IAP_ACCESS_GROUP}"
  log "Note:     /health is behind IAP too. A signed-out request gets Google's sign-in page."
fi
log ""
log "DWD scopes (paste in admin.google.com → Security → API controls → Domain-wide delegation):"
log "  ${DWD_SCOPES}"
log "OAuth redirect URI to add on the Web client:"
log "  ${REDIRECT_URI}"
if gcloud secrets describe checklist-oauth-redirect-uri --project="${PROJECT_ID}" >/dev/null 2>&1; then
  log ""
  log "The secret checklist-oauth-redirect-uri is no longer used. After you confirm sign-in works, delete it:"
  log "  gcloud secrets delete checklist-oauth-redirect-uri --project=${PROJECT_ID}"
fi
