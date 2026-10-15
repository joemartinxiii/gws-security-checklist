#!/usr/bin/env bash
# Single source of truth for OAuth consent and DWD scope strings.
# Keep SERVICE_ACCOUNT scopes in sync with backend/src/config/google.config.ts — run: npm run check:scopes

# Domain-wide delegation (service account client_id in admin.google.com)
DWD_SCOPES="https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/chrome.management.policy.readonly,https://www.googleapis.com/auth/cloud-identity.policies.readonly,https://www.googleapis.com/auth/drive.file"

# OAuth consent screen (browser sign-in — identity only; Workspace APIs use DWD)
OAUTH_CONSENT_SCOPES="openid,https://www.googleapis.com/auth/userinfo.email,https://www.googleapis.com/auth/userinfo.profile"

# APIs to enable
GCP_APIS=(
  run.googleapis.com
  secretmanager.googleapis.com
  cloudbuild.googleapis.com
  artifactregistry.googleapis.com
  iamcredentials.googleapis.com
  storage.googleapis.com
  admin.googleapis.com
  drive.googleapis.com
  chromepolicy.googleapis.com
  cloudidentity.googleapis.com
  iap.googleapis.com
)

# Secret Manager secret names used by Cloud Run, as ENV_NAME:secret-name.
# deploy.sh pins each one to its latest enabled version number.
# NOTE: no service-account-key. Domain-wide delegation is keyless.
# NOTE: GOOGLE_REDIRECT_URI is a plain env var (the service URL), not a secret.
# Delete the old checklist-oauth-redirect-uri secret after the first deploy with this script.
APP_SECRETS=(
  GOOGLE_CLIENT_ID:checklist-oauth-client-id
  GOOGLE_CLIENT_SECRET:checklist-oauth-client-secret
  JWT_SECRET:checklist-jwt-secret
  WORKSPACE_DOMAIN:checklist-workspace-domain
  GWS_ALLOWED_DOMAINS:checklist-allowed-domains
)

RUNTIME_SA="security-checklist-sa"
# Cloud Build runs as this service account (not the default compute account).
DEPLOY_SA="security-checklist-deploy-sa"
ARTIFACT_REPO="security-checklist-repo"
CLOUD_RUN_SERVICE="security-checklist"
DEFAULT_REGION="us-central1"
