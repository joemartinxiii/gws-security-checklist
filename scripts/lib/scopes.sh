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
)

# Secret Manager secret names used by Cloud Run.
# NOTE: no service-account-key — domain-wide delegation is keyless.
APP_SECRETS=(
  checklist-oauth-client-id
  checklist-oauth-client-secret
  checklist-oauth-redirect-uri
  checklist-jwt-secret
  checklist-workspace-domain
  checklist-allowed-domains
)

RUNTIME_SA="security-checklist-sa"
DEPLOY_SA="security-checklist-deploy-sa"
ARTIFACT_REPO="security-checklist-repo"
CLOUD_RUN_SERVICE="security-checklist"
DEFAULT_REGION="us-central1"
