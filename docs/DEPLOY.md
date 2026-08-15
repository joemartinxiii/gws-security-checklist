# Deploy to Cloud Run

Security Checklist runs as **one Cloud Run service** (API + built React app). It can live in the **same GCP project** as GWS Admin Assist. Use a **new** OAuth client, a **new** DWD service account, and a **new** GCS bucket.

Local development: [LOCAL_DEV.md](./LOCAL_DEV.md). Security model: [SECURITY.md](../SECURITY.md).

## Prerequisites

| You need | Why |
|----------|-----|
| Workspace **Super Admin** | Domain-wide delegation in admin.google.com |
| GCP **Project Owner** (or equivalent) | Cloud Run, secrets, IAM |
| Billing on the GCP project | Cloud Run + Artifact Registry |

## First deploy

```bash
PROJECT_ID=your-gcp-project-id \
WORKSPACE_DOMAIN=yourcompany.com \
ALLOWED_DOMAINS=yourcompany.com \
bash scripts/bootstrap.sh
```

Then complete the console steps the script prints:

1. **OAuth consent + Web client** — identity scopes only. Do not reuse the Admin Assist client.
2. Store the client id/secret in Secret Manager (`checklist-oauth-client-id`, `checklist-oauth-client-secret`).
3. **Domain-wide delegation** — authorize the printed SA numeric client ID with the scopes in `scripts/lib/scopes.sh`.

```bash
PROJECT_ID=your-gcp-project-id bash scripts/deploy.sh
```

Add `https://<service-url>/api/auth/callback` to the OAuth client’s authorized redirect URIs, then sign in.

## Updates

Re-run `bash scripts/deploy.sh` from a machine with `gcloud` and Cloud Build permissions.

## Env / secrets

| Name | Role |
|------|------|
| `CHECKLIST_BUCKET` | GCS bucket for `latest.json` + `waivers.json` (default `<project>-security-checklist`) |
| `SECURITY_CHECKLIST_PREFIX` | Object prefix (default `security-checklist`) |
| `GOOGLE_CLIENT_*` | OAuth Web client |
| `JWT_SECRET` | Session signing |
| `WORKSPACE_DOMAIN` / `GWS_ALLOWED_DOMAINS` | Login gate |
| `SERVICE_ACCOUNT_EMAIL` | Runtime SA for keyless DWD |

## Service names

| Resource | Value |
|----------|--------|
| Cloud Run | `security-checklist` |
| Runtime SA | `security-checklist-sa` |
| Artifact Registry | `security-checklist-repo` |
| Bucket | `<project>-security-checklist` |
