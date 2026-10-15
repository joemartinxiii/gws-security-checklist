# Security

GWS Security is one Cloud Run service. Identity-Aware Proxy (IAP) sits in front of it. The browser OAuth client identifies the person. Every Workspace API call uses domain-wide delegation. The runtime service account has no key file. Cloud Run asks the IAM Credentials API to sign the delegation token, and that token acts as the admin who signed in.

Create the OAuth client and the domain-wide delegation client ID for this app. Do not point them at another product.

## Layers in front of the app

1. **IAP.** `scripts/deploy.sh` turns on IAP on the Cloud Run service and keeps the Cloud Run invoker IAM check on. Only members of `IAP_ACCESS_GROUP` reach the app. IAP uses a Google-managed OAuth client that admits only users in the project's organization. The deploy stops if you set neither `IAP_ACCESS_GROUP` nor `ALLOW_PUBLIC_INGRESS=1`. The second value turns IAP off and is for tests and rollbacks only. See [docs/DEPLOY.md](docs/DEPLOY.md#access-through-iap).
2. **App sign-in.** The person must be a Workspace admin in an allowed domain (next section).
3. **Per-action checks.** The API checks the role on each route.

## Who can sign in

The account must be a Google Workspace admin (super admin or delegated admin) in an allowed domain. Allowed domains are `WORKSPACE_DOMAIN` plus `GWS_ALLOWED_DOMAINS`. If no domain is configured, sign-in fails closed.

A delegated admin needs the **Users read** privilege to sign in. Anyone else sees "not an admin".

Sign-in uses PKCE. The callback verifies the ID token's `hd` (hosted domain) and `email_verified` claims before it looks up the admin.

Until `GOOGLE_REDIRECT_URI` is set, sign-in answers 503 ("Sign-in is not set up yet"). The service still starts. `deploy.sh` sets the variable after the service URL is known.

The service logs the email of each denied sign-in to Cloud Logging. Treat those logs as containing personal data, and set a retention period that fits your policy.

## Who can do what

| Action | Who |
|--------|-----|
| View the last checklist run and waivers | Super admin, and emails listed in `GWS_AUDIT_READERS` |
| Download the checklist CSV | Super admin, and emails listed in `GWS_AUDIT_READERS` |
| Download the checklist PDF | Anyone who can view the last run (built in the browser from the loaded run) |
| Open the 2FA report and download its CSV | Any admin |
| Run the checklist | Super admin |
| Waive or restore a check | Super admin. A waiver needs a reason (1000 characters max). |
| Save a CSV to that admin’s Drive | Super admin |

`GWS_AUDIT_READERS` is a comma-separated list of emails. Set it in your shell when you run `deploy.sh`. Those readers must still be Workspace admins who can sign in.

The API enforces this with `requireAnyAdmin` and `requireSuperAdmin` and the audit-reader check. Hiding a button is not the control.

## Scopes

Domain-wide delegation scopes live in `scripts/lib/scopes.sh` and `backend/src/config/google.config.ts`. `npm run check:scopes` checks that they match.

- `https://www.googleapis.com/auth/admin.directory.user.readonly`
- `https://www.googleapis.com/auth/cloud-identity.policies.readonly`
- `https://www.googleapis.com/auth/chrome.management.policy.readonly`
- `https://www.googleapis.com/auth/drive.file`

`drive.file` can create the export file. It does not grant access to the rest of Drive.

The browser consent screen is `openid`, `userinfo.email`, and `userinfo.profile`.

## What domain-wide delegation allows

The scope list limits what the service account can do. It does not limit who the service account can act as. Domain-wide delegation lets it impersonate any user in the Workspace. Only the app code limits it to the admin who signed in.

Anyone who can run code as the runtime service account can bypass that code. That includes anyone who can deploy a revision as the account (project Editor, or `roles/run.developer` plus `roles/iam.serviceAccountUser`) and anyone who holds `roles/iam.serviceAccountTokenCreator` on it. They can:

- read the Directory as a super admin, including 2-step status for every user
- read every policy the app can read
- create and share Drive files in any user’s My Drive
Reduce the risk:

- Use a dedicated Google Cloud project for this app.
- Keep few principals on the project. Prefer groups, and review the list.
- Enforce the `iam.disableServiceAccountKeyCreation` organization policy. The app needs no key.
- Turn on Data Access audit logs for the IAM API, and alert on IAM Credentials `SignJwt` calls for the runtime service account that do not come from the account itself, or that spike above normal use.
- Keep IAP on, and keep `IAP_ACCESS_GROUP` small.

[docs/DEPLOY.md](docs/DEPLOY.md#protect-the-runtime-service-account) has the procedure and the log filter.

## Session and errors

The session is an HttpOnly cookie signed with HS256. Each admin has one session, stored next to the checklist snapshot. The session rotates every 5 minutes, not on every request. Logout deletes the stored session, so a copied cookie stops working. The cookie expires 15 minutes after the last request (`IDLE_TIMEOUT`). It also ends 1 hour after sign-in (`JWT_EXPIRES_IN`), even if the admin is still working. The OAuth callback does not put tokens in the query string.

In production, the API refuses bearer tokens and accepts only the session cookie. A request that changes data (POST, PUT, DELETE) must come from the app's own origin. In production, CORS allows only `CORS_ORIGIN`.

`/health` returns `{ status, timestamp }`. With IAP on, `/health` is behind IAP too.

CSV downloads prefix a cell that starts with `=`, `+`, `-`, `@`, or a tab, so a spreadsheet treats a display name as text.

## Secrets

The OAuth client id and secret, the session secret, and the domain lists are in Secret Manager. `deploy.sh` pins each one to a version number, so a change takes effect on the next deploy. See [Change a secret](docs/DEPLOY.md#change-a-secret). Rotating `checklist-jwt-secret` signs everyone out.

The OAuth redirect URI is the service URL plus `/api/auth/callback`. It is a plain env var, `GOOGLE_REDIRECT_URI`, not a secret. Production startup does not require it. On a first deploy, and when upgrading a 1.0.0 service that still reads it from `checklist-oauth-redirect-uri`, `deploy.sh` sets the plain value in a follow-up update. Sign-in returns 503 until that update lands. Keep the old secret until you will not roll back to 1.0.0. That revision still reads it.

## What is stored

The last successful run and the waivers are JSON objects in `CHECKLIST_BUCKET`:

`gs://<project>-security-checklist/security-checklist/latest.json`
`gs://<project>-security-checklist/security-checklist/waivers.json`

The bucket is created with uniform access, public access prevention, and object versioning. A lifecycle rule deletes noncurrent versions 30 days after they stop being current. Do not commit `.env` files, keys, or real tenant names. `.gitignore` and `.gcloudignore` exclude every `.env.*` file except `.env.example`.

Builds run as a dedicated service account with access to one repository and the source bucket only. See [Cloud Build account](docs/DEPLOY.md#cloud-build-account).
