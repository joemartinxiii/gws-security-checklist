# Changelog

## Unreleased

## 1.1.0 — 2026-10-15

### Access and sign-in
- Identity-Aware Proxy (IAP) sits in front of the Cloud Run service. `scripts/deploy.sh` requires `IAP_ACCESS_GROUP`, turns on `--iap` with the invoker IAM check, and lets the IAP service agent and that group through. `ALLOW_PUBLIC_INGRESS=1` keeps the old public behavior and prints a warning. With neither set, the deploy stops before it builds.
- Stored results, waivers, and the CSV export are for super admins and for emails in `GWS_AUDIT_READERS`.
- A delegated admin needs the Users read privilege to sign in. Other accounts see "not an admin".
- Sign-in uses PKCE and checks the ID token's `hd` and `email_verified` claims.
- Production refuses bearer tokens. A request that changes data must come from the app's own origin.
- Sessions rotate every 5 minutes, not on every request.
- The service logs the email of each denied sign-in. SECURITY.md says so.
- A waiver needs a reason, up to 1000 characters. An empty reason is rejected. Importing old browser waivers uses "Imported from browser (no reason given)" when the saved reason was blank.
- A delegated admin who cannot read stored results sees an explanation. The page no longer looks like the checklist has never been run.
- Checklist rows open from the keyboard with Enter or Space.
- Sign-in returns 503 until `GOOGLE_REDIRECT_URI` is set. The service starts without it. On a first deploy, and when a 1.0.0 service still reads the redirect URI from a secret, `deploy.sh` sets the plain value in a follow-up update.

### Checks and score
- New checks. Administrator Accounts: `super-admin-count`, `admin-2sv`, `super-admin-recovery`. Authentication: `security-keys`. Email: `gmail-pop-imap`, `gmail-comprehensive-storage`, `gmail-ip-allowlist`, `dns-mx`. Apps Control: `third-party-apps`. Google Drive: `drive-external-warning`, `drive-publishing`, `drive-non-google-invites`, `drive-receive-external`, `drive-shared-drive-move`. Groups: `groups-creation`, `groups-external-access`. Chat: `chat-external`.
- Chrome Browser: seven checks replace the browser-updates and force-installed-extension checks: `chrome-relaunch-notification`, `chrome-safe-browsing`, `chrome-safe-browsing-bypass`, `chrome-password-manager`, `chrome-download-restrictions`, `chrome-site-isolation`, `chrome-allowed-domains`.
- `chrome-admin-alerts` moves to a new Alerts category.
- The 2-Step Verification check reads the organization enforcement policy and excludes suspended users. The password check requires 12 or more characters. Less Secure Apps drops to low severity.
- Org-wide values come from the root organizational unit, using Google's documented policy precedence. Overrides count only when values differ.
- The score is weighted by severity: critical 4, high 3, medium 2, low 1. A warning counts half.
- DNS checks cover `WORKSPACE_DOMAIN` plus `GWS_ALLOWED_DOMAINS`, with the selectors in `DKIM_SELECTORS` (default `google`).
- CHECKLIST.md and README.md now say the catalog is based on Google's checklists, and say which items are automated and which are manual.

### Deploy and operations
- Builds run as a dedicated service account, `security-checklist-deploy-sa`, with only the roles a build needs. `deploy.sh` passes it to `gcloud builds submit` with a new `cloudbuild.yaml` that logs to Cloud Logging only. Bootstrap no longer grants roles to the default compute account. DEPLOY.md shows how to remove the old grants.
- `GOOGLE_REDIRECT_URI` is a plain env var. The `checklist-oauth-redirect-uri` secret is no longer used. Delete it after the first deploy with this version. The deploy no longer adds a secret version on every run.
- `deploy.sh` pins each secret to its newest enabled version number. A secret change reaches the service on the next deploy. DEPLOY.md documents how to change allowed domains and rotate `JWT_SECRET`.
- `deploy.sh` passes `GWS_AUDIT_READERS` and `DKIM_SELECTORS` to the service when you set them.
- Bootstrap sets an Artifact Registry cleanup policy (keep the 3 newest images) and a bucket lifecycle rule (delete noncurrent versions after 30 days). The cleanup policy is applied with `--no-dry-run`, so it deletes images. The lifecycle file uses the documented `{"lifecycle": ...}` shape.
- The mock UI includes a row for every check the engine emits, except the error placeholders.
- Bootstrap enables `iap.googleapis.com` and creates the IAP service agent.
- DEPLOY.md, DEPLOY_LOCAL.md, and DEPLOY_CLOUD_SHELL.md describe IAP, the upgrade from 1.0.0, and the risk of domain-wide delegation. They correct the old claim that the service account works only while it acts as the signed-in admin. SECURITY.md adds hardening guidance: a dedicated project, few project principals, the `iam.disableServiceAccountKeyCreation` org policy, and an alert on `SignJwt` calls.

### Container, repo, and dependencies
- The runtime image installs backend production dependencies only, and the base image is pinned by digest.
- `.gitignore` ignores every `.env.*` file except `.env.example`. A new `.gcloudignore` keeps env files, test output, and local data out of Cloud Build uploads.
- `npm audit fix` and removal of the unused `@google-cloud/secret-manager` package cut production advisories from 18 to 9, with no critical or high ones left.
- CI uses `npm ci`, read-only permissions, actions pinned to commit SHAs, `npm run lint`, and `npm audit --omit=dev --audit-level=high`. Dependabot covers npm, GitHub Actions, and Docker weekly.
- `npm run lint` lints the backend and the frontend.
- Playwright starts the mock UI itself, so `npx playwright test` works locally. The placeholder live test and its config are gone.
- Comments in `backend/src/utils/email.ts` and `concurrency.ts` no longer describe another project.

### Follow-ups
- Upgrade `googleapis` (now 128) and `@google-cloud/storage` (now 7) to current majors. They hold the remaining production advisories.
- Upgrade `react-router-dom` to a patched major.
- Upgrade Vite (esbuild advisory) and Jest and ts-jest (dev-only advisories).

## 1.0.0 — 2026-10-15

First public release.

- An admin signs in and runs a Workspace security checklist. Each control has a severity, the current value, and a recommended value.
- The checklist reads Workspace policies, DNS mail records, Chrome browser policy, and Directory 2-step verification.
- A setting with no saved admin policy is scored from Google’s published default when that default is documented.
- A super admin can waive a check, export CSV or PDF, and save a CSV to Drive. Any admin in an allowed domain can view the last run.
- The 2FA report lists each user’s name, email, enrollment, and enforcement.
- The session cookie expires 15 minutes after the last request, and 1 hour after sign-in. Logout revokes a copied cookie.
- Install on a Mac, on Windows with Git Bash, or in Google Cloud Shell. Update a running install with `git pull` and `scripts/deploy.sh`.
