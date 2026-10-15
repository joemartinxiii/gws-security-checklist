# GWS Security

GWS Security is a Google Workspace security checklist. An admin signs in, runs the checklist against their own tenant, and gets a score, a finding for each control, and a way to export the result.

The main page is the **Security Checklist**. It reads Workspace policies, DNS mail records, Chrome browser policy, and Directory 2-step verification. Each check has a severity, the current value, and a recommended value. Info and manual checks are shown, and they are left out of the score. The score is weighted by severity. A super admin can waive a check with a reason. The last run and the waivers are saved for the organization.

Open **2-Step Verification** and choose **2FA Report** for a user list: name, email, whether 2-step is enrolled, and whether it is enforced. Export that list to CSV or Drive.

This is not Google Security Health, and it is not the personal Security Checkup. The check list is based on Google’s published [Security checklists](https://knowledge.workspace.google.com/admin/security/security-checklists). It does not copy them. Most checks are automated, and some are manual because Google publishes no API for the setting. [CHECKLIST.md](CHECKLIST.md) lists each check. The DNS checks cover `WORKSPACE_DOMAIN` plus `GWS_ALLOWED_DOMAINS`, with the DKIM selectors in `DKIM_SELECTORS` (default `google`). The **Failing** tab includes manual checks, because they need review.

GWS Security is not made by or endorsed by Google. Google Workspace is a trademark of Google.

A passing score is a baseline review. It is not a certification that the tenant is secure.

## How it runs

One Cloud Run service serves the React app and the API. When nobody is using it, the service scales to zero.

Sign-in uses a Google OAuth Web client for identity only (email and profile). Workspace data is read with domain-wide delegation. The runtime service account has no downloaded key. Cloud Run asks Google to sign the delegation token.

| Piece | Role |
|-------|------|
| Browser | Checklist, 2FA report, CSV and PDF download |
| API | Run checks, save the last run and waivers, upload a CSV to Drive |
| Cloud Storage | `latest.json` and `waivers.json` |
| Identity-Aware Proxy | Admits only members of one Google Group to the service |
| Secret Manager | OAuth client, session secret, allowed domain |

Setup for your own Workspace:

- [On your Mac or Windows PC](docs/DEPLOY_LOCAL.md)
- [In Google Cloud Shell](docs/DEPLOY_CLOUD_SHELL.md)

Both guides deploy the same Cloud Run service. `scripts/deploy.sh` needs `IAP_ACCESS_GROUP`, a Google Group email whose members may reach the app. [docs/DEPLOY.md](docs/DEPLOY.md) is the short map, including the one command that updates an install that is already running.

## Try the UI without a tenant

```bash
npm install
npm run dev:frontend:msw
```

Opens http://localhost:3000 as a mock super admin with sample checks and sample users. No Google credentials.

## Lint and tests

```bash
npm run lint        # backend and frontend
npm test            # backend unit tests
npm run test:e2e    # Playwright, against the mock UI
```

`npm run test:e2e` starts the mock UI itself. Run `npx playwright install chromium` once first. See [docs/LOCAL_DEV.md](docs/LOCAL_DEV.md).

## Docs

- [docs/DEPLOY_LOCAL.md](docs/DEPLOY_LOCAL.md) — install on a Mac or Windows PC
- [docs/DEPLOY_CLOUD_SHELL.md](docs/DEPLOY_CLOUD_SHELL.md) — install in Google Cloud Shell
- [docs/DEPLOY.md](docs/DEPLOY.md) — which guide to use, and how to update
- [docs/LOCAL_DEV.md](docs/LOCAL_DEV.md) — local UI and full stack
- [SECURITY.md](SECURITY.md) — who can sign in, scopes, storage
- [CHECKLIST.md](CHECKLIST.md) — check catalog and API
