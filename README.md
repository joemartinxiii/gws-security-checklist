# GWS Security

GWS Security is a Google Workspace security checklist. An admin signs in, runs the checklist against their own tenant, and gets a score, a finding for each control, and a way to export the result.

The main page is the **Security Checklist**. It reads Workspace policies, DNS mail records, Chrome browser policy, and Directory 2-step verification. Each check has a severity, the current value, and a recommended value. Info and manual checks are shown, and they are left out of the score. A super admin can waive a check with a reason. The last run and the waivers are saved for the organization.

Open **2-Step Verification** and choose **2FA Report** for a user list: name, email, whether 2-step is enrolled, and whether it is enforced. Export that list to CSV or Drive.

This is not Google Security Health, and it is not the personal Security Checkup. The check list follows Google’s published [Security checklists](https://knowledge.workspace.google.com/admin/security/security-checklists).

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
| Secret Manager | OAuth client, session secret, allowed domain |

Setup for your own Workspace is in [docs/DEPLOY.md](docs/DEPLOY.md).

## Try the UI without a tenant

```bash
npm install
npm run dev:frontend:msw
```

Opens http://localhost:3000 as a mock super admin with sample checks and sample users. No Google credentials.

## Docs

- [docs/DEPLOY.md](docs/DEPLOY.md) — connect a GCP project and a Workspace tenant
- [docs/LOCAL_DEV.md](docs/LOCAL_DEV.md) — local UI and full stack
- [SECURITY.md](SECURITY.md) — who can sign in, scopes, storage
- [CHECKLIST.md](CHECKLIST.md) — check catalog and API
