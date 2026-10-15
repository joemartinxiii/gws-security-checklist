# Security

GWS Security is one Cloud Run service. The browser OAuth client identifies the person. Every Workspace API call uses domain-wide delegation. The runtime service account has no key file. Cloud Run asks the IAM Credentials API to sign the delegation token, and that token acts as the admin who signed in.

Create the OAuth client and the domain-wide delegation client ID for this app. Do not point them at another product.

## Who can sign in

The account must be a Google Workspace admin (super admin or delegated admin) in an allowed domain. Allowed domains are `WORKSPACE_DOMAIN` plus `GWS_ALLOWED_DOMAINS`. If no domain is configured, sign-in fails closed.

## Who can do what

| Action | Who |
|--------|-----|
| View the last checklist run and waivers | Any Workspace admin |
| Download the checklist CSV or PDF | Any admin (built in the browser from the loaded run) |
| Open the 2FA report and download its CSV | Any admin |
| Run the checklist | Super admin |
| Waive or restore a check | Super admin |
| Save a CSV to that admin’s Drive | Super admin |

The API enforces this with `requireAnyAdmin` and `requireSuperAdmin`. Hiding a button is not the control.

## Scopes

Domain-wide delegation scopes live in `scripts/lib/scopes.sh` and `backend/src/config/google.config.ts`. `npm run check:scopes` checks that they match.

- `https://www.googleapis.com/auth/admin.directory.user.readonly`
- `https://www.googleapis.com/auth/cloud-identity.policies.readonly`
- `https://www.googleapis.com/auth/chrome.management.policy.readonly`
- `https://www.googleapis.com/auth/drive.file`

`drive.file` can create the export file. It does not grant access to the rest of Drive.

The browser consent screen is `openid`, `userinfo.email`, and `userinfo.profile`.

## Session and errors

The session is an HttpOnly cookie. Each request replaces it. The cookie expires 15 minutes after the last request (`IDLE_TIMEOUT`). It also ends 8 hours after sign-in (`JWT_EXPIRES_IN`), even if the admin is still working. The OAuth callback does not put tokens in the query string. In production, CORS allows only `CORS_ORIGIN`.

`/health` returns `{ status, timestamp }`.

CSV downloads prefix a cell that starts with `=`, `+`, `-`, `@`, or a tab, so a spreadsheet treats a display name as text.

## What is stored

The last successful run and the waivers are JSON objects in `CHECKLIST_BUCKET`:

`gs://<project>-security-checklist/security-checklist/latest.json`
`gs://<project>-security-checklist/security-checklist/waivers.json`

The bucket is created with uniform access, public access prevention, and object versioning. Do not commit `.env` files, keys, or real tenant names.
