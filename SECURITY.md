# Security

Security Checklist is a single Cloud Run service. Browser OAuth is **identity only**. All Workspace API calls use **keyless domain-wide delegation** (the runtime service account signs its own JWT via the IAM Credentials API). There is no service-account key file.

## Who can sign in

- The user must be a Google Workspace **admin** (super or delegated) in an allowed domain (`WORKSPACE_DOMAIN` ∪ `GWS_ALLOWED_DOMAINS`).
- Domain checks fail closed when no domains are configured (`isEmailInAllowedDomain`).

## Who can do what

| Action | Gate |
|--------|------|
| View last run + waivers | Any Workspace admin |
| CSV export (cached) | Any admin |
| Run checklist | Super admin |
| Set / remove waiver | Super admin |
| Export to Drive | Super admin |

Enforced server-side by `requireAnyAdmin` / `requireSuperAdmin`. Hiding a button in the UI is not a security control.

## DWD scopes

Keep these in sync in `scripts/lib/scopes.sh` and `backend/src/config/google.config.ts`. Run `npm run check:scopes`.

- `https://www.googleapis.com/auth/cloud-identity.policies.readonly`
- `https://www.googleapis.com/auth/chrome.management.policy`
- `https://www.googleapis.com/auth/admin.directory.user`
- `https://www.googleapis.com/auth/drive` (CSV upload only)

Browser OAuth: `openid`, `userinfo.email`, `userinfo.profile`.

## Tokens and transport

- Session is an HttpOnly cookie. OAuth callback returns no tokens in the query string.
- CORS is locked to `CORS_ORIGIN` in production.
- `/health` returns only `{ status, timestamp }`.

## Persistence

Last-run and waivers live in `CHECKLIST_BUCKET` (`gs://<project>-security-checklist/security-checklist/`). Do not commit `.env*` files, keys, or real tenant identifiers.

## Sibling product

This app was copied from GWS Admin Assist and then diverged. Do not reuse Admin Assist OAuth clients or DWD client IDs. Use a dedicated SA (`security-checklist-sa`) and the trimmed scope list above.
