# AGENTS.md

GWS Security is a Google Workspace security checklist. It is this repo only: checklist, waivers, exports, and the 2FA user report. No user, group, Drive, or calendar admin screens.

- UI-only demo: `npm run dev:frontend:msw`
- Full stack needs env **before** node starts (`JWT_SECRET` is read at import time). `backend/src/bootstrap-env.ts` loads `backend/.env`.
- DWD scopes: `scripts/lib/scopes.sh` and `backend/src/config/google.config.ts` — `npm run check:scopes`.
- Deploy: `scripts/deploy.sh` needs `IAP_ACCESS_GROUP` (or `ALLOW_PUBLIC_INGRESS=1`). Builds run as `security-checklist-deploy-sa` through `cloudbuild.yaml`. Secrets are pinned to version numbers at deploy time. `GOOGLE_REDIRECT_URI` is a plain env var. The service starts without it, and sign-in returns 503 until deploy sets it.
- Lint: `npm run lint`. E2E: `npm run test:e2e` (starts the MSW UI).
- Session files (`todos.md`, `tech-debt.md`, `docs/session/`) are private and gitignored.
