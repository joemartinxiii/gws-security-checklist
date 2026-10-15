# AGENTS.md

GWS Security is a Google Workspace security checklist. It is this repo only: checklist, waivers, exports, and the 2FA user report. No user, group, Drive, or calendar admin screens.

- UI-only demo: `npm run dev:frontend:msw`
- Full stack needs env **before** node starts (`JWT_SECRET` is read at import time). `backend/src/bootstrap-env.ts` loads `backend/.env`.
- DWD scopes: `scripts/lib/scopes.sh` and `backend/src/config/google.config.ts` — `npm run check:scopes`.
- Session files (`todos.md`, `tech-debt.md`, `docs/session/`) are private and gitignored.
