# AGENTS.md

Sibling of GWS Admin Assist. Security Checklist only — no users/groups/Drive/calendar admin surfaces.

- UI-only demo: `npm run dev:frontend:msw`
- Full stack needs env **before** node starts (`JWT_SECRET` is read at import time).
- DWD scopes: `scripts/lib/scopes.sh` and `backend/src/config/google.config.ts` — `npm run check:scopes`.
- Session files (`todos.md`, `tech-debt.md`, `docs/session/`) are private and gitignored.
