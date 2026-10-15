# Local development

## UI-only (no secrets)

```bash
npm install
npm run dev:frontend:msw
```

Vite on http://localhost:3000. MSW signs you in as a mock super admin and mocks `/api/*`, so the checklist page is fully interactive.

## Full stack

```bash
# backend/src/bootstrap-env.ts loads backend/.env before auth.service.ts
# reads JWT_SECRET. From backend/, the same file is ./.env.
npm run dev
```

`npx dotenv -e backend/.env -- npm run dev` also works. Values already in the process environment win over the file.

- Backend: http://localhost:5001
- Frontend: http://localhost:3000 (proxies `/api` → :5001)

`backend/.env` is gitignored. Never commit real secrets or tenant identifiers.

Sign-in and live Google API calls also need:

- OAuth Web client (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_REDIRECT_URI`)
- A Workspace tenant with domain-wide delegation for `security-checklist-sa`
- Application Default Credentials (`gcloud auth application-default login`)

Without those, use MSW mode.

## Useful commands

| Command | What it does |
|---------|----------------|
| `npm run type-check:all` | Backend + frontend `tsc --noEmit` |
| `npm test` | Backend Jest (store + hardening meta) |
| `npm run check:scopes` | DWD/OAuth strings match `scopes.sh` |
