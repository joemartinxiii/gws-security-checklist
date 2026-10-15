# Local development

## UI only

This mode does not talk to Google. It is the way to click through the checklist and the 2FA report.

```bash
npm install
npm run dev:frontend:msw
```

Vite serves http://localhost:3000. The mock signs you in as a super admin and answers `/api/*` with sample checks and sample users.

## Full stack

Use this when you want the local API to call a real Workspace tenant. Finish [DEPLOY_LOCAL.md](./DEPLOY_LOCAL.md) or [DEPLOY_CLOUD_SHELL.md](./DEPLOY_CLOUD_SHELL.md) first, or create the same OAuth client and domain-wide delegation for a local redirect URI of `http://localhost:5001/api/auth/callback`.

`backend/src/bootstrap-env.ts` loads `backend/.env` before the server reads `JWT_SECRET`. Put secrets in `backend/.env`. That file is gitignored, and so is every `.env.*` file except `.env.example`. Do not commit them.

```bash
npm run dev
```

- API: http://localhost:5001
- App: http://localhost:3000 (Vite proxies `/api` to port 5001)

`npx dotenv -e backend/.env -- npm run dev` also works. Values already in the process environment win over the file.

Live Google calls also need Application Default Credentials:

```bash
gcloud auth application-default login
```

Without the OAuth client, domain-wide delegation, and those credentials, use the UI-only command above.

## Lint and end-to-end tests

`npm run lint` lints the backend and the frontend. The frontend lint fails on any warning (`--max-warnings 0`). CI runs it on every pull request.

`npm run test:e2e` (or `npx playwright test`) runs the browser tests in `tests/e2e/`. Playwright starts the mock UI (`npm run dev:frontend:msw`) on http://localhost:3000 and reuses it if it is already running. No Google credentials are needed. Install the browser once:

```bash
npx playwright install chromium
```

To test a server that is already running, set `E2E_BASE_URL`. Playwright then skips the mock UI:

```bash
E2E_BASE_URL=http://localhost:5001 npx playwright test
```

## Commands

| Command | What it does |
|---------|----------------|
| `npm run dev:frontend:msw` | Checklist UI with sample data |
| `npm run dev` | API and UI together |
| `npm run lint` | ESLint on backend and frontend |
| `npm run type-check:all` | Typecheck backend and frontend |
| `npm test` | Backend tests |
| `npm run test:e2e` | Playwright tests against the mock UI |
| `npm run check:scopes` | Confirm the scope list in code matches `scripts/lib/scopes.sh` |
| `npm audit --omit=dev --audit-level=high` | Fail on high or critical advisories in production dependencies |
