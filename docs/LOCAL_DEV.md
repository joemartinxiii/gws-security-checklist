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

`backend/src/bootstrap-env.ts` loads `backend/.env` before the server reads `JWT_SECRET`. Put secrets in `backend/.env`. That file is gitignored. Do not commit it.

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

## Commands

| Command | What it does |
|---------|----------------|
| `npm run dev:frontend:msw` | Checklist UI with sample data |
| `npm run dev` | API and UI together |
| `npm run type-check:all` | Typecheck backend and frontend |
| `npm test` | Backend tests |
| `npm run check:scopes` | Confirm the scope list in code matches `scripts/lib/scopes.sh` |
