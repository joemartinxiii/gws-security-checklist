# Security Checklist

A standalone Google Workspace **Security Checklist** app. It runs the same hardening baseline as the Security Audit page in [GWS Admin Assist](https://github.com/joemartinxiii/GWS_AdminAssist): score, checks, waivers, and CSV/PDF/Drive export.

This repo is a **sibling product**. The engine and UI were copied once from Admin Assist, then this codebase is independent. Admin Assist keeps its own Security Audit page. There is no shared package.

Google’s published docs are [Security checklists](https://knowledge.workspace.google.com/admin/security/security-checklists). The closest Admin console analog is **Security health** (Enterprise-gated). This app is not Google Security Health and not personal **Security Checkup**.

## Stack

- Frontend: React + TypeScript + Vite + MUI
- Backend: Node + Express + TypeScript
- Auth: Google OAuth (identity only) + keyless domain-wide delegation
- Deploy: one Cloud Run service

## Local UI (no secrets)

```bash
npm install
npm run dev:frontend:msw
```

Opens http://localhost:3000 as a mock super admin.

## Full stack

See [docs/LOCAL_DEV.md](docs/LOCAL_DEV.md). Sign-in and live checks need OAuth credentials, a Workspace tenant with DWD, and Application Default Credentials.

## Docs

- [CHECKLIST.md](CHECKLIST.md) — check catalog and API
- [SECURITY.md](SECURITY.md) — auth, scopes, storage
- [docs/LOCAL_DEV.md](docs/LOCAL_DEV.md)
- [docs/DEPLOY.md](docs/DEPLOY.md)
