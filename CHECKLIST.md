# Security Checklist

What this app checks, how it stores results, and how to run it.

Deploy and scopes: [docs/DEPLOY.md](docs/DEPLOY.md), [SECURITY.md](SECURITY.md).

The catalog mirrors Google’s published [Security checklists](https://knowledge.workspace.google.com/admin/security/security-checklists). Most non-DNS settings are read from the **Cloud Identity Policy API**; others are **manual** (Admin console link) when Google has no API.

Legend: **auto** (Policy API / DNS / user proxy / Chrome Policy) · **manual** (verify in console)

When the Policy API is unavailable (API off, missing DWD scope, or caller not super admin), auto checks degrade to manual with a banner — the page still loads.

---

## Check catalog

### Authentication
- **Auto** — 2-Step Verification (enrollment rate proxy)
- **Auto** — Strong password policy (`security.password`)
- **Auto** — Advanced Protection Program

### Email
- **Auto** — SPF / DKIM / DMARC (DNS)
- **Manual** — Email read receipts
- **Auto** — Mail delegation, confidential mode, restrict delivery, enhanced pre-delivery scanning, spam override lists, auto-forwarding
- **Manual** — Warn for external recipients
- **Auto** — Attachment safety, links/images, spoofing & authentication

### Calendar
- **Auto** — Primary/secondary external sharing max, external invitation warning

### Drive
- **Auto** — External sharing, general access default, shared drive creation, Drive for desktop, DLP (Enterprise if rules exist)
- **Manual** — Offline access, Docs/Sheets add-ons

### Chrome managed browsers
- **Auto** — Browser updates, company-enforced extensions (Chrome Policy API)
- **Manual** — Admin alerts

### Login challenges & data download
- **Auto** — Login challenges / employee ID, Google Takeout, less secure apps
- **Manual** — Post-SSO verification

### Apps control
- **Manual** — Context-Aware Access, core apps, additional apps (per-OU decisions)

---

## How to use (UI)

1. Open **Security Checklist** (`/`).
2. Page loads the **last saved org snapshot** (does not auto-run).
3. **Run checklist** (super admin) re-evaluates checks and writes `security-checklist/latest.json`.
4. Segments: **Overview**, **Passing**, **Failing**, **Waived**. Failing is sorted by severity.
5. Each check has severity, rationale, and recommendation (for client walkthroughs).
6. **Waive** (super admin) stores an optional reason in `security-checklist/waivers.json` (survives re-runs).
7. **Export** CSV/PDF/Drive uses the **cached** last run + waivers (no extra Policy API hit).

---

## Storage

| Object | Purpose |
|--------|---------|
| `gs://<CHECKLIST_BUCKET>/security-checklist/latest.json` | Last successful run |
| `gs://<CHECKLIST_BUCKET>/security-checklist/waivers.json` | Durable waivers |

Local disk under `backend/data/security-checklist/` when the bucket is unset (dev).

---

## API

| Method | Path | Who | Behavior |
|--------|------|-----|----------|
| GET | `/api/audit/hardening` or `/latest` | Any admin | Cached last run + waivers |
| POST | `/api/audit/hardening/run` | Super admin | Evaluate + persist |
| PUT/DELETE | `/api/audit/hardening/waivers/:checkId` | Super admin | Set / clear waiver |
| POST | `/api/audit/hardening/waivers/import` | Super admin | Merge browser-local waivers once |
| GET | `/api/audit/hardening/export` | Any admin | CSV from cache |
| POST | `/api/audit/hardening/export/drive` | Super admin | Drive upload from cache |

Paths keep the Admin Assist `/audit/hardening` prefix so the ported page stays stable.

### Status values

| Status | Meaning |
|--------|---------|
| `pass` | Meets recommendation |
| `warning` / `fail` | Issue or does not meet recommendation |
| `info` | Org-dependent; not scored |
| `manual` | Verify in Admin console |

Compliance percentage uses graded checks only: `pass / (pass + warning + fail)`.

---

## Requirements

- `https://www.googleapis.com/auth/cloud-identity.policies.readonly`
- `https://www.googleapis.com/auth/chrome.management.policy`
- `https://www.googleapis.com/auth/admin.directory.user`
- `https://www.googleapis.com/auth/drive` (export to Drive only)

Run the checklist as a Workspace **super admin**.

---

## Limitations

- Some settings are always manual (no Google API)
- DNS checks need outbound DNS from the service
- 2FA coverage is a Directory sample proxy, not the full org 2SV schedule
- Enterprise-only features (DLP, CAA) may be unavailable on the SKU
