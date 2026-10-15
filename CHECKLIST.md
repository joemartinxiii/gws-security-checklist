# Security Checklist

What this app checks, how it stores results, and how to run it.

Deploy and scopes: [docs/DEPLOY.md](docs/DEPLOY.md), [docs/DEPLOY_LOCAL.md](docs/DEPLOY_LOCAL.md), [docs/DEPLOY_CLOUD_SHELL.md](docs/DEPLOY_CLOUD_SHELL.md), [SECURITY.md](SECURITY.md).

The catalog is based on Google’s published [Security checklists](https://knowledge.workspace.google.com/admin/security/security-checklists). It is not a copy of them. Some items are automated, and the rest are manual. An automated check reads a setting through an API and scores it. A manual check tells the admin what to verify in the Admin console, and it is not scored. Most non-DNS settings are read from the **Cloud Identity Policy API**. Org-wide values come from the root organizational unit, using Google’s documented policy precedence. An override in a child unit counts only when its value differs from the root. When Google returns no saved policy, the check scores the published default and labels the current value “Google default.” Settings Google does not publish stay **manual**.

DNS checks cover `WORKSPACE_DOMAIN` plus every domain in `GWS_ALLOWED_DOMAINS`. The DKIM check looks up the selectors in `DKIM_SELECTORS` (default `google`).

Legend: **auto** (Policy API / DNS / Directory / Chrome Policy) · **manual** (verify in console)

When the Policy API is unavailable (API off, missing DWD scope, or caller not super admin), auto checks degrade to manual with a banner. The page still loads.

---

## Check catalog

### Administrator Accounts
- **Auto** `super-admin-count`: number of active super admin accounts
- **Auto** `admin-2sv`: 2-Step Verification enrollment for super admins and delegated admins
- **Auto** `super-admin-recovery`: whether super admins can recover their own accounts

### Authentication
- **Auto**: 2-Step Verification (Directory enrollment, paged). It reads the organization’s enforcement policy and excludes suspended users. The 2FA Report lists name, email, enrolled, and enforced.
- **Auto** `security-keys`: whether any org unit or group is limited to security keys or passkeys
- **Auto**: Strong password policy (`security.password`). It requires 12 or more characters.
- **Auto**: Advanced Protection Program

### Email
- **Auto**: SPF / DKIM / DMARC (DNS)
- **Auto** `dns-mx`: MX records point at Google (DNS)
- **Manual**: Email read receipts
- **Auto**: Mail delegation, confidential mode, restrict delivery, enhanced pre-delivery scanning, spam override lists, auto-forwarding, warn for external recipients
- **Auto**: Attachment safety, links/images, spoofing & authentication
- **Auto** `gmail-pop-imap`: POP and IMAP access
- **Auto** `gmail-comprehensive-storage`: comprehensive mail storage
- **Auto** `gmail-ip-allowlist`: Gmail IP allowlist

### Calendar
- **Auto**: Primary/secondary external sharing max, external invitation warning

### Google Drive
- **Auto**: External sharing, general access default, shared drive creation, Drive for desktop, Docs/Sheets add-ons, DLP (Enterprise if rules exist). Sharing suggestions use Google’s published suggestions default. Link sharing does not, because the published sharing-mode default is not confirmed.
- **Auto** `drive-external-warning`: warning when sharing outside the organization
- **Auto** `drive-publishing`: publishing files to the web
- **Auto** `drive-non-google-invites`: sharing invitations to people without a Google account
- **Auto** `drive-receive-external`: receiving files from outside the organization
- **Auto** `drive-shared-drive-move`: who can move shared-drive files into another organization
- **Manual**: Offline access (Google does not publish this setting)

### Groups
- **Auto** `groups-creation`: who can create groups
- **Auto** `groups-external-access`: external access to groups

### Chat
- **Auto** `chat-external`: external chat

### Chrome Browser
These checks use the Chrome Policy API. A Workspace with no managed browsers shows the API error. They replace the earlier browser-update and force-installed-extension checks.
- **Auto** `chrome-relaunch-notification`: relaunch notification for updates
- **Auto** `chrome-safe-browsing`: Safe Browsing protection level
- **Auto** `chrome-safe-browsing-bypass`: users bypassing Safe Browsing warnings
- **Auto** `chrome-password-manager`: Chrome password manager. Allowed is a pass. Blocked is a fail.
- **Auto** `chrome-download-restrictions`: download restrictions
- **Auto** `chrome-site-isolation`: site isolation
- **Auto** `chrome-allowed-domains`: allowed sign-in domains

### Alerts
- **Auto** `chrome-admin-alerts`: admin alerts (`rule.system_defined_alerts`). This check moved here from Chrome Managed Browsers.

### Login challenges & data download
- **Auto**: Login challenges / employee ID, Google Takeout, less secure apps
- **Manual**: Post-SSO verification (Google does not publish this setting)

### Apps Control
- **Manual**: Context-Aware Access (Enterprise)
- **Auto**: Core apps and additional apps, from saved `service_status` policies. No saved policy means Google defaults apply. It does not invent a service as on.
- **Auto** `third-party-apps`: access for third-party apps the organization has not configured

### Severity

Severity is how urgent the control is in a client review. It is separate from pass / fail.

| Severity | Use |
|----------|-----|
| Critical | Account takeover or domain spoofing with little legitimate reason to leave it weak: 2-Step Verification, SPF, DKIM, DMARC, attachment / link / spoofing protections |
| High | Material leak or a control that should be on, with a narrower exception: external-recipient warning, external Drive link sharing, default file access, pre-delivery scanning, spam bypass, Takeout, DLP, post-SSO, admin alerts, password strength |
| Medium | Real control with a common business exception, shown as info when the choice is org-dependent: automatic forwarding, mail delegation, calendar sharing, Drive desktop / offline / shared-drive creation, add-ons, core and additional apps |
| Low | Hygiene: read receipts, confidential mode, calendar external-guest warning, sharing suggestions, employee-ID login challenge, less secure apps |

Less secure apps is **low**. Automatic forwarding is **medium** and **info** when it is allowed. It is not scored as a fail.

---

## How to use (UI)

1. Open **Security Checklist** (`/`).
2. Page loads the **last saved org snapshot** (does not auto-run). A delegated admin who is not listed in `GWS_AUDIT_READERS` sees an explanation instead of the snapshot.
3. **Run checklist** (super admin) re-evaluates checks and writes `security-checklist/latest.json`.
4. Segments: **Overview**, **Passing**, **Failing**, **Waived**. The **Failing** tab lists failed and warning checks, and it also lists manual checks (they need review). It is sorted by severity, then by fail, warning, and manual. Waived checks move to **Waived**.
5. Each check has severity, rationale, and recommendation.
6. **Waive** (super admin) requires a reason, up to 1000 characters, stored in `security-checklist/waivers.json` (survives re-runs).
7. **Export** CSV and PDF are built in the browser from the loaded run. **Export to Drive** is super admin only. None of these call the Policy API again.
8. On **2-Step Verification**, **2FA Report** lists each user’s name, email, enrollment, and enforcement. Export that page to CSV or Drive.

---

## Storage

| Object | Purpose |
|--------|---------|
| `gs://<CHECKLIST_BUCKET>/security-checklist/latest.json` | Last successful run |
| `gs://<CHECKLIST_BUCKET>/security-checklist/waivers.json` | Durable waivers |

Local disk under `backend/data/security-checklist/` when the bucket is unset (dev).

The bucket keeps object versions. A lifecycle rule deletes noncurrent versions after 30 days.

---

## API

Stored results, waivers, and the CSV export are for super admins and for emails listed in `GWS_AUDIT_READERS`.

| Method | Path | Who | Behavior |
|--------|------|-----|----------|
| GET | `/api/audit/hardening` or `/latest` | Super admin or audit reader | Cached last run + waivers |
| POST | `/api/audit/hardening/run` | Super admin | Evaluate + persist |
| PUT/DELETE | `/api/audit/hardening/waivers/:checkId` | Super admin | Set or clear a waiver. A reason is required (1000 characters max). |
| POST | `/api/audit/hardening/waivers/import` | Super admin | Merge browser-local waivers once |
| GET | `/api/audit/hardening/export` | Super admin or audit reader | CSV from cache |
| POST | `/api/audit/hardening/export/drive` | Super admin | Drive upload from cache |
| GET | `/api/audit/2sv` | Any admin | Users with name, email, enrolled, enforced |
| POST | `/api/audit/2sv/export/drive` | Super admin | 2FA report CSV in that admin’s Drive |

The checklist page builds its CSV and PDF in the browser from the loaded run. The export routes above are the same data from the server.

### Status values

| Status | Meaning |
|--------|---------|
| `pass` | Meets recommendation |
| `warning` / `fail` | Issue or does not meet recommendation |
| `info` | Org-dependent; not scored |
| `manual` | Verify in Admin console |

### Score

The compliance percentage uses graded checks only (`pass`, `warning`, `fail`). Info, manual, and waived checks are left out. Each check is weighted by severity:

| Severity | Weight |
|----------|--------|
| Critical | 4 |
| High | 3 |
| Medium | 2 |
| Low | 1 |

A pass earns its full weight, a warning earns half, and a fail earns none. The percentage is the earned weight divided by the total weight of the graded checks.

---

## Requirements

- `https://www.googleapis.com/auth/cloud-identity.policies.readonly`
- `https://www.googleapis.com/auth/chrome.management.policy.readonly`
- `https://www.googleapis.com/auth/admin.directory.user.readonly`
- `https://www.googleapis.com/auth/drive.file` (export to Drive only)

Run the checklist as a Workspace **super admin**.

---

## Limitations

- Some settings are always manual (no Google API)
- DNS checks need outbound DNS from the service
- 2FA coverage pages through Directory users. A scan that hits the 50,000-user cap cannot pass. The 2FA Report uses the same cap.
- Enterprise-only features (DLP, CAA) may be unavailable on the SKU
