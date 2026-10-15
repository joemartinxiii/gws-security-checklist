# Changelog

## 1.0.0 — 2026-10-15

First public release.

- An admin signs in and runs a Workspace security checklist. Each control has a severity, the current value, and a recommended value.
- The checklist reads Workspace policies, DNS mail records, Chrome browser policy, and Directory 2-step verification.
- A setting with no saved admin policy is scored from Google’s published default when that default is documented.
- A super admin can waive a check, export CSV or PDF, and save a CSV to Drive. Any admin in an allowed domain can view the last run.
- The 2FA report lists each user’s name, email, enrollment, and enforcement.
- The session cookie expires 15 minutes after the last request, and 1 hour after sign-in. Logout revokes a copied cookie.
- Install on a Mac, on Windows with Git Bash, or in Google Cloud Shell. Update a running install with `git pull` and `scripts/deploy.sh`.
