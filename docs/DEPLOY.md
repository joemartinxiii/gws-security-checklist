# Set up GWS Security on your Workspace

GWS Security runs as one Cloud Run service: the API and the built React app. You need a Google Cloud project with billing, and a Google Workspace tenant where you are a super admin.

The app creates its own service account, OAuth client secrets, and storage bucket. Use those only for this app.

Local development without a tenant: [LOCAL_DEV.md](./LOCAL_DEV.md). Who can sign in and which scopes are used: [SECURITY.md](../SECURITY.md).

## What you need

| You need | Why |
|----------|-----|
| Workspace **super admin** | Turn on domain-wide delegation in the Admin console |
| GCP project **Owner** (or the same rights) | Cloud Run, Secret Manager, IAM, the bucket |
| Billing on that GCP project | Cloud Run, Cloud Build, and Artifact Registry |

The Cloud Run service uses `--min-instances 0`. It does not keep an instance running when nobody is calling it.

## 1. Bootstrap the GCP project

From a machine where `gcloud` is logged in to the project:

```bash
PROJECT_ID=your-gcp-project-id \
WORKSPACE_DOMAIN=yourcompany.com \
ALLOWED_DOMAINS=yourcompany.com \
bash scripts/bootstrap.sh
```

`WORKSPACE_DOMAIN` is the Workspace primary domain. `ALLOWED_DOMAINS` is the comma-separated list of domains whose admins may sign in. For one domain, set both to that domain.

The script enables the APIs, creates the runtime service account `security-checklist-sa`, an Artifact Registry repo, the bucket `<project>-security-checklist`, and Secret Manager entries. It prints the service account’s numeric client ID and the exact scope list. Keep that output.

## 2. Create the OAuth Web client

In Google Cloud Console, for the same project:

1. Configure the OAuth consent screen as **Internal**.
2. Create an **OAuth client ID** of type **Web application** for this app.
3. The consent scopes are identity only: `openid`, `userinfo.email`, `userinfo.profile`. Do not add Workspace admin scopes on this client. Those are granted to the service account in the next step.
4. You will add the redirect URI after the first deploy. Leave it blank for now, or add it as soon as `deploy.sh` prints it.

Store the client id and secret:

```bash
echo -n 'YOUR_CLIENT_ID' | gcloud secrets versions add checklist-oauth-client-id --data-file=- --project=YOUR_PROJECT_ID
echo -n 'YOUR_CLIENT_SECRET' | gcloud secrets versions add checklist-oauth-client-secret --data-file=- --project=YOUR_PROJECT_ID
```

Do not leave the bootstrap value `PLACEHOLDER` in those two secrets.

## 3. Authorize domain-wide delegation

In the Workspace Admin console: **Security → Access and data control → API controls → Domain-wide delegation → Add new**.

- Client ID: the numeric service account client ID printed by `bootstrap.sh`
- Scopes: the comma-separated list printed by the script (the same list is in `scripts/lib/scopes.sh`)

Those scopes are:

- `https://www.googleapis.com/auth/admin.directory.user.readonly` — users and 2-step status
- `https://www.googleapis.com/auth/cloud-identity.policies.readonly` — most checklist settings
- `https://www.googleapis.com/auth/chrome.management.policy.readonly` — Chrome browser policy
- `https://www.googleapis.com/auth/drive.file` — create the export CSV in the signed-in admin’s Drive

The service account can read those APIs only while it is acting as a Workspace admin who signed in. It cannot change users, Chrome policies, or existing Drive files.

## 4. Deploy

```bash
PROJECT_ID=your-gcp-project-id bash scripts/deploy.sh
```

The script builds the image, deploys Cloud Run service `security-checklist`, and prints the service URL. It writes `https://<service-url>/api/auth/callback` into `checklist-oauth-redirect-uri` and updates the service with that secret version and `CORS_ORIGIN`.

If that update fails, the script exits non-zero. The first revision may already be public, and sign-in stays on the placeholder redirect until you run `deploy.sh` again.

## 5. Finish the OAuth client and sign in

Add the printed callback URL to the OAuth Web client’s **Authorized redirect URIs**:

`https://<service-url>/api/auth/callback`

Open the service URL and sign in with a Workspace admin in an allowed domain. On the Security Checklist page, choose **Run checklist**. Open **2-Step Verification**, then **2FA Report**, to list who has 2-step enrolled and who has it enforced.

## After you change a secret

Cloud Run pins the secret version that was current when the revision was created. A new secret version does not affect the running service until you run `bash scripts/deploy.sh` again.

## Later deploys

Run `bash scripts/deploy.sh` again from a machine with `gcloud` and Cloud Build permission. If you change domain-wide delegation, replace the scope list in the Admin console with the scopes `deploy.sh` prints.

## Names

| Resource | Value |
|----------|--------|
| Cloud Run | `security-checklist` |
| Runtime service account | `security-checklist-sa` |
| Artifact Registry | `security-checklist-repo` |
| Bucket | `<project>-security-checklist` |
| Region | `us-central1` unless you set `REGION` |

| Secret | Role |
|--------|------|
| `checklist-oauth-client-id` | OAuth Web client id |
| `checklist-oauth-client-secret` | OAuth Web client secret |
| `checklist-oauth-redirect-uri` | `https://<service>/api/auth/callback` |
| `checklist-jwt-secret` | Session cookie signing |
| `checklist-workspace-domain` | Primary Workspace domain |
| `checklist-allowed-domains` | Domains allowed to sign in |
