# Set up GWS Security

GWS Security runs as one Cloud Run service. The API and the checklist page are the same service. You need a Google Cloud project with billing, and a Google Workspace tenant where you are a super admin.

Pick one install path and stay in that guide until the site is open. Both paths run the same scripts and produce the same app.

| Where you want to type the commands | Guide |
|-------------------------------------|--------|
| Your Mac, or a Windows PC | [Install on your computer](./DEPLOY_LOCAL.md) |
| The browser, already signed in to Google Cloud | [Install in Cloud Shell](./DEPLOY_CLOUD_SHELL.md) |

Local development with sample data, and no tenant, is [LOCAL_DEV.md](./LOCAL_DEV.md). Who can sign in, and which scopes are used, is [SECURITY.md](../SECURITY.md).

## What you need

| You need | Why |
|----------|-----|
| Workspace **super admin** | Turn on domain-wide delegation, and run the first checklist |
| GCP project **Owner** | Cloud Run, Secret Manager, IAM, and the bucket |
| Billing on that GCP project | Cloud Run, Cloud Build, and Artifact Registry |

Sign in to Google Cloud with that Workspace admin. The OAuth consent screen is Internal, so the Cloud project needs to live in the Workspace organization.

The Cloud Run service uses `--min-instances 0`. It does not keep an instance running when nobody is calling it. The service disables the Cloud Run invoker check so the sign-in page can load. It does not grant `allUsers` permission to invoke the service. Domain restricted sharing can stay on for the project. The app still requires a Workspace admin in an allowed domain.

## Update an install that is already running

Open a terminal in the folder where you cloned the repo. On Cloud Shell, that is the Cloud Shell window. Then run this one command. Replace `YOUR_PROJECT_ID` with the project ID you chose when you created the project.

```bash
cd ~/gws-security-checklist && git pull && PROJECT_ID=YOUR_PROJECT_ID bash scripts/deploy.sh
```

If you cloned the repo into a different folder, `cd` to that folder instead of `~/gws-security-checklist`.

The command downloads the latest code and deploys it. The first install is not this command. Follow one of the guides above for the first install. Those guides include this same update command at the end.

Cloud Run pins the secret version that was current when the revision was created. After you change a secret, run the update command again. If you change domain-wide delegation, replace the scope list in the Admin console with the scopes `deploy.sh` prints.

## Names

| Resource | Value |
|----------|--------|
| Cloud Run | `security-checklist` |
| Runtime service account | `security-checklist-sa` |
| Artifact Registry | `security-checklist-repo` |
| Bucket | `<project>-security-checklist` |
| Region | `us-central1` unless you set `REGION` on bootstrap and deploy |

| Secret | Role |
|--------|------|
| `checklist-oauth-client-id` | OAuth Web client id |
| `checklist-oauth-client-secret` | OAuth Web client secret |
| `checklist-oauth-redirect-uri` | `https://<service>/api/auth/callback` |
| `checklist-jwt-secret` | Session cookie signing |
| `checklist-workspace-domain` | Primary Workspace domain |
| `checklist-allowed-domains` | Domains allowed to sign in |
