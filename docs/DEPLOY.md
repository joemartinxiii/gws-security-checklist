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
| GCP project **Owner** | Cloud Run, Secret Manager, IAM, IAP, and the bucket |
| Billing on that GCP project | Cloud Run, Cloud Build, and Artifact Registry |
| A project inside your Workspace organization | IAP admits only people in the project's organization |
| A Google Group for app access | `IAP_ACCESS_GROUP`, see [Access through IAP](#access-through-iap) |

Sign in to Google Cloud with that Workspace admin. The OAuth consent screen is Internal, so the Cloud project needs to live in the Workspace organization.

The Cloud Run service uses `--min-instances 0`. It does not keep an instance running when nobody is calling it.

Identity-Aware Proxy (IAP) sits in front of the service. A person has to be in `IAP_ACCESS_GROUP` to reach the sign-in page. The app still requires a Workspace admin in an allowed domain. The service does not grant `allUsers` permission to invoke it, so domain restricted sharing can stay on for the project.

## Access through IAP

`scripts/deploy.sh` turns on IAP directly on the Cloud Run service (`--iap`). There is no load balancer and no IAP charge. IAP uses a Google-managed OAuth client that admits only users in the project's organization. The invoker IAM check stays on, and the IAP service agent is the only caller that can invoke the service. See [Configure IAP for Cloud Run](https://docs.cloud.google.com/run/docs/securing/identity-aware-proxy-cloud-run).

### Preconditions

- The project is inside your Workspace organization (not "No organization").
- You created a Google Group, for example `checklist-admins@yourcompany.com`.
- The super admins who run the checklist are members of that group. Group members who are not Workspace admins can pass IAP but cannot sign in to the app.
- You run `scripts/bootstrap.sh` once. It enables `iap.googleapis.com` and creates the IAP service agent.
- You can grant IAP access. Project Owner is enough in most projects. Uncertain: if the grant fails, ask for `roles/iap.admin` on the project.

### Procedure

Set `IAP_ACCESS_GROUP` when you run the deploy:

```bash
PROJECT_ID=YOUR_PROJECT_ID IAP_ACCESS_GROUP=checklist-admins@yourcompany.com bash scripts/deploy.sh
```

The script deploys with `--iap` and `--invoker-iam-check`. After the deploy, it:

1. Grants `serviceAccount:service-PROJECT_NUMBER@gcp-sa-iap.iam.gserviceaccount.com` the `roles/run.invoker` role on the service.
2. Grants `group:IAP_ACCESS_GROUP` the `roles/iap.httpsResourceAccessor` role on the service (`gcloud iap web add-iam-policy-binding --resource-type=cloud-run`).

If you set neither `IAP_ACCESS_GROUP` nor `ALLOW_PUBLIC_INGRESS=1`, the script stops before it builds anything.

`ALLOW_PUBLIC_INGRESS=1` keeps the old public behavior: IAP off, invoker check off. The script prints a warning. Use it only for a short test or a rollback.

The script needs a current `gcloud`. The `--iap` flag on `gcloud run deploy` is in recent releases. Run `gcloud components update` if the flag is missing. The IAP service agent step uses `gcloud services identity create`, or `gcloud beta services identity create` on older releases. Cloud Shell has both.

### Verify

1. Open the service URL in a signed-out browser window. Google's IAP sign-in page appears first. The checklist page does not load.
2. Sign in as a group member who is a super admin. The app sign-in page appears, then the checklist.
3. Sign in as a person who is not in the group. IAP shows a "You don't have access" page.
4. Check the service settings:

```bash
gcloud run services describe security-checklist --region us-central1 --project YOUR_PROJECT_ID \
  --format='value(metadata.annotations["run.googleapis.com/iap-enabled"],metadata.annotations["run.googleapis.com/invoker-iam-disabled"])'
```

The first value is `true`. The second value is empty or `false`, which means the invoker check is on. `gcloud run services describe security-checklist --region us-central1` also prints `Iap Enabled: true`.

To see who has access:

```bash
gcloud iap web get-iam-policy --resource-type=cloud-run --service=security-checklist --region=us-central1 --project=YOUR_PROJECT_ID
```

### Rollback

Turn IAP off and open the service again:

```bash
gcloud run services update security-checklist --region us-central1 --project YOUR_PROJECT_ID --no-iap --no-invoker-iam-check
```

You can also redeploy with `ALLOW_PUBLIC_INGRESS=1`:

```bash
PROJECT_ID=YOUR_PROJECT_ID ALLOW_PUBLIC_INGRESS=1 bash scripts/deploy.sh
```

Both leave the service open to the internet. Put IAP back by deploying with `IAP_ACCESS_GROUP` set.

## Update an install that is already running

Open a terminal in the folder where you cloned the repo. On Cloud Shell, that is the Cloud Shell window. Then run this one command. Replace `YOUR_PROJECT_ID` with the project ID you chose when you created the project, and `checklist-admins@yourcompany.com` with your access group.

```bash
cd ~/gws-security-checklist && git pull && PROJECT_ID=YOUR_PROJECT_ID IAP_ACCESS_GROUP=checklist-admins@yourcompany.com bash scripts/deploy.sh
```

If you cloned the repo into a different folder, `cd` to that folder instead of `~/gws-security-checklist`.

The command downloads the latest code and deploys it. The first install is not this command. Follow one of the guides above for the first install. Those guides include this same update command at the end.

### Optional service settings

Set these in your shell when you run `deploy.sh`. Each deploy replaces the service's values, so set them every time.

| Variable | Meaning |
|----------|---------|
| `GWS_AUDIT_READERS` | Comma-separated emails that may read stored results besides super admins |
| `DKIM_SELECTORS` | Comma-separated DKIM selectors the DNS check looks up. Default `google`. |

```bash
PROJECT_ID=YOUR_PROJECT_ID IAP_ACCESS_GROUP=checklist-admins@yourcompany.com \
GWS_AUDIT_READERS=auditor@yourcompany.com,lead@yourcompany.com \
DKIM_SELECTORS=google,selector1 \
bash scripts/deploy.sh
```

## Change a secret

`deploy.sh` looks up the newest enabled version of each secret and pins the service to that version number. A new secret version does not reach the service until you deploy again. Cloud Run does not pick up the newest version on its own.

To change the allowed domains, the primary domain, or the OAuth client:

1. Add a version. Use single quotes around the value.

   ```bash
   echo -n 'yourcompany.com,partner.com' | gcloud secrets versions add checklist-allowed-domains --data-file=- --project=YOUR_PROJECT_ID
   ```

   The secrets are `checklist-allowed-domains`, `checklist-workspace-domain`, `checklist-oauth-client-id`, and `checklist-oauth-client-secret`.
2. Run the update command above. The deploy pins the new version.

To rotate the session signing secret:

```bash
openssl rand -hex 32 | tr -d '\n' | gcloud secrets versions add checklist-jwt-secret --data-file=- --project=YOUR_PROJECT_ID
```

Then run the update command. Rotating `JWT_SECRET` signs everyone out.

`bootstrap.sh` creates a secret only when it does not exist yet. It never changes an existing secret, so re-running bootstrap does not reset a value.

If you change domain-wide delegation, replace the scope list in the Admin console with the scopes `deploy.sh` prints.

## Upgrade from 1.0.0

Version 1.0.0 had no IAP, built as the default compute account, and kept the redirect URI in a secret. Upgrade in this order:

1. Pull the new code and create the access group (see [Access through IAP](#access-through-iap)).
2. Re-run bootstrap with the same values you used the first time. It is safe to re-run. It creates the build service account, the IAP service agent, the image cleanup policy, and the bucket lifecycle rule.

   ```bash
   PROJECT_ID=YOUR_PROJECT_ID WORKSPACE_DOMAIN=yourcompany.com ALLOWED_DOMAINS=yourcompany.com bash scripts/bootstrap.sh
   ```
3. Deploy with `IAP_ACCESS_GROUP` set. The deploy pins secrets to version numbers. It also moves `GOOGLE_REDIRECT_URI` off the old secret. gcloud cannot turn a secret env var into a plain value in one command, so the script drops the secret on the main deploy and sets the plain value in a follow-up update. That is two revisions. Sign-in returns 503 for about a minute between them. A first deploy does the same, because there is no service URL until the first revision exists.
4. Check that sign-in works through IAP.
5. After sign-in works, and after you are sure you will not roll traffic back to the 1.0.0 revision, delete the unused secret:

   ```bash
   gcloud secrets delete checklist-oauth-redirect-uri --project=YOUR_PROJECT_ID
   ```
6. Remove the project-wide grants from the default compute account. See [Cloud Build account](#cloud-build-account).

## Cloud Build account

Builds run as `security-checklist-deploy-sa`, not as the default compute service account. Bootstrap grants that account only what it needs:

| Role | Where | Why |
|------|-------|-----|
| `roles/logging.logWriter` | Project | Build logs go to Cloud Logging only |
| `roles/artifactregistry.writer` | The `security-checklist-repo` repository | Push the image |
| `roles/storage.objectViewer` | The `<project>_cloudbuild` source bucket | Read the uploaded source |

The person who runs `deploy.sh` needs `roles/iam.serviceAccountUser` on that account. Bootstrap grants it to the signed-in `gcloud` account. Project Owner already has it.

`deploy.sh` runs `gcloud builds submit` with `--config cloudbuild.yaml` and `--service-account`. The config sets `logging: CLOUD_LOGGING_ONLY`, which Cloud Build requires for a user-specified service account. See [Run builds with a user-managed service account](https://docs.cloud.google.com/build/docs/securing-builds/configure-user-specified-service-accounts).

Bootstrap no longer grants `roles/cloudbuild.builds.builder` or `roles/artifactregistry.writer` to the default compute account. Projects set up by 1.0.0 still have those grants. After the first successful deploy with the new script, remove them:

```bash
PROJECT_NUMBER=$(gcloud projects describe YOUR_PROJECT_ID --format='value(projectNumber)')
gcloud projects remove-iam-policy-binding YOUR_PROJECT_ID \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role=roles/cloudbuild.builds.builder
gcloud projects remove-iam-policy-binding YOUR_PROJECT_ID \
  --member="serviceAccount:${PROJECT_NUMBER}-compute@developer.gserviceaccount.com" \
  --role=roles/artifactregistry.writer
```

Check first that nothing else in the project builds as the default compute account.

Rollback: remove the `--service-account` line from the `gcloud builds submit` call in `scripts/deploy.sh`, and grant the default compute account the two roles again.

## Protect the runtime service account

Domain-wide delegation lets the runtime service account impersonate any user in the Workspace for the scopes you authorized. Only the app code limits it to the admin who signed in. Read [SECURITY.md](../SECURITY.md) for the full risk. In short:

- Anyone who can deploy a revision that runs as the runtime service account (project Editor, or `roles/run.developer` plus `roles/iam.serviceAccountUser`) can read the Directory as a super admin and read every policy. They can also create and share Drive files in any user's My Drive.
- Anyone with `roles/iam.serviceAccountTokenCreator` on the account can do the same without Cloud Run.

Reduce that exposure:

1. Use a dedicated project for this app. Do not share it with other workloads.
2. Keep few principals on the project. Grant roles to a group, and review the list.
3. Enforce the `iam.disableServiceAccountKeyCreation` organization policy (its managed form is `iam.managed.disableServiceAccountKeyCreation`). The app needs no key, and a key would let someone sign from outside Google Cloud. See [Restrict IAM service account usage](https://docs.cloud.google.com/organization-policy/restrict-service-accounts).
4. Turn on Data Access audit logs for the IAM API (`iam.googleapis.com`). That also turns them on for the IAM Credentials API, where `SignJwt` is logged. See [Service Account Credentials audit logging](https://docs.cloud.google.com/iam/docs/audit-logging/audit-logging-iamcreds).
5. Create a log-based alert on `SignJwt` calls for the runtime service account. This Logs Explorer filter finds them:

   ```text
   protoPayload.serviceName="iamcredentials.googleapis.com"
   protoPayload.methodName="SignJwt"
   resource.labels.email_id="security-checklist-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com"
   ```

   The app signs a token each time an admin uses it, so the runtime service account itself appears in normal use. Alert on a caller that is not the runtime service account (`protoPayload.authenticationInfo.principalEmail` is a person or a different account), and on a call volume well above your usual use. Verify the fields in a real log entry before you rely on the alert.

## Retention

- Artifact Registry keeps the 3 newest image versions and deletes older ones. The policy runs in a background job, so deletes can take about a day. A rollback to a revision older than 3 deploys can fail because its image is gone.
- The results bucket deletes noncurrent object versions 30 days after they stop being current. The current `latest.json` and `waivers.json` are never deleted.

## Names

| Resource | Value |
|----------|--------|
| Cloud Run | `security-checklist` |
| Runtime service account | `security-checklist-sa` |
| Build service account | `security-checklist-deploy-sa` |
| Artifact Registry | `security-checklist-repo` |
| Bucket | `<project>-security-checklist` |
| Source staging bucket | `<project>_cloudbuild` |
| Region | `us-central1` unless you set `REGION` on bootstrap and deploy |

| Secret | Role |
|--------|------|
| `checklist-oauth-client-id` | OAuth Web client id |
| `checklist-oauth-client-secret` | OAuth Web client secret |
| `checklist-jwt-secret` | Session cookie signing |
| `checklist-workspace-domain` | Primary Workspace domain |
| `checklist-allowed-domains` | Domains allowed to sign in |

The OAuth redirect URI (`https://<service>/api/auth/callback`) is a plain env var, `GOOGLE_REDIRECT_URI`. It is not a secret. The service starts without it. Sign-in answers 503 until `deploy.sh` sets it.
