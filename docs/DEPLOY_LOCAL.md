# Install GWS Security on your computer

Use this guide on a Mac or a Windows PC. You will install Google Cloud’s command line, clone this repo, and deploy one Cloud Run service.

The other path is [Install in Cloud Shell](./DEPLOY_CLOUD_SHELL.md). Cloud Shell is a terminal inside the Google Cloud website. Use that if you do not want to install tools on the PC. The app you get is the same.

Stay in this guide until the checklist page is open in your browser.

## What you need

| You need | Why |
|----------|-----|
| Workspace **super admin** | Turn on domain-wide delegation, and run the first checklist |
| A Google account in that Workspace | Create the Cloud project and sign `gcloud` in |
| A billing account | Cloud Run, Cloud Build, and Artifact Registry |
| A Google Group | The people who may reach the app through Identity-Aware Proxy (IAP). You create it in step 9. |

You will invent a project ID in the next step. It does not exist until you create the project.

## 1. Create the Google Cloud project

1. Open [Google Cloud Console](https://console.cloud.google.com/) and sign in as the Workspace super admin.
2. Open the project picker at the top of the page. Choose **New project**.
3. Set the project name to `GWS Security`. The name is only a label.
4. Under **Project ID**, click **Edit**. Type the ID you want. Use 6 to 30 characters: a letter first, then lowercase letters, numbers, and hyphens. Do not end with a hyphen. This ID is permanent, and it has to be unique across Google Cloud.
5. If you see an organization menu, choose your Workspace organization. That lets the OAuth consent screen be Internal, and IAP needs it too.
6. Click **Create**. Wait until the new project is selected.
7. Open **Billing** and link a billing account to this project. If you do not have a billing account yet, create one when Google asks. The deploy will fail until billing is linked.

Write the project ID down. Every command below uses it as `YOUR_PROJECT_ID`. The ID is shown under the project name in the project picker. It can be different from the name `GWS Security`.

## 2. Install the tools

You need Git, the Google Cloud CLI (`gcloud`), and OpenSSL. Check them only after the install steps for your system.

### macOS

1. Open **Terminal**. It is in Applications → Utilities.
2. If `git` is missing, run `xcode-select --install` and accept the prompt.
3. Install the Google Cloud CLI from [Install the gcloud CLI](https://cloud.google.com/sdk/docs/install). Choose the macOS steps on that page. When the installer finishes, close Terminal and open it again.

### Windows

The deploy scripts are bash. Use **Git Bash**, which comes with Git for Windows. Command Prompt and PowerShell will not run these scripts.

1. Install Git from [https://git-scm.com/download/win](https://git-scm.com/download/win). Keep the default options.
2. Install the Google Cloud CLI from [Install the gcloud CLI](https://cloud.google.com/sdk/docs/install). Choose the Windows steps on that page. When it finishes, close every terminal window.
3. Open **Git Bash** from the Start menu. The window title should say Git Bash.

### Check the tools

In Terminal on a Mac, or Git Bash on Windows, run:

```bash
git --version
gcloud --version
openssl version
```

Each command should print a version. If `gcloud` is not found, close the window, open it again, and retry. If `openssl` is not found on Windows, use [Install in Cloud Shell](./DEPLOY_CLOUD_SHELL.md) instead of hunting for a separate OpenSSL install.

## 3. Sign in and select the project

```bash
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
gcloud config get-value project
```

A browser window opens for `gcloud auth login`. Sign in as the same Workspace admin. The last command should print your project ID. If it prints `(unset)`, run the `gcloud config set project` line again with the ID from the project picker.

## 4. Get the code

```bash
cd ~
git clone https://github.com/joemartinxiii/gws-security-checklist.git
cd gws-security-checklist
ls scripts/bootstrap.sh
```

The last command should print `scripts/bootstrap.sh`. If it says the file does not exist, you are in the wrong folder. Run `cd ~/gws-security-checklist` and try again.

On Windows, `~` in Git Bash is your user folder, such as `C:\Users\YourName`.

## 5. Bootstrap the project

`WORKSPACE_DOMAIN` is the primary Workspace domain, the part after `@` in your admin email. `ALLOWED_DOMAINS` is who may sign in. For one domain, set both to that domain.

```bash
PROJECT_ID=YOUR_PROJECT_ID \
WORKSPACE_DOMAIN=yourcompany.com \
ALLOWED_DOMAINS=yourcompany.com \
bash scripts/bootstrap.sh
```

This enables APIs, creates the runtime service account `security-checklist-sa`, a build service account, a bucket, the IAP service agent, and Secret Manager entries. It can take a few minutes. Leave the window open.

When it finishes, it prints **SA client ID**. That is a long number. Copy it. Domain-wide delegation needs this number.

That number is not the OAuth client ID. The OAuth client ID ends in `.apps.googleusercontent.com` and comes from the next step.

If you lose the number, print it again:

```bash
gcloud iam service-accounts describe security-checklist-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com --format='value(uniqueId)'
```

If bootstrap stops with an error about the service account not existing yet, run the same bootstrap command again. A brand-new account can take a few seconds to appear.

## 6. Create the OAuth Web client

Still in Google Cloud Console, with this project selected:

1. Open [OAuth consent screen](https://console.cloud.google.com/apis/credentials/consent).
2. Choose **Internal**. The app name can be `GWS Security`. Set the support email to your admin email.
3. If Google asks for scopes, the consent screen only needs identity: `openid`, `userinfo.email`, and `userinfo.profile`. Do not add Workspace admin scopes on this client. Admin access is the service account in the next step.
4. Open [Credentials](https://console.cloud.google.com/apis/credentials). Click **Create credentials**, then **OAuth client ID**.
5. Application type: **Web application**. Name: `GWS Security`.
6. Leave **Authorized redirect URIs** empty. You will add the real URL after deploy prints it.
7. Click **Create**. Copy the **Client ID** and the **Client secret**. Google shows the secret once. If you lose the secret, open this client and use **Reset secret**.

## 7. Store the client id and secret

Run these in the repo folder. Use single quotes around the values. Replace the placeholders. Do not commit these values, and do not leave the bootstrap value `PLACEHOLDER` in either secret.

```bash
echo -n 'YOUR_CLIENT_ID' | gcloud secrets versions add checklist-oauth-client-id --data-file=- --project=YOUR_PROJECT_ID
echo -n 'YOUR_CLIENT_SECRET' | gcloud secrets versions add checklist-oauth-client-secret --data-file=- --project=YOUR_PROJECT_ID
```

## 8. Authorize domain-wide delegation

Open the Workspace Admin console: **Security → Access and data control → API controls → Domain-wide delegation → Add new**.

The direct page is [Domain-wide delegation](https://admin.google.com/ac/owl/domainwidedelegation).

- Client ID: the numeric **SA client ID** from bootstrap.
- OAuth scopes: paste this as one line.

```text
https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/chrome.management.policy.readonly,https://www.googleapis.com/auth/cloud-identity.policies.readonly,https://www.googleapis.com/auth/drive.file
```

Those scopes let the service account read users and 2-step status, read checklist policies, read Chrome browser policy, and create an export file in the signed-in admin’s Drive. The scopes cannot change users, Chrome policies, or existing Drive files.

Know what you are granting. Domain-wide delegation lets the service account impersonate any user in your Workspace for these scopes. Only the app code limits it to the admin who signed in. Anyone who can deploy a revision that runs as the service account (project Editor, or `roles/run.developer` plus `roles/iam.serviceAccountUser`), or who holds Token Creator on it, can read the Directory as a super admin, read every policy, and create and share Drive files in any user’s My Drive. Use a dedicated project, keep few principals on it, and read [Protect the runtime service account](./DEPLOY.md#protect-the-runtime-service-account).

Click **Authorize**.

## 9. Create the access group

IAP lets only the members of one Google Group reach the app. Create that group first.

1. Open the Admin console: **Directory → Groups → Create group**. The direct page is [Groups](https://admin.google.com/ac/groups).
2. Name it, for example `checklist-admins@yourcompany.com`.
3. Add the super admins who run the checklist as members.

Group members still need to be Workspace admins to sign in to the app. The group only decides who can reach the sign-in page.

## 10. Deploy

```bash
cd ~/gws-security-checklist
PROJECT_ID=YOUR_PROJECT_ID IAP_ACCESS_GROUP=checklist-admins@yourcompany.com bash scripts/deploy.sh
```

Use the group email from the last step. If you set neither `IAP_ACCESS_GROUP` nor `ALLOW_PUBLIC_INGRESS=1`, the script stops before it builds anything. Do not use `ALLOW_PUBLIC_INGRESS=1` for a normal install. It leaves the service open to the internet.

Cloud Build and Cloud Run usually take several minutes. The script turns on IAP, then lets the IAP service agent invoke the service and lets your group through. When it finishes, it prints:

- `Deployed:` followed by the site URL
- `OAuth redirect URI to add on the Web client:` followed by `https://…/api/auth/callback`

Copy that callback URL exactly.

If the script exits with an error after the first revision is created, run the same deploy command again. Sign-in stays broken until the redirect URI is set on the service.

## 11. Finish sign-in

1. Open the OAuth Web client you created. Under **Authorized redirect URIs**, add the callback URL the script printed. Save.
2. Open the `Deployed:` URL in a browser. Google's IAP sign-in page comes first. Sign in with an account in your access group.
3. Sign in to the app with a super admin in the allowed domain.
4. On the Security Checklist page, choose **Run checklist**.

A super admin can run the checklist, waive a check, and save a CSV to Drive. Another Workspace admin in an allowed domain can view the last run and download CSV or PDF.

If Google says the redirect URI does not match, the URI on the OAuth client is different from the one `deploy.sh` printed. Add the printed one and try again.

## Update later

From the clone, this one command gets the latest code and deploys it:

```bash
cd ~/gws-security-checklist && git pull && PROJECT_ID=YOUR_PROJECT_ID IAP_ACCESS_GROUP=checklist-admins@yourcompany.com bash scripts/deploy.sh
```

Run it again after you add a secret version. The deploy pins each secret to its newest enabled version, so a new version reaches the service only on the next deploy. To change the allowed domains or rotate the session secret, see [Change a secret](./DEPLOY.md#change-a-secret). If you change domain-wide delegation, paste the scope list that `deploy.sh` prints into the Admin console.
