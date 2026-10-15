import { google } from 'googleapis';
import { CodeChallengeMethod, GoogleAuth, OAuth2Client } from 'google-auth-library';

let baseAuth: GoogleAuth | null = null;
let cachedSaEmail: string | null = null;

// Scopes the service account is authorized for via domain-wide delegation.
// Keep in sync with scripts/lib/scopes.sh (DWD_SCOPES) — run: npm run check:scopes
const SERVICE_ACCOUNT_SCOPES = [
  'https://www.googleapis.com/auth/admin.directory.user.readonly',
  'https://www.googleapis.com/auth/chrome.management.policy.readonly',
  'https://www.googleapis.com/auth/cloud-identity.policies.readonly',
  'https://www.googleapis.com/auth/drive.file',
];

export interface GoogleConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  workspaceDomain: string;
}

export function getGoogleConfig(): GoogleConfig {
  return {
    clientId: process.env.GOOGLE_CLIENT_ID || '',
    clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
    redirectUri: process.env.GOOGLE_REDIRECT_URI || '',
    workspaceDomain: process.env.WORKSPACE_DOMAIN || '',
  };
}

// --- Keyless domain-wide delegation ----------------------------------------
// Instead of loading a downloaded service-account private key, the app runs as
// its runtime service account (Cloud Run) and asks Google's IAM Credentials API
// to sign the delegation assertion on its behalf. This requires the runtime SA
// to hold roles/iam.serviceAccountTokenCreator on itself and the
// iamcredentials.googleapis.com API to be enabled. No key file is stored.

interface CachedToken {
  accessToken: string;
  expiresAt: number;
}

const delegatedTokenCache = new Map<string, CachedToken>();

function getBaseAuth(): GoogleAuth {
  if (!baseAuth) {
    baseAuth = new GoogleAuth({
      scopes: ['https://www.googleapis.com/auth/cloud-platform'],
    });
  }
  return baseAuth;
}

async function getRuntimeServiceAccountEmail(): Promise<string> {
  if (cachedSaEmail) {
    return cachedSaEmail;
  }
  // Prefer an explicit env var (set by the deploy) to avoid a metadata lookup.
  if (process.env.SERVICE_ACCOUNT_EMAIL) {
    cachedSaEmail = process.env.SERVICE_ACCOUNT_EMAIL;
    return cachedSaEmail;
  }
  const credentials = await getBaseAuth().getCredentials();
  if (!credentials.client_email) {
    throw new Error(
      'Could not determine the runtime service account email. Set SERVICE_ACCOUNT_EMAIL.'
    );
  }
  cachedSaEmail = credentials.client_email;
  return cachedSaEmail;
}

async function mintDelegatedToken(subject: string): Promise<CachedToken> {
  const saEmail = await getRuntimeServiceAccountEmail();
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: saEmail,
    sub: subject,
    scope: SERVICE_ACCOUNT_SCOPES.join(' '),
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
  };

  // Have Google sign the assertion as the SA (no local private key).
  const iamcredentials = google.iamcredentials({ version: 'v1', auth: getBaseAuth() });
  const signResp = await iamcredentials.projects.serviceAccounts.signJwt({
    name: `projects/-/serviceAccounts/${saEmail}`,
    requestBody: { payload: JSON.stringify(payload) },
  });
  const signedJwt = signResp.data.signedJwt;
  if (!signedJwt) {
    throw new Error('IAM signJwt returned no signedJwt');
  }

  // Exchange the signed assertion for an access token scoped to the subject.
  const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: signedJwt,
    }).toString(),
  });

  if (!tokenResp.ok) {
    const text = await tokenResp.text().catch(() => '');
    throw new Error(`Delegated token exchange failed (${tokenResp.status}): ${text}`);
  }

  const tok = (await tokenResp.json()) as { access_token: string; expires_in: number };
  // Refresh 5 minutes early to avoid using a token that expires mid-request.
  return {
    accessToken: tok.access_token,
    expiresAt: Date.now() + (tok.expires_in - 300) * 1000,
  };
}

export async function getDelegatedAccessToken(subject: string): Promise<string> {
  if (!subject) {
    throw new Error('A subject (user email) is required for domain-wide delegation');
  }
  const cached = delegatedTokenCache.get(subject);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.accessToken;
  }
  const fresh = await mintDelegatedToken(subject);
  delegatedTokenCache.set(subject, fresh);
  return fresh.accessToken;
}

/**
 * Returns an OAuth2 client authenticated as the given Workspace user via
 * keyless domain-wide delegation. Use this as the `auth` for googleapis calls.
 */
export async function getDelegatedAuthClient(subject: string): Promise<OAuth2Client> {
  const accessToken = await getDelegatedAccessToken(subject);
  const client = new google.auth.OAuth2();
  client.setCredentials({ access_token: accessToken });
  return client;
}

/**
 * A new client every call. Login must not share one OAuth2Client: token
 * exchange and userinfo both call setCredentials, and Cloud Run handles
 * concurrent callbacks on the same process.
 */
export function getOAuth2Client(): OAuth2Client {
  const config = getGoogleConfig();
  return new google.auth.OAuth2(config.clientId, config.clientSecret, config.redirectUri);
}

/**
 * Browser OAuth is identity-only. Workspace APIs use domain-wide delegation
 * server-side; the SPA never holds Google access/refresh tokens.
 */
export function getAuthUrl(state?: string, codeChallenge?: string): string {
  const client = getOAuth2Client();

  return client.generateAuthUrl({
    // Online only — no Google refresh token for the browser or long-lived offline grant.
    access_type: 'online',
    scope: [
      'openid',
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile',
    ],
    prompt: 'select_account',
    ...(state ? { state } : {}),
    ...(codeChallenge
      ? { code_challenge: codeChallenge, code_challenge_method: CodeChallengeMethod.S256 }
      : {}),
  });
}

export async function createPkcePair(): Promise<{ codeVerifier: string; codeChallenge: string }> {
  const { codeVerifier, codeChallenge } = await getOAuth2Client().generateCodeVerifierAsync();
  if (!codeChallenge) throw new Error('Could not generate a PKCE code challenge');
  return { codeVerifier, codeChallenge };
}

export async function getTokensFromCode(code: string, codeVerifier?: string) {
  const client = getOAuth2Client();
  const { tokens } = await client.getToken({ code, ...(codeVerifier ? { codeVerifier } : {}) });
  client.setCredentials(tokens);
  return tokens;
}
