import crypto from 'crypto';
import request from 'supertest';
import { createApp } from '../src/app';
import { authService } from '../src/services/auth.service';
import { permissionsService } from '../src/services/permissions.service';

jest.mock('../src/services/auth.service', () => ({
  authService: {
    exchangeCodeForTokens: jest.fn(),
    verifyIdToken: jest.fn(),
    createSessionToken: jest.fn(() => 'session-token'),
    verifySessionToken: jest.fn(),
  },
}));

jest.mock('../src/services/permissions.service', () => ({
  permissionsService: {
    getAdminRoles: jest.fn(),
    getUserPermissions: jest.fn(),
  },
}));

function cookieValue(setCookie: string | string[] | undefined, name: string): string {
  const list = Array.isArray(setCookie) ? setCookie : [setCookie || ''];
  const row = list.find((entry) => entry.startsWith(`${name}=`));
  if (!row) throw new Error(`missing cookie ${name}`);
  return decodeURIComponent(row.split(';')[0].slice(name.length + 1));
}

function s256(verifier: string): string {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

const identity = {
  sub: 'google-sub-1',
  email: 'admin@example.com',
  emailVerified: true,
  hd: 'example.com',
  name: 'Admin',
};

const superAdmin = {
  isSuperAdmin: true,
  isDelegatedAdmin: false,
  id: 'directory-id-1',
  primaryEmail: 'admin@example.com',
};

describe('OAuth callback', () => {
  const app = createApp();

  async function startLogin() {
    const login = await request(app).get('/api/auth/login');
    expect(login.status).toBe(200);
    const state = cookieValue(login.headers['set-cookie'], 'oauth_state');
    const verifier = cookieValue(login.headers['set-cookie'], 'oauth_verifier');
    return { login, state, verifier, authUrl: new URL(login.body.authUrl) };
  }

  beforeEach(() => {
    jest.clearAllMocks();
    // Stands in for Google: the exchange succeeds only for the verifier that matches the challenge.
    let challenge = '';
    (authService.exchangeCodeForTokens as jest.Mock).mockImplementation(
      async (_code: string, verifier: string) => {
        if (!verifier || s256(verifier) !== challenge) throw new Error('invalid_grant');
        return { accessToken: 'google-access', idToken: 'id-token', expiresAt: Date.now() + 1000 };
      }
    );
    (authService.verifyIdToken as jest.Mock).mockResolvedValue(identity);
    (permissionsService.getAdminRoles as jest.Mock).mockResolvedValue(superAdmin);
    setChallenge = (value: string) => {
      challenge = value;
    };
  });

  let setChallenge: (value: string) => void;

  async function callback(overrides: { verifier?: string | null; state?: string } = {}) {
    const { state, verifier, authUrl } = await startLogin();
    setChallenge(authUrl.searchParams.get('code_challenge') || '');
    const cookies = [`oauth_state=${state}`];
    const sentVerifier = overrides.verifier === undefined ? verifier : overrides.verifier;
    if (sentVerifier) cookies.push(`oauth_verifier=${sentVerifier}`);
    return request(app)
      .get(`/api/auth/callback?code=abc&state=${overrides.state ?? state}`)
      .set('Cookie', cookies)
      .redirects(0);
  }

  test('login sends a PKCE challenge and keeps the verifier in an HttpOnly cookie', async () => {
    const { login, verifier, authUrl } = await startLogin();
    expect(authUrl.searchParams.get('code_challenge_method')).toBe('S256');
    expect(authUrl.searchParams.get('code_challenge')).toBe(s256(verifier));
    const cookies = login.headers['set-cookie'] as unknown as string[];
    const row = cookies.find((c) => c.startsWith('oauth_verifier='))!;
    expect(row).toMatch(/HttpOnly/i);
    expect(row).toMatch(/Max-Age=600/i);
  });

  test('sends a successful sign-in to / and stores the token subject', async () => {
    const res = await callback();

    expect(res.status).toBe(302);
    expect(res.headers.location).toBe('http://localhost:3000/');
    expect(res.headers.location).not.toContain('token');
    expect(authService.verifyIdToken).toHaveBeenCalledWith('id-token');
    expect(authService.createSessionToken).toHaveBeenCalledWith(
      expect.objectContaining({ email: 'admin@example.com', sub: 'google-sub-1' })
    );
  });

  test('rejects an email in an allowed domain when the token has no hd claim', async () => {
    (authService.verifyIdToken as jest.Mock).mockResolvedValue({ ...identity, hd: undefined });

    const res = await callback();

    expect(res.headers.location).toBe('http://localhost:3000/auth/error?error=domain_not_allowed');
    expect(permissionsService.getAdminRoles).not.toHaveBeenCalled();
    expect(authService.createSessionToken).not.toHaveBeenCalled();
  });

  test('rejects an hd claim outside the allowed domains', async () => {
    (authService.verifyIdToken as jest.Mock).mockResolvedValue({ ...identity, hd: 'other.com' });

    const res = await callback();

    expect(res.headers.location).toContain('error=domain_not_allowed');
    expect(permissionsService.getAdminRoles).not.toHaveBeenCalled();
  });

  test('accepts hd in a different case', async () => {
    (authService.verifyIdToken as jest.Mock).mockResolvedValue({ ...identity, hd: 'Example.COM' });

    const res = await callback();

    expect(res.headers.location).toBe('http://localhost:3000/');
  });

  test('rejects an unverified email before any Directory call', async () => {
    (authService.verifyIdToken as jest.Mock).mockResolvedValue({ ...identity, emailVerified: false });

    const res = await callback();

    expect(res.headers.location).toContain('error=domain_not_allowed');
    expect(permissionsService.getAdminRoles).not.toHaveBeenCalled();
    expect(authService.createSessionToken).not.toHaveBeenCalled();
  });

  test('rejects a Directory user whose primary email differs from the token email', async () => {
    (permissionsService.getAdminRoles as jest.Mock).mockResolvedValue({
      ...superAdmin,
      primaryEmail: 'someone.else@example.com',
    });

    const res = await callback();

    expect(res.headers.location).toContain('error=admin_check_failed');
    expect(authService.createSessionToken).not.toHaveBeenCalled();
  });

  test('compares the Directory primary email case-insensitively', async () => {
    (permissionsService.getAdminRoles as jest.Mock).mockResolvedValue({
      ...superAdmin,
      primaryEmail: 'Admin@Example.com',
    });

    const res = await callback();

    expect(res.headers.location).toBe('http://localhost:3000/');
  });

  test('rejects a Directory user without an id', async () => {
    (permissionsService.getAdminRoles as jest.Mock).mockResolvedValue({ ...superAdmin, id: undefined });

    const res = await callback();

    expect(res.headers.location).toContain('error=admin_check_failed');
  });

  test('maps a non-admin to not_admin', async () => {
    (permissionsService.getAdminRoles as jest.Mock).mockResolvedValue({
      isSuperAdmin: false,
      isDelegatedAdmin: false,
    });

    const res = await callback();

    expect(res.headers.location).toContain('error=not_admin');
  });

  test('keeps other admin lookup failures as admin_check_failed', async () => {
    (permissionsService.getAdminRoles as jest.Mock).mockRejectedValue(new Error('Directory unavailable'));

    const res = await callback();

    expect(res.headers.location).toContain('error=admin_check_failed');
  });

  test('fails when the PKCE verifier cookie is missing and never calls Google', async () => {
    const res = await callback({ verifier: null });

    expect(res.headers.location).toContain('error=invalid_state');
    expect(authService.exchangeCodeForTokens).not.toHaveBeenCalled();
  });

  test('fails when the PKCE verifier does not match the challenge', async () => {
    const res = await callback({ verifier: 'x'.repeat(64) });

    expect(authService.exchangeCodeForTokens).toHaveBeenCalledWith('abc', 'x'.repeat(64));
    expect(res.headers.location).toContain('error=callback_failed');
    expect(authService.createSessionToken).not.toHaveBeenCalled();
  });

  test('rejects a mismatched state', async () => {
    const res = await callback({ state: 'forged' });

    expect(res.headers.location).toContain('error=invalid_state');
    expect(authService.exchangeCodeForTokens).not.toHaveBeenCalled();
  });

  test('admin-check failures do not return IAM details', async () => {
    (authService.verifySessionToken as jest.Mock).mockReturnValue({
      email: 'admin@example.com',
      name: 'Admin',
    });
    (permissionsService.getAdminRoles as jest.Mock).mockRejectedValue(
      new Error('Secret Manager projects/secret-checklist denied for domain-wide delegation')
    );

    const res = await request(app)
      .get('/api/audit/hardening')
      .set('Authorization', 'Bearer session');

    expect(res.status).toBe(500);
    expect(JSON.stringify(res.body)).not.toMatch(/Secret Manager|projects\/secret-checklist|delegation/i);
    expect(res.body.error).toMatch(/Check server logs/);
  });
});
