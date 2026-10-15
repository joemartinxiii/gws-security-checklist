import request from 'supertest';
import { createApp } from '../src/app';
import { authService } from '../src/services/auth.service';
import { permissionsService } from '../src/services/permissions.service';

jest.mock('../src/services/auth.service', () => ({
  authService: {
    exchangeCodeForTokens: jest.fn(),
    getUserInfo: jest.fn(),
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

describe('OAuth callback', () => {
  const app = createApp();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('sends a successful sign-in to /', async () => {
    const login = await request(app).get('/api/auth/login');
    expect(login.status).toBe(200);
    const state = cookieValue(login.headers['set-cookie'], 'oauth_state');

    (authService.exchangeCodeForTokens as jest.Mock).mockResolvedValue({
      accessToken: 'google-access',
      expiresAt: Date.now() + 1000,
    });
    (authService.getUserInfo as jest.Mock).mockResolvedValue({
      email: 'admin@example.com',
      name: 'Admin',
    });
    (permissionsService.getAdminRoles as jest.Mock).mockResolvedValue({
      isSuperAdmin: true,
      isDelegatedAdmin: false,
    });

    const callback = await request(app)
      .get(`/api/auth/callback?code=abc&state=${state}`)
      .set('Cookie', login.headers['set-cookie'])
      .redirects(0);

    expect(callback.status).toBe(302);
    expect(callback.headers.location).toBe('http://localhost:3000/');
    expect(callback.headers.location).not.toContain('token');
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
