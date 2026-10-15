import request from 'supertest';
import { createApp } from '../src/app';
import { authService } from '../src/services/auth.service';
import { permissionsService } from '../src/services/permissions.service';
import { setWaiver, mergeWaivers } from '../src/services/securityAuditStore';

jest.mock('../src/services/auth.service', () => ({
  authService: {
    verifySessionToken: jest.fn(),
    refreshSessionToken: jest.fn(),
    revokeSessionToken: jest.fn(),
  },
}));

jest.mock('../src/services/permissions.service', () => ({
  permissionsService: {
    getAdminRoles: jest.fn(),
    getUserPermissions: jest.fn(),
  },
}));

jest.mock('../src/services/securityAuditStore', () => ({
  getLatest: jest.fn(async () => null),
  getWaivers: jest.fn(async () => ({})),
  putLatest: jest.fn(),
  setWaiver: jest.fn(async () => ({})),
  removeWaiver: jest.fn(async () => ({})),
  mergeWaivers: jest.fn(async () => ({})),
}));

const ORIGINAL_ENV = { ...process.env };

function useEnv(env: Record<string, string | undefined>): void {
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

afterEach(() => {
  process.env = { ...ORIGINAL_ENV };
});

describe('Origin check on state-changing API calls', () => {
  describe('production', () => {
    const appOrigin = 'https://checklist.example.com';
    let app: ReturnType<typeof createApp>;

    beforeEach(() => {
      useEnv({ NODE_ENV: 'production', CORS_ORIGIN: appOrigin, SERVE_FRONTEND: 'false' });
      app = createApp();
    });

    test('allows the configured origin', async () => {
      const res = await request(app).post('/api/auth/logout').set('Origin', appOrigin);
      expect(res.status).toBe(200);
    });

    test('allows the configured origin with a trailing slash in config', async () => {
      useEnv({ CORS_ORIGIN: `${appOrigin}/` });
      const res = await request(app).post('/api/auth/logout').set('Origin', appOrigin);
      expect(res.status).toBe(200);
    });

    test.each(['https://evil.example.net', 'null', 'http://checklist.example.com'])(
      'rejects origin %s',
      async (origin) => {
        const res = await request(app).post('/api/auth/logout').set('Origin', origin);
        expect(res.status).toBe(403);
        expect(res.body.error).toMatch(/blocked/i);
      }
    );

    test.each(['put', 'patch', 'delete'] as const)('rejects a cross-origin %s', async (method) => {
      const res = await request(app)[method]('/api/audit/hardening/waivers/x').set('Origin', 'https://evil.example.net');
      expect(res.status).toBe(403);
    });

    test('rejects a request without Origin when Sec-Fetch-Site is cross-site', async () => {
      const res = await request(app).post('/api/auth/logout').set('Sec-Fetch-Site', 'cross-site');
      expect(res.status).toBe(403);
    });

    test('rejects a request with neither Origin nor Sec-Fetch-Site', async () => {
      const res = await request(app).post('/api/auth/logout');
      expect(res.status).toBe(403);
    });

    test.each(['same-origin', 'none'])('allows no Origin with Sec-Fetch-Site %s', async (site) => {
      const res = await request(app).post('/api/auth/logout').set('Sec-Fetch-Site', site);
      expect(res.status).toBe(200);
    });

    test('does not check safe methods', async () => {
      const res = await request(app).get('/health').set('Origin', 'https://evil.example.net');
      expect(res.status).toBe(200);
      const api = await request(app).get('/api/audit/hardening').set('Origin', 'https://evil.example.net');
      expect(api.status).toBe(401);
    });

    test('never reflects another origin in CORS headers', async () => {
      const res = await request(app).get('/health').set('Origin', 'https://evil.example.net');
      expect(res.headers['access-control-allow-origin']).toBeUndefined();
      const ok = await request(app).get('/health').set('Origin', appOrigin);
      expect(ok.headers['access-control-allow-origin']).toBe(appOrigin);
    });

    test('ignores the Bearer header', async () => {
      (authService.verifySessionToken as jest.Mock).mockResolvedValue({ email: 'a@example.com', name: 'A' });
      const res = await request(app).get('/api/auth/me').set('Authorization', 'Bearer session');
      expect(res.status).toBe(401);
      expect(authService.verifySessionToken).not.toHaveBeenCalled();
    });
  });

  describe('production without CORS_ORIGIN', () => {
    beforeEach(() => {
      useEnv({ NODE_ENV: 'production', CORS_ORIGIN: undefined, SERVE_FRONTEND: 'false' });
    });

    test('accepts only the request host as Origin and sends no CORS headers', async () => {
      const app = createApp();
      const same = await request(app)
        .post('/api/auth/logout')
        .set('Host', 'checklist.example.com')
        .set('X-Forwarded-Proto', 'https')
        .set('Origin', 'https://checklist.example.com');
      expect(same.status).toBe(200);
      const other = await request(app)
        .post('/api/auth/logout')
        .set('Host', 'checklist.example.com')
        .set('X-Forwarded-Proto', 'https')
        .set('Origin', 'https://evil.example.net');
      expect(other.status).toBe(403);
      const cors = await request(app).get('/health').set('Origin', 'https://evil.example.net');
      expect(cors.headers['access-control-allow-origin']).toBeUndefined();
    });
  });

  describe('outside production', () => {
    beforeEach(() => {
      useEnv({ NODE_ENV: 'test', CORS_ORIGIN: undefined });
    });

    test('allows requests without Origin', async () => {
      const res = await request(createApp()).post('/api/auth/logout');
      expect(res.status).toBe(200);
    });

    test.each(['http://localhost:3000', 'http://localhost:5173', 'http://127.0.0.1:3000'])(
      'allows local origin %s',
      async (origin) => {
        const res = await request(createApp()).post('/api/auth/logout').set('Origin', origin);
        expect(res.status).toBe(200);
      }
    );

    test('rejects a remote origin', async () => {
      const res = await request(createApp()).post('/api/auth/logout').set('Origin', 'https://evil.example.net');
      expect(res.status).toBe(403);
    });
  });

  test('the API takes JSON only', async () => {
    useEnv({ NODE_ENV: 'test' });
    (authService.verifySessionToken as jest.Mock).mockResolvedValue({ email: 's@example.com', name: 'S' });
    (permissionsService.getAdminRoles as jest.Mock).mockResolvedValue({ isSuperAdmin: true, isDelegatedAdmin: false });
    const res = await request(createApp())
      .put('/api/audit/hardening/waivers/gmail-delegation')
      .set('Authorization', 'Bearer session')
      .type('form')
      .send('reason=ok');
    expect(res.status).toBe(400);
    expect(setWaiver).not.toHaveBeenCalled();
  });
});

describe('waiver validation', () => {
  const app = createApp();
  const put = (checkId: string, body: unknown) =>
    request(app)
      .put(`/api/audit/hardening/waivers/${encodeURIComponent(checkId)}`)
      .set('Authorization', 'Bearer session')
      .send(body as object);

  beforeEach(() => {
    jest.clearAllMocks();
    (authService.verifySessionToken as jest.Mock).mockResolvedValue({ email: 's@example.com', name: 'S' });
    (permissionsService.getAdminRoles as jest.Mock).mockResolvedValue({ isSuperAdmin: true, isDelegatedAdmin: false });
  });

  test('saves a valid waiver with the trimmed reason', async () => {
    const res = await put('gmail-delegation', { reason: '  Compensating control in place  ' });
    expect(res.status).toBe(200);
    expect(setWaiver).toHaveBeenCalledWith('gmail-delegation', 'Compensating control in place', 's@example.com');
  });

  test.each([
    ['uppercase', 'Gmail-Delegation'],
    ['leading hyphen', '-gmail'],
    ['underscore', 'gmail_delegation'],
    ['dot', 'a.b'],
    ['over 80 characters', 'a'.repeat(81)],
  ])('rejects a checkId with %s', async (_label, checkId) => {
    const res = await put(checkId, { reason: 'ok' });
    expect(res.status).toBe(400);
    expect(setWaiver).not.toHaveBeenCalled();
  });

  test('accepts an 80 character checkId', async () => {
    expect((await put('a'.repeat(80), { reason: 'ok' })).status).toBe(200);
  });

  test.each([
    ['missing', {}],
    ['empty', { reason: '' }],
    ['whitespace only', { reason: '   ' }],
    ['not a string', { reason: 12 }],
    ['over 1000 characters', { reason: 'x'.repeat(1001) }],
  ])('rejects a %s reason', async (_label, body) => {
    const res = await put('gmail-delegation', body);
    expect(res.status).toBe(400);
    expect(setWaiver).not.toHaveBeenCalled();
  });

  test('accepts a 1000 character reason', async () => {
    expect((await put('gmail-delegation', { reason: 'x'.repeat(1000) })).status).toBe(200);
  });

  describe('import', () => {
    const post = (waivers: unknown) =>
      request(app)
        .post('/api/audit/hardening/waivers/import')
        .set('Authorization', 'Bearer session')
        .send({ waivers } as object);

    test('merges trimmed valid entries', async () => {
      const res = await post({ 'gmail-delegation': ' reason ', 'drive-dlp': 'other' });
      expect(res.status).toBe(200);
      expect(mergeWaivers).toHaveBeenCalledWith(
        { 'gmail-delegation': 'reason', 'drive-dlp': 'other' },
        's@example.com'
      );
    });

    test.each([
      ['bad id', { 'Bad_ID': 'reason' }],
      ['empty reason', { 'gmail-delegation': '' }],
      ['long reason', { 'gmail-delegation': 'x'.repeat(1001) }],
      ['one bad entry among good ones', { 'drive-dlp': 'ok', 'gmail-delegation': '' }],
    ])('rejects the whole import for %s', async (_label, waivers) => {
      const res = await post(waivers);
      expect(res.status).toBe(400);
      expect(mergeWaivers).not.toHaveBeenCalled();
    });
  });
});
