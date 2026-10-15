import request from 'supertest';
import { createApp } from '../src/app';
import { authService } from '../src/services/auth.service';
import { permissionsService } from '../src/services/permissions.service';

jest.mock('../src/services/auth.service', () => ({
  authService: {
    verifySessionToken: jest.fn(),
    refreshSessionToken: jest.fn(),
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

jest.mock('../src/services/hardening.service', () => ({
  hardeningService: {
    preflightPolicyApi: jest.fn(),
    runAllChecks: jest.fn(),
    listTwoSvUsers: jest.fn(async () => ({ generatedAt: '2026-01-01T00:00:00.000Z', users: [] })),
  },
  isTransientPolicyFailure: jest.fn(() => false),
}));

const roles: Record<string, { isSuperAdmin: boolean; isDelegatedAdmin: boolean }> = {
  'super@example.com': { isSuperAdmin: true, isDelegatedAdmin: false },
  'help@example.com': { isSuperAdmin: false, isDelegatedAdmin: true },
  'reader@example.com': { isSuperAdmin: false, isDelegatedAdmin: true },
  'listed-user@example.com': { isSuperAdmin: false, isDelegatedAdmin: false },
};

const storedReads = ['/api/audit/hardening', '/api/audit/hardening/latest', '/api/audit/hardening/waivers'];

describe('stored-result route gating', () => {
  const app = createApp();
  let currentUser = 'super@example.com';

  const asUser = (email: string) => {
    currentUser = email;
  };
  const get = (path: string) => request(app).get(path).set('Authorization', 'Bearer session');

  beforeEach(() => {
    jest.clearAllMocks();
    process.env.GWS_AUDIT_READERS = ' Reader@Example.com ,listed-user@example.com,';
    (authService.verifySessionToken as jest.Mock).mockImplementation(async () => ({
      email: currentUser,
      name: 'User',
    }));
    (permissionsService.getAdminRoles as jest.Mock).mockImplementation(
      async (email: string) => roles[email] ?? { isSuperAdmin: false, isDelegatedAdmin: false }
    );
  });

  afterAll(() => {
    delete process.env.GWS_AUDIT_READERS;
  });

  test.each(storedReads)('super admin reads %s', async (path) => {
    asUser('super@example.com');
    expect((await get(path)).status).toBe(200);
  });

  test('super admin reaches the export route', async () => {
    asUser('super@example.com');
    expect((await get('/api/audit/hardening/export')).status).toBe(404);
  });

  test.each([...storedReads, '/api/audit/hardening/export'])(
    'delegated admin gets 403 on %s',
    async (path) => {
      asUser('help@example.com');
      const res = await get(path);
      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/Super admin/);
    }
  );

  test.each(storedReads)('listed delegated admin reads %s', async (path) => {
    asUser('reader@example.com');
    expect((await get(path)).status).toBe(200);
  });

  test('listed delegated admin reaches the export route', async () => {
    asUser('reader@example.com');
    expect((await get('/api/audit/hardening/export')).status).toBe(404);
  });

  test('a listed email that is not an admin gets 403', async () => {
    asUser('listed-user@example.com');
    expect((await get('/api/audit/hardening')).status).toBe(403);
  });

  test('an empty GWS_AUDIT_READERS grants nothing', async () => {
    process.env.GWS_AUDIT_READERS = '';
    asUser('reader@example.com');
    expect((await get('/api/audit/hardening')).status).toBe(403);
  });

  test.each([
    ['put', '/api/audit/hardening/waivers/gmail-delegation'],
    ['delete', '/api/audit/hardening/waivers/gmail-delegation'],
    ['post', '/api/audit/hardening/waivers/import'],
    ['post', '/api/audit/hardening/run'],
    ['post', '/api/audit/hardening/export/drive'],
    ['post', '/api/audit/2sv/export/drive'],
  ] as const)('listed delegated admin gets 403 on %s %s', async (method, path) => {
    asUser('reader@example.com');
    const res = await request(app)
      [method](path)
      .set('Authorization', 'Bearer session')
      .send({ reason: 'ok', waivers: { 'gmail-delegation': 'ok' } });
    expect(res.status).toBe(403);
  });

  test('delegated admin keeps access to the 2SV report', async () => {
    asUser('help@example.com');
    expect((await get('/api/audit/2sv')).status).toBe(200);
  });

  test('permissions endpoint reports stored-result access', async () => {
    (permissionsService.getUserPermissions as jest.Mock).mockResolvedValue(['audit.view']);
    asUser('reader@example.com');
    const listed = await get('/api/auth/permissions');
    expect(listed.body.canReadStoredAudit).toBe(true);
    asUser('help@example.com');
    const unlisted = await get('/api/auth/permissions');
    expect(unlisted.body.canReadStoredAudit).toBe(false);
  });
});
