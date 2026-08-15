import { http, HttpResponse } from 'msw';
import { hardeningData, demoHardeningWaivers, setDemoHardeningWaivers } from './fixtures';

const MOCK_USER = {
  email: 'admin@example.com',
  name: 'Mock Admin',
  allowedDomains: ['example.com'],
  protectedUsers: [] as string[],
};

function json(data: Parameters<typeof HttpResponse.json>[0]) {
  return HttpResponse.json(data);
}

const mockDriveLink = { id: 'mock-file-id', webViewLink: 'https://drive.google.com/mock' };

export const handlers = [
  http.get('*/api/auth/me', () => json(MOCK_USER)),
  http.get('*/api/auth/permissions', () =>
    json({
      permissions: ['audit.view', 'audit.export'],
      isSuperAdmin: true,
      isDelegatedAdmin: false,
    })
  ),
  http.post('*/api/auth/logout', () => json({ message: 'ok' })),

  http.get('*/api/audit/hardening', () => json({ ...hardeningData, waivers: hardeningData.waivers })),
  http.get('*/api/audit/hardening/latest', () =>
    json({ ...hardeningData, waivers: hardeningData.waivers })
  ),
  http.post('*/api/audit/hardening/run', () =>
    json({
      ...hardeningData,
      status: 'ready',
      ranAt: new Date().toISOString(),
      triggeredBy: 'admin@example.com',
      policyApi: { available: true },
      waivers: hardeningData.waivers,
    })
  ),
  http.get('*/api/audit/hardening/waivers', () => json({ waivers: hardeningData.waivers })),
  http.put('*/api/audit/hardening/waivers/:checkId', async ({ params, request }) => {
    const body = (await request.json().catch(() => ({}))) as { reason?: string };
    const checkId = String(params.checkId || '');
    const next = {
      ...demoHardeningWaivers,
      [checkId]: {
        reason: typeof body.reason === 'string' ? body.reason : '',
        waivedBy: 'admin@example.com',
        waivedAt: new Date().toISOString(),
      },
    };
    setDemoHardeningWaivers(next);
    return json({ waivers: next });
  }),
  http.delete('*/api/audit/hardening/waivers/:checkId', async ({ params }) => {
    const checkId = String(params.checkId || '');
    const next = { ...demoHardeningWaivers };
    delete next[checkId];
    setDemoHardeningWaivers(next);
    return json({ waivers: next });
  }),
  http.post('*/api/audit/hardening/waivers/import', async ({ request }) => {
    const body = (await request.json().catch(() => ({}))) as { waivers?: Record<string, string> };
    const next = { ...demoHardeningWaivers };
    const now = new Date().toISOString();
    for (const [id, reason] of Object.entries(body.waivers || {})) {
      if (id in next) continue;
      next[id] = { reason: reason || '', waivedBy: 'admin@example.com', waivedAt: now };
    }
    setDemoHardeningWaivers(next);
    return json({ waivers: next, imported: Object.keys(body.waivers || {}).length });
  }),
  http.get(
    '*/api/audit/hardening/export',
    () => new HttpResponse('csv', { headers: { 'Content-Type': 'text/csv' } })
  ),
  http.post('*/api/audit/hardening/export/drive', () => json({ ...mockDriveLink })),
];
