import { http, HttpResponse } from 'msw';
import { hardeningChecksToCsv } from '../utils/checklistCsv';
import { hardeningData, demoHardeningWaivers, setDemoHardeningWaivers, users } from './fixtures';

const MOCK_USER = {
  email: 'admin@example.com',
  name: 'Mock Admin',
  allowedDomains: ['example.com'],
};

function json(data: Parameters<typeof HttpResponse.json>[0]) {
  return HttpResponse.json(data);
}

const mockDriveLink = { id: 'mock-file-id', webViewLink: 'https://drive.google.com/mock' };

const WAIVER_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,79}$/;
const WAIVER_REASON_MAX = 1000;

function waiverProblem(checkId: string, reason: unknown): string | null {
  if (!WAIVER_ID_PATTERN.test(checkId)) {
    return 'checkId must be lowercase letters, digits, and hyphens (80 characters max)';
  }
  const trimmed = typeof reason === 'string' ? reason.trim() : '';
  if (!trimmed) return 'reason is required';
  if (trimmed.length > WAIVER_REASON_MAX) {
    return `reason must be ${WAIVER_REASON_MAX} characters or fewer`;
  }
  return null;
}

export const handlers = [
  http.get('*/api/auth/me', () => json(MOCK_USER)),
  http.get('*/api/auth/permissions', () =>
    json({
      permissions: ['audit.view', 'audit.export'],
      isSuperAdmin: true,
      isDelegatedAdmin: false,
      canReadStoredAudit: true,
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
      policyApi: hardeningData.policyApi,
      waivers: hardeningData.waivers,
    })
  ),
  http.get('*/api/audit/hardening/waivers', () => json({ waivers: hardeningData.waivers })),
  http.put('*/api/audit/hardening/waivers/:checkId', async ({ params, request }) => {
    const body = (await request.json().catch(() => ({}))) as { reason?: string };
    const checkId = String(params.checkId || '');
    const problem = waiverProblem(checkId, body.reason);
    if (problem) return HttpResponse.json({ error: problem }, { status: 400 });
    const next = {
      ...demoHardeningWaivers,
      [checkId]: {
        reason: body.reason!.trim(),
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
    const body = (await request.json().catch(() => ({}))) as { waivers?: Record<string, unknown> };
    const incoming = body.waivers;
    if (!incoming || typeof incoming !== 'object' || Array.isArray(incoming)) {
      return HttpResponse.json({ error: 'waivers object is required' }, { status: 400 });
    }
    for (const [id, reason] of Object.entries(incoming)) {
      const problem = waiverProblem(id, reason);
      if (problem) {
        return HttpResponse.json(
          { error: `Invalid waiver "${id.slice(0, 80)}": ${problem}` },
          { status: 400 }
        );
      }
    }
    const next = { ...demoHardeningWaivers };
    const now = new Date().toISOString();
    for (const [id, reason] of Object.entries(incoming)) {
      if (id in next) continue;
      next[id] = {
        reason: String(reason).trim(),
        waivedBy: 'admin@example.com',
        waivedAt: now,
      };
    }
    setDemoHardeningWaivers(next);
    return json({ waivers: next, imported: Object.keys(incoming).length });
  }),
  http.get('*/api/audit/hardening/export', () => {
    const csv = hardeningChecksToCsv(hardeningData.checks, hardeningData.waivers);
    return new HttpResponse(csv, {
      headers: { 'Content-Type': 'text/csv;charset=utf-8' },
    });
  }),
  http.post('*/api/audit/hardening/export/drive', () => json({ ...mockDriveLink })),
  http.get('*/api/audit/2sv', () =>
    json({
      generatedAt: '2026-07-09T15:00:00.000Z',
      truncated: false,
      users: users.map((user) => ({
        name: user.name.fullName,
        email: user.primaryEmail,
        enrolled: user.isEnrolledIn2Sv === true,
        enforced: user.isEnforcedIn2Sv === true,
      })),
    })
  ),
  http.post('*/api/audit/2sv/export/drive', () => json({ ...mockDriveLink })),
];
