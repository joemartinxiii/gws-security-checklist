import {
  humanizeApiFailure,
  policyApiMetaFromSnapshot,
  isTransientPolicyFailure,
  countEnforced2sv,
  summarize2svCoverage,
  hardeningService,
} from '../src/services/hardening.service';
import { PolicySnapshot } from '../src/services/policy.service';

describe('hardening humanizeApiFailure', () => {
  test('maps 403 without dumping JSON bodies', () => {
    const raw = 'Policy API HTTP 403: {"error":{"code":403,"message":"The caller does not have permission"}}';
    const msg = humanizeApiFailure(raw, 'Cloud Identity Policy API');
    expect(msg).toMatch(/permission denied/i);
    expect(msg).not.toMatch(/\{/);
    expect(msg).not.toMatch(/caller does not have permission/i);
  });

  test('maps 429 rate limits clearly', () => {
    const msg = humanizeApiFailure('Policy API HTTP 429', 'Cloud Identity Policy API');
    expect(msg).toMatch(/rate-limited/i);
    expect(msg).toMatch(/run the audit again/i);
  });

  test('maps generic long/JSON payloads to stable copy', () => {
    const msg = humanizeApiFailure('something went wrong ' + '{'.repeat(5) + 'x'.repeat(200), 'Directory');
    expect(msg).toMatch(/request failed/i);
    expect(msg.length).toBeLessThan(200);
  });
});

describe('policyApiMetaFromSnapshot', () => {
  test('available snapshot has no error fields', () => {
    const snap = new PolicySnapshot([], true);
    expect(policyApiMetaFromSnapshot(snap)).toEqual({ available: true });
  });

  test('403 becomes http_403 with human message', () => {
    const snap = new PolicySnapshot([], false, 'Policy API HTTP 403');
    const meta = policyApiMetaFromSnapshot(snap);
    expect(meta.available).toBe(false);
    expect(meta.code).toBe('http_403');
    expect(meta.message).toMatch(/permission denied/i);
  });

  test('429 becomes http_429 with retry guidance', () => {
    const snap = new PolicySnapshot([], false, 'Policy API HTTP 429');
    const meta = policyApiMetaFromSnapshot(snap);
    expect(meta.code).toBe('http_429');
    expect(meta.message).toMatch(/rate-limited/i);
  });
});

describe('2-Step Verification coverage', () => {
  test('pages until the directory listing ends', async () => {
    const counted = await countEnforced2sv(async (pageToken) => {
      if (!pageToken) {
        return {
          users: [{ isEnforcedIn2Sv: true }, { isEnforcedIn2Sv: false }],
          nextPageToken: 'next',
        };
      }
      return { users: [{ isEnforcedIn2Sv: true }, { isEnforcedIn2Sv: true }] };
    });
    expect(counted).toEqual({ enforced: 3, total: 4, complete: true });
    expect(summarize2svCoverage(3, 4, true)).toEqual({
      status: 'warning',
      currentValue: '75% enforced (3/4 users)',
    });
  });

  test('a truncated listing cannot pass', async () => {
    const counted = await countEnforced2sv(async () => ({
      users: [{ isEnforcedIn2Sv: true }, { isEnforcedIn2Sv: true }],
      nextPageToken: 'more',
    }), 2);
    expect(counted.complete).toBe(false);
    expect(summarize2svCoverage(counted.enforced, counted.total, counted.complete).status).toBe('warning');
    expect(summarize2svCoverage(10, 10, false).currentValue).toMatch(/cannot pass/);
    expect(summarize2svCoverage(9, 10, true).status).toBe('pass');
    expect(summarize2svCoverage(0, 0, true).status).toBe('warning');
  });

  test('an empty page with another token does not loop', async () => {
    let calls = 0;
    const counted = await countEnforced2sv(async () => {
      calls += 1;
      return { users: [], nextPageToken: 'again' };
    });
    expect(calls).toBe(1);
    expect(counted).toEqual({ enforced: 0, total: 0, complete: false });
  });
});

describe('isTransientPolicyFailure', () => {
  test('429 and 503 are transient; 403 and available are not', () => {
    expect(isTransientPolicyFailure({ available: true })).toBe(false);
    expect(isTransientPolicyFailure({ available: false, code: 'http_429' })).toBe(true);
    expect(isTransientPolicyFailure({ available: false, code: 'http_503' })).toBe(true);
    expect(isTransientPolicyFailure({ available: false, code: 'http_403' })).toBe(false);
    expect(isTransientPolicyFailure({ available: false, code: 'unavailable' })).toBe(false);
  });
});

describe('PolicySnapshot org unit choice', () => {
  test('prefers the broader org unit and counts the others', () => {
    const snap = new PolicySnapshot(
      [
        {
          setting: {
            type: 'settings/gmail.auto_forwarding',
            value: { enableAutoForwarding: false },
          },
          type: 'ADMIN',
          policyQuery: { orgUnit: 'orgUnits/child', sortOrder: 1 },
        },
        {
          setting: {
            type: 'settings/gmail.auto_forwarding',
            value: { enableAutoForwarding: true },
          },
          type: 'ADMIN',
          policyQuery: { orgUnit: 'orgUnits/root', sortOrder: 10 },
        },
      ],
      true
    );
    const lookup = snap.get('gmail.auto_forwarding');
    expect(lookup.value).toEqual({ enableAutoForwarding: true });
    expect(lookup.scopeCount).toBe(2);
  });
});

describe('published policy defaults', () => {
  const service = hardeningService as unknown as {
    policyCheck: (...args: unknown[]) => {
      status: string;
      source: string;
      currentValue: string;
      issues?: string[];
    };
    appsControlChecks: (snapshot: PolicySnapshot) => Array<{
      id: string;
      status: string;
      currentValue: string;
      issues?: string[];
    }>;
    adminAlertCheck: (snapshot: PolicySnapshot) => {
      status: string;
      currentValue: string;
      issues?: string[];
    };
  };

  const meta = {
    id: 'sample',
    category: 'Email',
    name: 'Sample',
    description: 'Sample',
    severity: 'medium' as const,
    recommendedValue: 'Off',
    rationale: 'Why',
    recommendation: 'Do this',
  };

  test('scores a missing auto-forwarding policy as the Google default', () => {
    const check = service.policyCheck(
      new PolicySnapshot([], true),
      meta,
      'gmail.auto_forwarding',
      (value: { enableAutoForwarding?: boolean }) => ({
        status: value.enableAutoForwarding ? 'info' : 'pass',
        currentValue: value.enableAutoForwarding ? 'Allowed' : 'Off',
      }),
      { defaultValue: { enableAutoForwarding: true } }
    );
    expect(check.status).toBe('info');
    expect(check.source).toBe('auto');
    expect(check.currentValue).toBe('Allowed (Google default)');
    expect(check.issues?.join(' ')).toMatch(/published default/i);
  });

  test('says how many other org units differ', () => {
    const snap = new PolicySnapshot(
      [
        {
          setting: { type: 'settings/gmail.auto_forwarding', value: { enableAutoForwarding: false } },
          type: 'ADMIN',
          policyQuery: { orgUnit: 'orgUnits/root', sortOrder: 10 },
        },
        {
          setting: { type: 'settings/gmail.auto_forwarding', value: { enableAutoForwarding: true } },
          type: 'ADMIN',
          policyQuery: { orgUnit: 'orgUnits/child', sortOrder: 1 },
        },
      ],
      true
    );
    const check = service.policyCheck(
      snap,
      meta,
      'gmail.auto_forwarding',
      () => ({ status: 'pass', currentValue: 'Off' })
    );
    expect(check.issues?.join(' ')).toMatch(/top-level org unit/);
    expect(check.issues?.join(' ')).toMatch(/1 other org unit differs/);
  });

  test('does not invent additional services when none are saved', () => {
    const [core, extra] = service
      .appsControlChecks(new PolicySnapshot([], true))
      .filter((check) => check.id === 'core-apps' || check.id === 'additional-apps');
    expect(core.status).toBe('info');
    expect(extra.status).toBe('info');
    expect(extra.currentValue).toMatch(/No explicit service changes/);
  });

  test('warns when an additional service is explicitly on', () => {
    const snap = new PolicySnapshot(
      [
        {
          setting: { type: 'settings/blogger.service_status', value: { serviceState: 'ENABLED' } },
          type: 'ADMIN',
        },
        {
          setting: { type: 'settings/gmail.service_status', value: { serviceState: 'ENABLED' } },
          type: 'ADMIN',
        },
      ],
      true
    );
    const checks = service.appsControlChecks(snap);
    expect(checks.find((check) => check.id === 'additional-apps')?.status).toBe('warning');
    expect(checks.find((check) => check.id === 'additional-apps')?.currentValue).toMatch(/Blogger/);
    expect(checks.find((check) => check.id === 'core-apps')?.status).toBe('info');
  });

  test('reads admin alert rules instead of calling them unpublished', () => {
    const snap = new PolicySnapshot(
      [
        {
          setting: {
            type: 'settings/rule.system_defined_alerts',
            value: {
              displayName: 'Admin password reset',
              state: 'ACTIVE',
              action: { alertCenterConfig: { status: 'ENABLED' } },
            },
          },
          type: 'ADMIN',
        },
      ],
      true
    );
    const check = service.adminAlertCheck(snap);
    expect(check.status).toBe('pass');
    expect(check.currentValue).toBe('1 active, 0 inactive');
  });
});
