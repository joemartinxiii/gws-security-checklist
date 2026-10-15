import {
  humanizeApiFailure,
  policyApiMetaFromSnapshot,
  isTransientPolicyFailure,
  countEnforced2sv,
  summarize2svCoverage,
  evaluate2svEnforcement,
  evaluatePasswordPolicy,
  computeHardeningScore,
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

  test('carries snapshot warnings and the partial flag', () => {
    const snap = new PolicySnapshot([], true, undefined, {
      partial: true,
      warnings: ['The policy list was cut off after 200 pages. Results may be incomplete.'],
    });
    expect(policyApiMetaFromSnapshot(snap)).toEqual({
      available: true,
      partial: true,
      warnings: ['The policy list was cut off after 200 pages. Results may be incomplete.'],
    });
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

type Fixture = ConstructorParameters<typeof PolicySnapshot>[0][number];

function policy(
  type: string,
  value: Record<string, unknown>,
  orgUnit: string | null,
  sortOrder: number,
  extra: { kind?: 'ADMIN' | 'SYSTEM'; group?: string; query?: string } = {}
): Fixture {
  return {
    setting: { type: `settings/${type}`, value },
    type: extra.kind ?? 'ADMIN',
    policyQuery: {
      ...(orgUnit ? { orgUnit: `orgUnits/${orgUnit}` } : {}),
      ...(extra.group ? { group: extra.group } : {}),
      ...(extra.query ? { query: extra.query } : {}),
      sortOrder,
    },
  };
}

/** Google attaches SYSTEM defaults to the root org unit; this marks which one it is. */
const rootMarker = (root = 'root') => policy('security.password', {}, root, 1, { kind: 'SYSTEM' });

describe('PolicySnapshot root org unit', () => {
  test('derives the root from SYSTEM policies and strips the prefix', () => {
    const snap = new PolicySnapshot(
      [rootMarker('root'), rootMarker('root'), rootMarker('other'), policy('a.b', {}, 'child', 9)],
      true
    );
    expect(snap.rootOrgUnitId).toBe('root');
  });

  test('ignores group-scoped SYSTEM policies', () => {
    const snap = new PolicySnapshot(
      [rootMarker('root'), policy('a.b', {}, 'other', 1, { kind: 'SYSTEM', group: 'groups/g1' }), policy('a.c', {}, 'other', 1, { kind: 'SYSTEM', group: 'groups/g2' })],
      true
    );
    expect(snap.rootOrgUnitId).toBe('root');
  });

  test('is null when SYSTEM policies tie or are absent, and says so', () => {
    const tie = new PolicySnapshot([rootMarker('a'), rootMarker('b')], true);
    expect(tie.rootOrgUnitId).toBeNull();
    expect(tie.warnings.join(' ')).toMatch(/top-level org unit could not be identified/);

    const none = new PolicySnapshot([policy('a.b', {}, 'root', 1)], true);
    expect(none.rootOrgUnitId).toBeNull();
    expect(none.warnings).toHaveLength(1);

    expect(new PolicySnapshot([], true).warnings).toEqual([]);
  });
});

describe('PolicySnapshot effective value', () => {
  const type = 'gmail.auto_forwarding';

  test('a child override does not leak into the root value', () => {
    const snap = new PolicySnapshot(
      [
        rootMarker(),
        policy(type, { enableAutoForwarding: false }, 'root', 10),
        policy(type, { enableAutoForwarding: true }, 'child', 20),
      ],
      true
    );
    const lookup = snap.get(type);
    expect(lookup.value).toEqual({ enableAutoForwarding: false });
    expect(lookup.overrideCount).toBe(1);
  });

  test('a SYSTEM-only root returns the SYSTEM value', () => {
    const snap = new PolicySnapshot(
      [rootMarker(), policy(type, { enableAutoForwarding: true }, 'root', 5, { kind: 'SYSTEM' })],
      true
    );
    expect(snap.get(type)).toMatchObject({
      found: true,
      value: { enableAutoForwarding: true },
      overrideCount: 0,
    });
  });

  test('a root ADMIN policy beats a lower-sortOrder SYSTEM policy', () => {
    const snap = new PolicySnapshot(
      [
        rootMarker(),
        policy(type, { enableAutoForwarding: true }, 'root', 5, { kind: 'SYSTEM' }),
        policy(type, { enableAutoForwarding: false }, 'root', 50),
      ],
      true
    );
    expect(snap.get(type).value).toEqual({ enableAutoForwarding: false });
  });

  test('counts overrides only when the value differs', () => {
    const snap = new PolicySnapshot(
      [
        rootMarker(),
        policy(type, { enableAutoForwarding: false }, 'root', 10),
        policy(type, { enableAutoForwarding: false }, 'same', 20),
        policy(type, { enableAutoForwarding: true }, 'differs', 21),
        policy(type, { enableAutoForwarding: true }, 'root', 22, { group: 'groups/ops' }),
        policy(type, { enableAutoForwarding: true }, 'differs', 23, { kind: 'SYSTEM' }),
      ],
      true
    );
    expect(snap.get(type).overrideCount).toBe(2);
    expect(snap.overrides(type).map((scope) => scope.kind).sort()).toEqual(['group', 'orgUnit', 'orgUnit']);
  });

  test('returns not found when only child org units have a policy', () => {
    const snap = new PolicySnapshot(
      [rootMarker(), policy(type, { enableAutoForwarding: true }, 'child', 20)],
      true
    );
    expect(snap.get(type).found).toBe(false);
  });

  test('a merge-reducer setting takes each field from the highest policy that has it', () => {
    const merged = new PolicySnapshot(
      [
        rootMarker(),
        policy('groups_for_business.groups_sharing', { createGroupsAccessLevel: 'USERS_IN_DOMAIN', ownersCanAllowExternalMembers: false }, 'root', 5, { kind: 'SYSTEM' }),
        policy('groups_for_business.groups_sharing', { createGroupsAccessLevel: 'ADMIN_ONLY' }, 'root', 50),
      ],
      true
    ).get('groups_for_business.groups_sharing');
    expect(merged.value).toEqual({ createGroupsAccessLevel: 'ADMIN_ONLY', ownersCanAllowExternalMembers: false });

    const max = new PolicySnapshot(
      [
        rootMarker(),
        policy(type, { enableAutoForwarding: true, other: 1 }, 'root', 5, { kind: 'SYSTEM' }),
        policy(type, { enableAutoForwarding: false }, 'root', 50),
      ],
      true
    ).get(type);
    expect(max.value).toEqual({ enableAutoForwarding: false });
  });

  test('prefers root policies without a license clause and flags license-only values', () => {
    const license = "entity.licenses.exists(license, license in ['/product/Google-Apps/sku/1'])";
    const both = new PolicySnapshot(
      [
        rootMarker(),
        policy(type, { enableAutoForwarding: false }, 'root', 10),
        policy(type, { enableAutoForwarding: true }, 'root', 90, { query: license }),
      ],
      true
    ).get(type);
    expect(both).toMatchObject({ value: { enableAutoForwarding: false }, licenseConditional: false });

    const only = new PolicySnapshot(
      [rootMarker(), policy(type, { enableAutoForwarding: true }, 'root', 90, { query: license })],
      true
    ).get(type);
    expect(only).toMatchObject({ value: { enableAutoForwarding: true }, licenseConditional: true });
  });

  test('without a known root, the lowest-sortOrder org unit stands in', () => {
    const snap = new PolicySnapshot(
      [
        policy(type, { enableAutoForwarding: true }, 'child', 40),
        policy(type, { enableAutoForwarding: false }, 'top', 10),
      ],
      true
    );
    expect(snap.get(type).value).toEqual({ enableAutoForwarding: false });
    expect(snap.get(type).overrideCount).toBe(1);
    expect(snap.warnings).toHaveLength(1);
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

  test('says how many other org units or groups override the setting', () => {
    const snap = new PolicySnapshot(
      [
        rootMarker(),
        policy('gmail.auto_forwarding', { enableAutoForwarding: false }, 'root', 10),
        policy('gmail.auto_forwarding', { enableAutoForwarding: true }, 'child', 20),
        policy('gmail.auto_forwarding', { enableAutoForwarding: true }, 'root', 30, { group: 'groups/ops' }),
        policy('gmail.auto_forwarding', { enableAutoForwarding: false }, 'quiet', 40),
      ],
      true
    );
    const check = service.policyCheck(snap, meta, 'gmail.auto_forwarding', () => ({
      status: 'pass',
      currentValue: 'Off',
    }));
    expect(check.issues?.join(' ')).toMatch(/top-level org unit/);
    expect(check.issues?.join(' ')).toMatch(/2 other org units or groups override this setting/);
  });

  test('stays quiet when other scopes match the root', () => {
    const snap = new PolicySnapshot(
      [
        rootMarker(),
        policy('gmail.auto_forwarding', { enableAutoForwarding: false }, 'root', 10),
        policy('gmail.auto_forwarding', { enableAutoForwarding: false }, 'child', 20),
      ],
      true
    );
    const check = service.policyCheck(snap, meta, 'gmail.auto_forwarding', () => ({
      status: 'pass',
      currentValue: 'Off',
    }));
    expect(check.issues).toBeUndefined();
  });

  test('mentions license-conditional values', () => {
    const snap = new PolicySnapshot(
      [
        rootMarker(),
        policy('gmail.auto_forwarding', { enableAutoForwarding: false }, 'root', 10, {
          query: "entity.licenses.exists(license, license in ['/product/Google-Apps/sku/1'])",
        }),
      ],
      true
    );
    const check = service.policyCheck(snap, meta, 'gmail.auto_forwarding', () => ({
      status: 'pass',
      currentValue: 'Off',
    }));
    expect(check.issues?.join(' ')).toMatch(/specific license/);
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

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const svc = hardeningService as any;

function evalCheck(checks: Array<{ id: string }>, id: string) {
  const found = checks.find((c) => c.id === id);
  if (!found) throw new Error(`check ${id} not found`);
  return found as {
    id: string;
    category: string;
    status: string;
    severity: string;
    currentValue: string;
    issues?: string[];
  };
}

function mockDirectory(
  responses: Record<string, Array<Record<string, unknown>>>,
  calls: Array<Record<string, unknown>> = []
) {
  const list = jest.fn(async (params: Record<string, unknown>) => {
    calls.push(params);
    const key = String(params.query ?? '');
    return { data: { users: responses[key] ?? [] } };
  });
  jest.spyOn(svc, 'adminFor').mockResolvedValue({ users: { list } });
  return list;
}

afterEach(() => {
  jest.restoreAllMocks();
});

describe('2-Step Verification enforcement policy', () => {
  const type = 'security.two_step_verification_enforcement';
  const now = new Date('2026-10-15T12:00:00Z');
  const snap = (...policies: Fixture[]) => new PolicySnapshot([rootMarker(), ...policies], true);

  test('passes when the root enforces from a past date', () => {
    const result = evaluate2svEnforcement(snap(policy(type, { enforcedFrom: '2026-01-01T00:00:00Z' }, 'root', 5)), now);
    expect(result.status).toBe('pass');
    expect(result.currentValue).toMatch(/since 2026-01-01/);
  });

  test('warns when enforcement starts in the future', () => {
    const result = evaluate2svEnforcement(snap(policy(type, { enforcedFrom: '2026-12-01T00:00:00Z' }, 'root', 5)), now);
    expect(result.status).toBe('warning');
    expect(result.currentValue).toMatch(/starts 2026-12-01/);
  });

  test('fails when nothing is set', () => {
    expect(evaluate2svEnforcement(snap(), now).status).toBe('fail');
    expect(evaluate2svEnforcement(snap(policy(type, {}, 'root', 5)), now).status).toBe('fail');
  });

  test('warns when only a child org unit or group enforces', () => {
    const result = evaluate2svEnforcement(
      snap(policy(type, { enforcedFrom: '2026-01-01T00:00:00Z' }, 'child', 20)),
      now
    );
    expect(result.status).toBe('warning');
    expect(result.currentValue).toMatch(/1 org unit or group only/);
  });

  test('warns when a child org unit turns enforcement off under an enforcing root', () => {
    const result = evaluate2svEnforcement(
      snap(
        policy(type, { enforcedFrom: '2026-01-01T00:00:00Z' }, 'root', 5),
        policy(type, {}, 'child', 20)
      ),
      now
    );
    expect(result.status).toBe('warning');
  });

  test('check uses the policy, excludes suspended users, and keeps the ratio as detail', async () => {
    const calls: Array<Record<string, unknown>> = [];
    mockDirectory({ 'isSuspended=false': [{ isEnforcedIn2Sv: true }, { isEnforcedIn2Sv: false }] }, calls);
    const check = await svc.check2FAEnforcement(
      'admin@example.com',
      snap(policy(type, { enforcedFrom: '2026-01-01T00:00:00Z' }, 'root', 5)),
      now
    );
    expect(check.status).toBe('pass');
    expect(calls[0].query).toBe('isSuspended=false');
    expect(check.issues.join(' ')).toMatch(/50% enforced \(1\/2 users\)/);
  });

  test('falls back to the ratio and says so when the Policy API is unavailable', async () => {
    mockDirectory({ 'isSuspended=false': [{ isEnforcedIn2Sv: true }, { isEnforcedIn2Sv: true }] });
    const check = await svc.check2FAEnforcement(
      'admin@example.com',
      new PolicySnapshot([], false, 'Policy API HTTP 403'),
      now
    );
    expect(check.status).toBe('pass');
    expect(check.issues.join(' ')).toMatch(/Policy API is unavailable/);
  });
});

describe('password policy', () => {
  const base = { allowedStrength: 'STRONG', enforceRequirementsAtLogin: true, minimumLength: 12 };

  test('passes only with strong, enforced, and 12 or more characters', () => {
    expect(evaluatePasswordPolicy(base).status).toBe('pass');
    expect(evaluatePasswordPolicy({ ...base, minimumLength: 11 }).status).toBe('warning');
    expect(evaluatePasswordPolicy({ ...base, enforceRequirementsAtLogin: false }).status).toBe('warning');
    expect(evaluatePasswordPolicy({ allowedStrength: 'STRONG', enforceRequirementsAtLogin: true }).status).toBe('warning');
    expect(evaluatePasswordPolicy({ ...base, allowedStrength: 'WEAK' }).status).toBe('fail');
  });

  test('reads a minimum length sent as a string', () => {
    expect(evaluatePasswordPolicy({ ...base, minimumLength: '14' }).status).toBe('pass');
    expect(evaluatePasswordPolicy({ ...base, minimumLength: '8' }).currentValue).toMatch(/min length: 8/);
  });
});

describe('hardening score', () => {
  test('weights by severity and gives warnings half credit', () => {
    const score = computeHardeningScore([
      { status: 'pass', severity: 'critical' },
      { status: 'warning', severity: 'high' },
      { status: 'fail', severity: 'medium' },
      { status: 'pass', severity: 'low' },
      { status: 'manual', severity: 'critical' },
      { status: 'info', severity: 'high' },
    ]);
    // (4 + 1.5 + 0 + 1) / (4 + 3 + 2 + 1) = 65%
    expect(score).toBe(65);
  });

  test('is null when nothing is graded and 100 when everything passes', () => {
    expect(computeHardeningScore([])).toBeNull();
    expect(computeHardeningScore([{ status: 'manual', severity: 'high' }, { status: 'info', severity: 'low' }])).toBeNull();
    expect(computeHardeningScore([{ status: 'pass', severity: 'high' }])).toBe(100);
    expect(computeHardeningScore([{ status: 'fail', severity: 'high' }])).toBe(0);
  });
});

describe('administrator account checks', () => {
  const admins = (n: number) => Array.from({ length: n }, (_, i) => ({ primaryEmail: `admin${i}@example.com` }));

  test.each([
    [0, 'warning'],
    [1, 'warning'],
    [2, 'pass'],
    [4, 'pass'],
    [5, 'warning'],
  ])('super-admin-count with %i super admins is %s', async (count, status) => {
    const list = mockDirectory({ 'isAdmin=true': admins(count) });
    const check = await svc.checkSuperAdminCount('admin@example.com');
    expect(check.id).toBe('super-admin-count');
    expect(check.category).toBe('Administrator Accounts');
    expect(check.status).toBe(status);
    expect(list.mock.calls[0][0]).toMatchObject({ query: 'isAdmin=true', fields: expect.stringContaining('users(') });
  });

  test('super-admin-count ignores suspended super admins', async () => {
    mockDirectory({
      'isAdmin=true': [...admins(2), { primaryEmail: 'old@example.com', suspended: true }],
    });
    expect((await svc.checkSuperAdminCount('admin@example.com')).currentValue).toBe('2 super admins');
  });

  test('super-admin-count is manual when the Directory call fails', async () => {
    jest.spyOn(svc, 'adminFor').mockRejectedValue(new Error('Request failed with 403'));
    const check = await svc.checkSuperAdminCount('admin@example.com');
    expect(check.status).toBe('manual');
  });

  test('admin-2sv passes when every admin is enrolled', async () => {
    mockDirectory({
      'isAdmin=true': [{ primaryEmail: 'a@example.com', isEnrolledIn2Sv: true }],
      'isDelegatedAdmin=true': [{ primaryEmail: 'd@example.com', isEnrolledIn2Sv: true }],
    });
    const check = await svc.checkAdminTwoSv('admin@example.com');
    expect(check.status).toBe('pass');
    expect(check.currentValue).toBe('2 of 2 admins enrolled');
  });

  test('admin-2sv fails when a super admin is not enrolled', async () => {
    mockDirectory({
      'isAdmin=true': [
        { primaryEmail: 'a@example.com', isEnrolledIn2Sv: true },
        { primaryEmail: 'b@example.com', isEnrolledIn2Sv: false },
      ],
      'isDelegatedAdmin=true': [],
    });
    const check = await svc.checkAdminTwoSv('admin@example.com');
    expect(check.status).toBe('fail');
    expect(check.issues[0]).toMatch(/b@example.com/);
  });

  test('admin-2sv only warns when a delegated admin is not enrolled', async () => {
    mockDirectory({
      'isAdmin=true': [{ primaryEmail: 'a@example.com', isEnrolledIn2Sv: true }],
      'isDelegatedAdmin=true': [{ primaryEmail: 'd@example.com', isEnrolledIn2Sv: false }],
    });
    expect((await svc.checkAdminTwoSv('admin@example.com')).status).toBe('warning');
  });

  test('super-admin-recovery passes when off and warns when on', () => {
    const type = 'security.super_admin_account_recovery';
    const off = svc.administratorAccountPolicyChecks(
      new PolicySnapshot([rootMarker(), policy(type, { enableAccountRecovery: false }, 'root', 5)], true)
    );
    const on = svc.administratorAccountPolicyChecks(
      new PolicySnapshot([rootMarker(), policy(type, { enableAccountRecovery: true }, 'root', 5)], true)
    );
    expect(evalCheck(off, 'super-admin-recovery').status).toBe('pass');
    expect(evalCheck(on, 'super-admin-recovery').status).toBe('warning');
    expect(evalCheck(svc.administratorAccountPolicyChecks(new PolicySnapshot([], true)), 'super-admin-recovery').status).toBe('pass');
  });
});

describe('Gmail, apps, Drive, Groups, and Chat policy checks', () => {
  const snap = (...policies: Fixture[]) => new PolicySnapshot([rootMarker(), ...policies], true);

  test('gmail-pop-imap passes with both off and warns when either is on', () => {
    const run = (pop: boolean, imap: boolean) =>
      evalCheck(
        svc.emailChecks(
          snap(
            policy('gmail.pop_access', { enablePopAccess: pop }, 'root', 5),
            policy('gmail.imap_access', { enableImapAccess: imap }, 'root', 5)
          )
        ),
        'gmail-pop-imap'
      );
    expect(run(false, false).status).toBe('pass');
    expect(run(true, false).status).toBe('warning');
    expect(run(false, true).status).toBe('warning');
    expect(evalCheck(svc.emailChecks(snap()), 'gmail-pop-imap').status).toBe('manual');
  });

  test('gmail-comprehensive-storage and gmail-ip-allowlist read their fields', () => {
    const on = svc.emailChecks(
      snap(
        policy('gmail.comprehensive_mail_storage', { ruleId: 'abc' }, 'root', 5),
        policy('gmail.email_spam_filter_ip_allowlist', { allowedIpAddresses: ['10.0.0.1'] }, 'root', 5)
      )
    );
    expect(evalCheck(on, 'gmail-comprehensive-storage').status).toBe('pass');
    expect(evalCheck(on, 'gmail-ip-allowlist').status).toBe('warning');
    const off = svc.emailChecks(snap());
    expect(evalCheck(off, 'gmail-comprehensive-storage').status).toBe('warning');
    expect(evalCheck(off, 'gmail-ip-allowlist').status).toBe('pass');
  });

  test('gmail-comprehensive-storage is off when its rule is turned off', () => {
    const checks = svc.emailChecks(
      snap(
        policy('gmail.comprehensive_mail_storage', { ruleId: 'abc' }, 'root', 5),
        policy('gmail.rule_states', { ruleStates: [{ ruleId: 'abc', enabled: false }] }, 'root', 5)
      )
    );
    expect(evalCheck(checks, 'gmail-comprehensive-storage')).toMatchObject({ status: 'warning', currentValue: 'Off' });
  });

  test('gmail-spam-bypass reports unauthenticated and domain approved senders', () => {
    const checks = svc.emailChecks(
      snap(
        policy('gmail.spam_override_lists', { spamOverride: [{ bypassSelectedSenders: true }] }, 'root', 5),
        policy(
          'gmail.email_address_lists',
          {
            emailAddressList: [
              {
                id: 'l1',
                addressList: {
                  address: [
                    { address: 'boss@partner.com', requireAddressVerification: true },
                    { address: 'partner.com', requireAddressVerification: false },
                  ],
                },
              },
            ],
          },
          'root',
          5
        )
      )
    );
    const check = evalCheck(checks, 'gmail-spam-bypass');
    expect(check.status).toBe('warning');
    expect(check.issues?.join(' ')).toMatch(/1 approved sender does not require authentication/);
    expect(check.issues?.join(' ')).toMatch(/1 approved sender is a whole domain/);
  });

  test('third-party-apps passes when blocked or limited and warns when open', () => {
    const type = 'api_controls.unconfigured_third_party_apps';
    const run = (level: string) =>
      evalCheck(svc.appsControlChecks(snap(policy(type, { accessLevel: level }, 'root', 5))), 'third-party-apps');
    expect(run('BLOCK_ALL').status).toBe('pass');
    expect(run('ALLOW_SIGN_IN_ONLY').status).toBe('pass');
    expect(run('ACCESS_LEVEL_UNSPECIFIED').status).toBe('warning');
    expect(evalCheck(svc.appsControlChecks(snap()), 'third-party-apps').status).toBe('warning');
  });

  test('drive field checks read external sharing fields and Google defaults', () => {
    const type = 'drive_and_docs.external_sharing';
    const configured = svc.driveChecks(
      snap(
        policy(
          type,
          {
            externalSharingMode: 'ALLOWED',
            warnForExternalSharing: true,
            allowPublishingFiles: false,
            allowNonGoogleInvites: true,
            allowReceivingExternalFiles: false,
            allowedPartiesForDistributingContent: 'ELIGIBLE_INTERNAL_USERS',
          },
          'root',
          5
        )
      )
    );
    expect(evalCheck(configured, 'drive-external-warning').status).toBe('pass');
    expect(evalCheck(configured, 'drive-publishing').status).toBe('pass');
    expect(evalCheck(configured, 'drive-non-google-invites').status).toBe('warning');
    expect(evalCheck(configured, 'drive-receive-external').status).toBe('info');
    expect(evalCheck(configured, 'drive-shared-drive-move').status).toBe('pass');

    const defaults = svc.driveChecks(snap());
    expect(evalCheck(defaults, 'drive-publishing').status).toBe('warning');
    expect(evalCheck(defaults, 'drive-publishing').currentValue).toMatch(/Google default/);
    expect(evalCheck(defaults, 'drive-shared-drive-move').status).toBe('warning');
  });

  test('drive publishing is not a finding when external sharing is off', () => {
    const checks = svc.driveChecks(
      snap(policy('drive_and_docs.external_sharing', { externalSharingMode: 'DISALLOWED' }, 'root', 5))
    );
    expect(evalCheck(checks, 'drive-publishing').status).toBe('pass');
  });

  test('groups-creation passes only for admin-only creation', () => {
    const type = 'groups_for_business.groups_sharing';
    const run = (level: string) =>
      evalCheck(svc.groupsChecks(snap(policy(type, { createGroupsAccessLevel: level }, 'root', 5))), 'groups-creation');
    expect(run('ADMIN_ONLY').status).toBe('pass');
    expect(run('USERS_IN_DOMAIN').status).toBe('warning');
    expect(evalCheck(svc.groupsChecks(snap()), 'groups-creation').status).toBe('warning');
  });

  test('groups-external-access needs a closed domain, no external members, and no public mail', () => {
    const type = 'groups_for_business.groups_sharing';
    const closed = svc.groupsChecks(
      snap(
        policy(
          type,
          {
            collaborationCapability: 'DOMAIN_USERS_ONLY',
            ownersCanAllowExternalMembers: false,
            ownersCanAllowIncomingMailFromPublic: false,
          },
          'root',
          5
        )
      )
    );
    expect(evalCheck(closed, 'groups-external-access').status).toBe('pass');
    // Google's default allows public incoming mail.
    expect(evalCheck(svc.groupsChecks(snap()), 'groups-external-access').status).toBe('warning');
  });

  test('chat-external passes when off or limited to trusted domains', () => {
    const type = 'chat.external_chat_restriction';
    const run = (value: Record<string, unknown>) =>
      evalCheck(svc.chatChecks(snap(policy(type, value, 'root', 5))), 'chat-external');
    expect(run({ allowExternalChat: false }).status).toBe('pass');
    expect(run({ allowExternalChat: true, externalChatRestriction: 'TRUSTED_DOMAINS' }).status).toBe('pass');
    expect(run({ allowExternalChat: true, externalChatRestriction: 'NO_RESTRICTION' }).status).toBe('warning');
    expect(evalCheck(svc.chatChecks(snap()), 'chat-external').status).toBe('pass');
  });

  test('security-keys passes when any scope is limited to keys or passkeys', () => {
    const type = 'security.two_step_verification_enforcement_factor';
    const noneRestricted = evalCheck(
      svc.authenticationChecks(snap(policy(type, { allowedSignInFactorSet: 'ALL' }, 'root', 5))),
      'security-keys'
    );
    expect(noneRestricted.status).toBe('info');
    expect(noneRestricted.currentValue).toMatch(/Top-level: Any method/);

    const adminGroup = evalCheck(
      svc.authenticationChecks(
        snap(
          policy(type, { allowedSignInFactorSet: 'ALL' }, 'root', 5),
          policy(type, { allowedSignInFactorSet: 'PASSKEY_ONLY' }, 'root', 30, { group: 'groups/admins' })
        )
      ),
      'security-keys'
    );
    expect(adminGroup.status).toBe('pass');
    expect(adminGroup.currentValue).toMatch(/1 org unit or group/);
  });

  test('less-secure-apps is low severity and the admin alert check is in Alerts', () => {
    const lsa = evalCheck(svc.dataDownloadChecks(snap()), 'less-secure-apps');
    expect(lsa.severity).toBe('low');
    expect(lsa.status).toBe('pass');
    expect(evalCheck([svc.adminAlertCheck(snap())], 'chrome-admin-alerts').category).toBe('Alerts');
  });
});

describe('withRetry Retry-After', () => {
  test('waits for an HTTP-date Retry-After on a 429', async () => {
    const delays: number[] = [];
    jest.spyOn(global, 'setTimeout').mockImplementation(((fn: () => void, ms?: number) => {
      delays.push(ms ?? 0);
      fn();
      return 0 as unknown as NodeJS.Timeout;
    }) as typeof setTimeout);
    const retryAt = new Date(Date.now() + 8000).toUTCString();
    const operation = jest
      .fn()
      .mockRejectedValueOnce({ response: { status: 429, headers: { 'retry-after': retryAt } } })
      .mockResolvedValueOnce('ok');

    await expect(svc.withRetry(operation)).resolves.toBe('ok');
    expect(delays[0]).toBeGreaterThan(5000);
    expect(delays[0]).toBeLessThanOrEqual(8000);
  });

  test('falls back to backoff when the header is unreadable', async () => {
    const delays: number[] = [];
    jest.spyOn(global, 'setTimeout').mockImplementation(((fn: () => void, ms?: number) => {
      delays.push(ms ?? 0);
      fn();
      return 0 as unknown as NodeJS.Timeout;
    }) as typeof setTimeout);
    const operation = jest
      .fn()
      .mockRejectedValueOnce({ response: { status: 429, headers: { 'retry-after': 'soon' } } })
      .mockResolvedValueOnce('ok');
    await svc.withRetry(operation, 3, 250);
    expect(delays[0]).toBe(250);
  });
});
