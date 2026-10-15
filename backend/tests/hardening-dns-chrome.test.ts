import { hardeningService } from '../src/services/hardening.service';
import { PolicySnapshot } from '../src/services/policy.service';
import { dnsCheckService, type DNSRecord } from '../src/services/dns-check.service';
import { chromePolicyService, ChromePolicyApiError } from '../src/services/chrome-policy.service';

function dnsRecords(domain: string): DNSRecord[] {
  return (['SPF', 'DKIM', 'DMARC', 'MX'] as const).map((type) => ({
    type,
    domain,
    status: 'pass' as const,
    currentValue: 'ok',
  }));
}

function arrange(rootOrgUnitPolicies: any[] = []) {
  jest.spyOn(hardeningService as any, 'check2FAEnforcement').mockResolvedValue({
    id: '2sv-enforcement',
    category: 'Authentication',
    name: '2SV',
    description: '2SV',
    status: 'pass',
    source: 'auto',
    severity: 'high',
    rationale: '',
    recommendation: '',
  });
  jest.spyOn(dnsCheckService, 'checkAllDNS').mockImplementation(async (d: string) => dnsRecords(d));
  return new PolicySnapshot(rootOrgUnitPolicies, true);
}

afterEach(() => jest.restoreAllMocks());

describe('runAllChecks DNS block', () => {
  test('primary domain keeps the plain ids and extra domains get slugged ids and named checks', async () => {
    const snapshot = arrange();
    jest.spyOn(chromePolicyService, 'getAllPolicyChecks').mockResolvedValue([]);
    const { checks } = await hardeningService.runAllChecks('admin@example.com', 'example.com', snapshot);
    const dns = checks.filter((c) => c.id.startsWith('dns-'));

    expect(dns.map((c) => c.id)).toEqual([
      'dns-spf',
      'dns-dkim',
      'dns-dmarc',
      'dns-mx',
      'dns-spf-subsidiary-com',
      'dns-dkim-subsidiary-com',
      'dns-dmarc-subsidiary-com',
      'dns-mx-subsidiary-com',
    ]);
    expect(dns.find((c) => c.id === 'dns-spf')?.name).toBe('SPF Record (example.com)');
    expect(dns.find((c) => c.id === 'dns-mx-subsidiary-com')).toMatchObject({
      name: 'MX Record (subsidiary.com)',
      category: 'Email',
      severity: 'high',
    });
  });

  test('a single domain keeps the original check names', async () => {
    const snapshot = arrange();
    jest.spyOn(chromePolicyService, 'getAllPolicyChecks').mockResolvedValue([]);
    const saved = process.env.GWS_ALLOWED_DOMAINS;
    process.env.GWS_ALLOWED_DOMAINS = 'example.com';
    try {
      const { checks } = await hardeningService.runAllChecks('admin@example.com', 'example.com', snapshot);
      expect(checks.filter((c) => c.id.startsWith('dns-')).map((c) => c.name)).toEqual([
        'SPF Record',
        'DKIM Record',
        'DMARC Record',
        'MX Record',
      ]);
    } finally {
      process.env.GWS_ALLOWED_DOMAINS = saved;
    }
  });
});

describe('runAllChecks Chrome block', () => {
  test('a Chrome Policy API failure becomes one warning and no Chrome checks', async () => {
    const snapshot = arrange();
    jest
      .spyOn(chromePolicyService, 'getAllPolicyChecks')
      .mockRejectedValue(new ChromePolicyApiError('Chrome Policy API is not enabled for the Google Cloud project.'));
    const { checks } = await hardeningService.runAllChecks('admin@example.com', 'example.com', snapshot);
    const chrome = checks.filter((c) => c.id.startsWith('chrome-') && c.id !== 'chrome-admin-alerts');

    expect(chrome).toHaveLength(1);
    expect(chrome[0]).toMatchObject({ id: 'chrome-policy-api', status: 'warning', category: 'Chrome Browser' });
    expect(chrome[0].issues?.[0]).toMatch(/not enabled/);
    expect(chrome[0].issues?.[0]).not.toMatch(/no managed browsers/i);
  });

  test('passes the snapshot root org unit to the Chrome service', async () => {
    const snapshot = arrange([
      {
        type: 'SYSTEM',
        policyQuery: { orgUnit: 'orgUnits/03ph8a2z1' },
        setting: { type: 'settings/gmail.mail_delegation', value: {} },
      },
    ]);
    const spy = jest.spyOn(chromePolicyService, 'getAllPolicyChecks').mockResolvedValue([]);
    await hardeningService.runAllChecks('admin@example.com', 'example.com', snapshot);
    expect(spy).toHaveBeenCalledWith('admin@example.com', '03ph8a2z1');
  });

  test('a manual Chrome check is reported with source manual', async () => {
    const snapshot = arrange();
    const checks = await chromePolicyService.getAllPolicyChecks('admin@example.com', null);
    jest.spyOn(chromePolicyService, 'getAllPolicyChecks').mockResolvedValue(checks);
    const result = await hardeningService.runAllChecks('admin@example.com', 'example.com', snapshot);
    const safe = result.checks.find((c) => c.id === 'chrome-safe-browsing');
    expect(safe).toMatchObject({ status: 'manual', source: 'manual', currentValue: 'Not verified' });
  });
});
