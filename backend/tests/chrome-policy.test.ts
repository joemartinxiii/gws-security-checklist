import { ChromePolicyApiError, ChromePolicyService } from '../src/services/chrome-policy.service';

const ALL_SCHEMAS = [
  'chrome.users.RelaunchNotificationWithDurationV2',
  'chrome.users.SafeBrowsingProtectionLevel',
  'chrome.users.DisableSafeBrowsingProceedAnyway',
  'chrome.users.PasswordManager',
  'chrome.users.DownloadRestrictions',
  'chrome.users.SiteIsolationBrowser',
  'chrome.users.SecondaryGoogleAccountSignin',
];

type Resolved = Record<string, Record<string, unknown>>;

function fakeClient(schemas: string[], resolved: Resolved = {}) {
  const list = jest.fn(async () => ({
    data: { policySchemas: schemas.map((s) => ({ name: `customers/C0/policySchemas/${s}`, schemaName: s })) },
  }));
  const resolve = jest.fn(async ({ requestBody }: any) => {
    const schema: string = requestBody.policySchemaFilter;
    const value = resolved[schema];
    return {
      data: { resolvedPolicies: value ? [{ value: { policySchema: schema, value } }] : [] },
    };
  });
  return { customers: { policySchemas: { list }, policies: { resolve } } };
}

function serviceWith(client: unknown) {
  const service = new ChromePolicyService();
  jest.spyOn(service as any, 'chromePolicyFor').mockResolvedValue(client);
  return service;
}

const byId = (checks: Array<{ id: string }>, id: string) => checks.find((c) => c.id === id) as any;

describe('Chrome policy checks', () => {
  test('returns the seven checklist checks in the Chrome Browser category', async () => {
    const checks = await serviceWith(fakeClient(ALL_SCHEMAS)).getAllPolicyChecks('admin@example.com', 'abc123');
    expect(checks.map((c) => c.id)).toEqual([
      'chrome-relaunch-notification',
      'chrome-safe-browsing',
      'chrome-safe-browsing-bypass',
      'chrome-password-manager',
      'chrome-download-restrictions',
      'chrome-site-isolation',
      'chrome-allowed-domains',
    ]);
    expect(new Set(checks.map((c) => c.category))).toEqual(new Set(['Chrome Browser']));
    expect(checks.map((c) => c.severity)).toEqual(['medium', 'high', 'high', 'low', 'high', 'medium', 'medium']);
    for (const c of checks) {
      expect(c.recommendedValue).toBeTruthy();
      expect(c.rationale).toBeTruthy();
      expect(c.recommendation).toBeTruthy();
      expect(c.adminConsoleUrl).toMatch(/^https:\/\/admin\.google\.com\//);
      expect(JSON.stringify(c)).not.toMatch(/\u2014/);
    }
  });

  test('targets the root org unit and resolves one exact schema name per check', async () => {
    const client = fakeClient(ALL_SCHEMAS);
    await serviceWith(client).getAllPolicyChecks('admin@example.com', 'abc123');
    const calls = client.customers.policies.resolve.mock.calls.map(([arg]: any) => arg);
    expect(calls).toHaveLength(7);
    for (const arg of calls) {
      expect(arg.customer).toBe('customers/my_customer');
      expect(arg.requestBody.policyTargetKey).toEqual({ targetResource: 'orgunits/abc123' });
    }
    expect(calls.map((c: any) => c.requestBody.policySchemaFilter).sort()).toEqual([...ALL_SCHEMAS].sort());
  });

  test('schema discovery picks the candidate that exists', async () => {
    const legacy = ALL_SCHEMAS.map((s) =>
      s === 'chrome.users.RelaunchNotificationWithDurationV2' ? 'chrome.users.RelaunchNotificationWithDuration' : s
    );
    const client = fakeClient(legacy, {
      'chrome.users.RelaunchNotificationWithDuration': { relaunchNotificationEnum: 'REQUIRED' },
    });
    const checks = await serviceWith(client).getAllPolicyChecks('admin@example.com', 'abc123');
    const filters = client.customers.policies.resolve.mock.calls.map(([a]: any) => a.requestBody.policySchemaFilter);
    expect(filters).toContain('chrome.users.RelaunchNotificationWithDuration');
    expect(filters).not.toContain('chrome.users.RelaunchNotificationWithDurationV2');
    expect(byId(checks, 'chrome-relaunch-notification').status).toBe('pass');
  });

  test('prefers the first candidate when both exist and both resolve', async () => {
    const client = fakeClient(
      [...ALL_SCHEMAS, 'chrome.users.RelaunchNotificationWithDuration'],
      {
        'chrome.users.RelaunchNotificationWithDurationV2': { relaunchNotificationEnum: 'REQUIRED' },
        'chrome.users.RelaunchNotificationWithDuration': { relaunchNotificationEnum: 'NO_NOTIFICATION' },
      }
    );
    const checks = await serviceWith(client).getAllPolicyChecks('admin@example.com', 'abc123');
    expect(byId(checks, 'chrome-relaunch-notification').status).toBe('pass');
  });

  test('marks a check manual and names the schemas tried when none exist', async () => {
    const missing = ALL_SCHEMAS.filter((s) => !s.endsWith('SiteIsolationBrowser'));
    const checks = await serviceWith(fakeClient(missing)).getAllPolicyChecks('admin@example.com', 'abc123');
    const site = byId(checks, 'chrome-site-isolation');
    expect(site.status).toBe('manual');
    expect(site.currentValue).toBe('Not verified');
    expect(site.issues[0]).toContain('chrome.users.SiteIsolationBrowser');
  });

  test('an empty resolve scores Chrome defaults and says so', async () => {
    const checks = await serviceWith(fakeClient(ALL_SCHEMAS)).getAllPolicyChecks('admin@example.com', 'abc123');

    const password = byId(checks, 'chrome-password-manager');
    expect(password.status).toBe('pass');
    expect(password.currentValue).toMatch(/Chrome default/);

    expect(byId(checks, 'chrome-site-isolation')).toMatchObject({ status: 'pass' });
    expect(byId(checks, 'chrome-site-isolation').currentValue).toMatch(/Chrome default/);

    const safeBrowsing = byId(checks, 'chrome-safe-browsing');
    expect(safeBrowsing.status).toBe('warning');
    expect(safeBrowsing.currentValue).toMatch(/Chrome default/);

    for (const id of [
      'chrome-relaunch-notification',
      'chrome-safe-browsing-bypass',
      'chrome-download-restrictions',
    ]) {
      expect(byId(checks, id).status).toBe('fail');
      expect(byId(checks, id).currentValue).toMatch(/Not set/);
    }
    expect(byId(checks, 'chrome-allowed-domains').status).toBe('warning');
  });

  test('scores explicit values', async () => {
    const checks = await serviceWith(
      fakeClient(ALL_SCHEMAS, {
        'chrome.users.RelaunchNotificationWithDurationV2': { relaunchNotificationEnum: 'RECOMMENDED' },
        'chrome.users.SafeBrowsingProtectionLevel': {
          safeBrowsingProtectionLevel: 'ENHANCED_PROTECTION',
          safeBrowsingProtectionLevelCategoryItemPolicyMode: 'MANDATORY',
        },
        'chrome.users.DisableSafeBrowsingProceedAnyway': { disableSafeBrowsingProceedAnyway: true },
        'chrome.users.PasswordManager': { passwordManagerEnabled: 'FALSE' },
        'chrome.users.DownloadRestrictions': {
          safeBrowsingDownloadRestrictions: 'BLOCK_ALL_MALICIOUS_DOWNLOAD',
          downloadRestrictionsPolicyMode: 'RECOMMENDED',
        },
        'chrome.users.SiteIsolationBrowser': { sitePerProcess: true },
        'chrome.users.SecondaryGoogleAccountSignin': {
          secondaryGoogleAccountSigninAllowed: 'TRUE',
          allowedDomainsForApps: ['example.com'],
        },
      })
    ).getAllPolicyChecks('admin@example.com', 'abc123');

    expect(byId(checks, 'chrome-relaunch-notification').status).toBe('warning');
    expect(byId(checks, 'chrome-safe-browsing')).toMatchObject({ status: 'pass', currentValue: 'Enhanced protection, enforced' });
    expect(byId(checks, 'chrome-safe-browsing-bypass').status).toBe('pass');
    expect(byId(checks, 'chrome-password-manager').status).toBe('fail');
    expect(byId(checks, 'chrome-download-restrictions').status).toBe('warning');
    expect(byId(checks, 'chrome-site-isolation').status).toBe('pass');
    expect(byId(checks, 'chrome-allowed-domains')).toMatchObject({ status: 'pass', currentValue: 'Limited to example.com' });
  });

  test('reads the full enum names the API returns', async () => {
    const checks = await serviceWith(
      fakeClient(ALL_SCHEMAS, {
        'chrome.users.RelaunchNotificationWithDurationV2': {
          relaunchNotificationEnum: 'RELAUNCH_NOTIFICATION_ENUM_REQUIRED',
        },
        'chrome.users.SafeBrowsingProtectionLevel': {
          safeBrowsingProtectionLevel: 'SAFE_BROWSING_PROTECTION_LEVEL_ENUM_STANDARD_PROTECTION',
          safeBrowsingProtectionLevelCategoryItemPolicyMode: 'POLICY_MODE_ENUM_RECOMMENDED',
        },
        'chrome.users.PasswordManager': { passwordManagerEnabled: 'PASSWORD_MANAGER_ENABLED_ENUM_FALSE' },
        'chrome.users.DownloadRestrictions': {
          safeBrowsingDownloadRestrictions: 'SAFE_BROWSING_DOWNLOAD_RESTRICTIONS_ENUM_BLOCK_DANGEROUS_DOWNLOAD',
        },
        'chrome.users.SecondaryGoogleAccountSignin': {
          secondaryGoogleAccountSigninAllowed: 'SECONDARY_GOOGLE_ACCOUNT_SIGNIN_ALLOWED_ENUM_TRUE',
          allowedDomainsForApps: ['example.com'],
        },
      })
    ).getAllPolicyChecks('admin@example.com', 'abc123');

    expect(byId(checks, 'chrome-relaunch-notification').status).toBe('pass');
    expect(byId(checks, 'chrome-safe-browsing')).toMatchObject({
      status: 'warning',
      currentValue: 'Standard protection, users can override',
    });
    expect(byId(checks, 'chrome-password-manager').status).toBe('fail');
    expect(byId(checks, 'chrome-download-restrictions')).toMatchObject({
      status: 'pass',
      currentValue: 'Block malicious downloads and dangerous file types',
    });
    expect(byId(checks, 'chrome-allowed-domains').status).toBe('pass');
  });

  test('a domain list passes only when sign-in is limited to those domains', async () => {
    const run = async (value: Record<string, unknown>) =>
      byId(
        await serviceWith(
          fakeClient(ALL_SCHEMAS, { 'chrome.users.SecondaryGoogleAccountSignin': value })
        ).getAllPolicyChecks('admin@example.com', 'abc123'),
        'chrome-allowed-domains'
      );

    const anyAccount = await run({ secondaryGoogleAccountSigninAllowed: 'UNSET', allowedDomainsForApps: ['example.com'] });
    expect(anyAccount.status).toBe('warning');
    const blocked = await run({ secondaryGoogleAccountSigninAllowed: 'FALSE' });
    expect(blocked.status).toBe('warning');
    expect(blocked.issues[0]).toMatch(/ChromeOS/);
  });

  test('Safe Browsing off or overridable never passes', async () => {
    const run = async (value: Record<string, unknown>) =>
      byId(
        await serviceWith(fakeClient(ALL_SCHEMAS, { 'chrome.users.SafeBrowsingProtectionLevel': value })).getAllPolicyChecks(
          'admin@example.com',
          'abc123'
        ),
        'chrome-safe-browsing'
      ).status;

    expect(await run({ safeBrowsingProtectionLevel: 'NO_PROTECTION' })).toBe('fail');
    expect(await run({ safeBrowsingProtectionLevel: 'USER_CHOICE' })).toBe('warning');
    expect(
      await run({
        safeBrowsingProtectionLevel: 'STANDARD_PROTECTION',
        safeBrowsingProtectionLevelCategoryItemPolicyMode: 'RECOMMENDED',
      })
    ).toBe('warning');
  });

  test('an unrecognized value is a warning, not a pass', async () => {
    const checks = await serviceWith(
      fakeClient(ALL_SCHEMAS, { 'chrome.users.DownloadRestrictions': { safeBrowsingDownloadRestrictions: 'SOMETHING_NEW' } })
    ).getAllPolicyChecks('admin@example.com', 'abc123');
    expect(byId(checks, 'chrome-download-restrictions').status).toBe('warning');
  });

  test('an API error throws one error that names the likely cause', async () => {
    const client = fakeClient(ALL_SCHEMAS);
    client.customers.policies.resolve.mockRejectedValue(
      Object.assign(new Error('The caller does not have permission'), { code: 403 })
    );
    const failure = serviceWith(client).getAllPolicyChecks('admin@example.com', 'abc123');
    await expect(failure).rejects.toBeInstanceOf(ChromePolicyApiError);
    await expect(failure).rejects.toThrow(/scope is not granted/);
    await expect(failure).rejects.not.toThrow(/no managed browsers/i);
  });

  test('a disabled API is called out as not enabled', async () => {
    const client = fakeClient(ALL_SCHEMAS);
    client.customers.policySchemas.list.mockRejectedValue(
      Object.assign(new Error('Chrome Policy API has not been used in project 123 before or it is disabled.'), {
        code: 403,
        response: { status: 403, data: { error: { status: 'PERMISSION_DENIED', details: [{ reason: 'SERVICE_DISABLED' }] } } },
      })
    );
    await expect(serviceWith(client).getAllPolicyChecks('admin@example.com', 'abc123')).rejects.toThrow(
      /not enabled/
    );
  });

  test('a null root org unit returns Not verified without calling the API', async () => {
    const client = fakeClient(ALL_SCHEMAS);
    const checks = await serviceWith(client).getAllPolicyChecks('admin@example.com', null);
    expect(checks).toHaveLength(7);
    for (const c of checks) {
      expect(c.status).toBe('manual');
      expect(c.currentValue).toBe('Not verified');
      expect(c.issues?.[0]).toMatch(/root org unit/);
    }
    expect(client.customers.policySchemas.list).not.toHaveBeenCalled();
    expect(client.customers.policies.resolve).not.toHaveBeenCalled();
  });

  test('pages through the schema list', async () => {
    const client = fakeClient([]);
    client.customers.policySchemas.list
      .mockResolvedValueOnce({
        data: {
          policySchemas: [{ schemaName: 'chrome.users.PasswordManager' }],
          nextPageToken: 'next',
        },
      } as any)
      .mockResolvedValueOnce({
        data: { policySchemas: [{ schemaName: 'chrome.users.SiteIsolationBrowser' }] },
      } as any);
    const checks = await serviceWith(client).getAllPolicyChecks('admin@example.com', 'abc123');
    expect(client.customers.policySchemas.list).toHaveBeenCalledTimes(2);
    expect(byId(checks, 'chrome-password-manager').status).toBe('pass');
    expect(byId(checks, 'chrome-site-isolation').status).toBe('pass');
    expect(byId(checks, 'chrome-safe-browsing').status).toBe('manual');
  });
});
