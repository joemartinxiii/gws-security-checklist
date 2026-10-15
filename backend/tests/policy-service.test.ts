import { parseRetryAfterMs } from '../src/utils/retryAfter';

jest.mock('../src/config/google.config', () => ({
  getDelegatedAccessToken: jest.fn(async () => 'token'),
}));

import { policyService } from '../src/services/policy.service';

function jsonResponse(body: unknown, init: { status?: number; headers?: Record<string, string> } = {}) {
  const status = init.status ?? 200;
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (name: string) => init.headers?.[name.toLowerCase()] ?? null },
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}

describe('parseRetryAfterMs', () => {
  test('reads seconds and HTTP-dates', () => {
    expect(parseRetryAfterMs('3')).toBe(3000);
    expect(parseRetryAfterMs(120)).toBe(120_000);
    const now = Date.parse('2026-10-15T12:00:00Z');
    expect(parseRetryAfterMs('Thu, 15 Oct 2026 12:00:07 GMT', now)).toBe(7000);
    expect(parseRetryAfterMs('Thu, 15 Oct 2026 11:59:00 GMT', now)).toBe(0);
  });

  test('returns null for missing or unreadable values', () => {
    expect(parseRetryAfterMs(undefined)).toBeNull();
    expect(parseRetryAfterMs('')).toBeNull();
    expect(parseRetryAfterMs('soon')).toBeNull();
  });
});

describe('policyService.loadOrgPolicies', () => {
  let delays: number[];

  beforeEach(() => {
    delays = [];
    jest.spyOn(global, 'setTimeout').mockImplementation(((fn: () => void, ms?: number) => {
      delays.push(ms ?? 0);
      fn();
      return 0 as unknown as NodeJS.Timeout;
    }) as typeof setTimeout);
    jest.spyOn(console, 'warn').mockImplementation(() => undefined);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  const onePolicy = [{ setting: { type: 'settings/a.b', value: {} }, type: 'ADMIN' }];

  test('caps paging at 200 pages and marks the snapshot partial', async () => {
    const fetchMock = jest.fn(async () => jsonResponse({ policies: onePolicy, nextPageToken: 'more' }));
    global.fetch = fetchMock as unknown as typeof fetch;

    const snapshot = await policyService.loadOrgPolicies('admin@example.com');

    expect(fetchMock).toHaveBeenCalledTimes(200);
    expect(snapshot.available).toBe(true);
    expect(snapshot.partial).toBe(true);
    expect(snapshot.warnings).toContain('The policy list was cut off after 200 pages. Results may be incomplete.');
  });

  test('stops when an empty page still returns a token', async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValueOnce(jsonResponse({ policies: onePolicy, nextPageToken: 'p2' }))
      .mockResolvedValueOnce(jsonResponse({ policies: [], nextPageToken: 'p3' }));
    global.fetch = fetchMock as unknown as typeof fetch;

    const snapshot = await policyService.loadOrgPolicies('admin@example.com');

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(snapshot.partial).toBe(true);
    expect(snapshot.warnings.join(' ')).toMatch(/cut off after 2 pages/);
    expect(snapshot.all('a.b')).toHaveLength(1);
  });

  test('a complete list is not partial', async () => {
    global.fetch = jest.fn(async () => jsonResponse({ policies: onePolicy })) as unknown as typeof fetch;
    const snapshot = await policyService.loadOrgPolicies('admin@example.com');
    expect(snapshot.partial).toBe(false);
    expect(snapshot.warnings.filter((w) => /cut off/.test(w))).toEqual([]);
  });

  test('honors an HTTP-date Retry-After', async () => {
    const retryAt = new Date(Date.now() + 6000).toUTCString();
    global.fetch = jest
      .fn()
      .mockResolvedValueOnce(jsonResponse({}, { status: 429, headers: { 'retry-after': retryAt } }))
      .mockResolvedValueOnce(jsonResponse({ policies: onePolicy })) as unknown as typeof fetch;

    const snapshot = await policyService.loadOrgPolicies('admin@example.com');

    expect(snapshot.available).toBe(true);
    const wait = delays.find((ms) => ms >= 4000);
    expect(wait).toBeDefined();
    expect(wait).toBeLessThanOrEqual(6000);
  });
});
