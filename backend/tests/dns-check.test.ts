import * as dns from 'dns';
import {
  dnsCheckService,
  domainsToCheck,
  evaluateDkim,
  evaluateDmarc,
  evaluateMx,
  evaluateSpf,
  type TxtLookup,
} from '../src/services/dns-check.service';

const txt = (...records: string[][]): TxtLookup => ({ records });

const KEY_2048 = 'A'.repeat(392);
const KEY_1024 = 'A'.repeat(216);

function mockDns(opts: {
  txt?: Record<string, string[][]>;
  mx?: Record<string, Array<{ exchange: string; priority: number }>>;
  txtError?: Record<string, string>;
}) {
  jest.spyOn(dns.promises, 'resolveTxt').mockImplementation(async (name: string) => {
    if (opts.txtError?.[name]) throw Object.assign(new Error('timeout'), { code: opts.txtError[name] });
    const found = opts.txt?.[name];
    if (!found) throw Object.assign(new Error('queryTxt ENODATA'), { code: 'ENODATA' });
    return found;
  });
  jest.spyOn(dns.promises, 'resolveMx').mockImplementation(async (name: string) => {
    const found = opts.mx?.[name];
    if (!found) throw Object.assign(new Error('queryMx ENODATA'), { code: 'ENODATA' });
    return found;
  });
}

afterEach(() => {
  jest.restoreAllMocks();
  delete process.env.DKIM_SELECTORS;
});

describe('SPF', () => {
  test('reads -all from the second string of a split record', () => {
    const result = evaluateSpf('example.com', txt(['v=spf1 include:_spf.google.com ', '-all']), false);
    expect(result.status).toBe('pass');
    expect(result.currentValue).toMatch(/-all/);
  });

  test('matches v=spf1 case-insensitively', () => {
    expect(evaluateSpf('example.com', txt(['V=SPF1 -all']), false).status).toBe('pass');
  });

  test('fails when the domain has no SPF record', () => {
    const result = evaluateSpf('example.com', txt(['google-site-verification=abc']), false);
    expect(result.status).toBe('fail');
    expect(result.currentValue).toBe('Not found');
  });

  test('fails on two SPF records', () => {
    const result = evaluateSpf('example.com', txt(['v=spf1 -all'], ['v=spf1 include:x.com -all']), false);
    expect(result.status).toBe('fail');
    expect(result.currentValue).toMatch(/2 SPF records/);
  });

  test('fails on +all and on a bare all', () => {
    expect(evaluateSpf('example.com', txt(['v=spf1 +all']), true).status).toBe('fail');
    expect(evaluateSpf('example.com', txt(['v=spf1 all']), true).status).toBe('fail');
  });

  test('warns on ?all', () => {
    expect(evaluateSpf('example.com', txt(['v=spf1 ?all']), true).status).toBe('warning');
  });

  test('passes ~all only when DMARC enforces', () => {
    const record = txt(['v=spf1 include:_spf.google.com ~all']);
    expect(evaluateSpf('example.com', record, true).status).toBe('pass');
    expect(evaluateSpf('example.com', record, false).status).toBe('warning');
  });

  test('a record with no all mechanism warns, and a redirect passes with a note', () => {
    expect(evaluateSpf('example.com', txt(['v=spf1 include:_spf.google.com']), false).status).toBe('warning');
    const redirect = evaluateSpf('example.com', txt(['v=spf1 redirect=_spf.example.net']), false);
    expect(redirect.status).toBe('pass');
    expect(redirect.issues?.[0]).toMatch(/redirect/);
  });

  test('checkSPF scores ~all from the same domain DMARC policy', async () => {
    mockDns({
      txt: {
        'example.com': [['v=spf1 include:_spf.google.com ~all']],
        '_dmarc.example.com': [['v=DMARC1; p=quarantine']],
      },
    });
    expect((await dnsCheckService.checkSPF('example.com')).status).toBe('pass');

    mockDns({
      txt: {
        'example.com': [['v=spf1 include:_spf.google.com ~all']],
        '_dmarc.example.com': [['v=DMARC1; p=none']],
      },
    });
    expect((await dnsCheckService.checkSPF('example.com')).status).toBe('warning');
  });
});

describe('DMARC', () => {
  test('p=reject passes', () => {
    expect(evaluateDmarc('example.com', txt(['v=DMARC1; p=reject; rua=mailto:d@example.com'])).status).toBe('pass');
  });

  test('sp= never satisfies p=', () => {
    const result = evaluateDmarc('example.com', txt(['v=DMARC1; sp=reject']));
    expect(result.status).toBe('fail');
    expect(result.currentValue).toMatch(/No policy/);
  });

  test('sp=none does not weaken p=reject', () => {
    expect(evaluateDmarc('example.com', txt(['v=DMARC1; sp=none; p=reject'])).status).toBe('pass');
  });

  test('tolerates spaces around =', () => {
    const result = evaluateDmarc('example.com', txt(['v=DMARC1; p = reject ; pct = 100']));
    expect(result.status).toBe('pass');
    expect(result.issues).toBeUndefined();
  });

  test('p=quarantine passes and notes a pct below 100', () => {
    const result = evaluateDmarc('example.com', txt(['v=DMARC1; p=quarantine; pct=25']));
    expect(result.status).toBe('pass');
    expect(result.issues?.[0]).toMatch(/pct=25/);
  });

  test('p=none warns', () => {
    expect(evaluateDmarc('example.com', txt(['v=DMARC1; p=none'])).status).toBe('warning');
  });

  test('an invalid p fails', () => {
    expect(evaluateDmarc('example.com', txt(['v=DMARC1; p=allow'])).status).toBe('fail');
  });

  test('two DMARC records fail', () => {
    expect(evaluateDmarc('example.com', txt(['v=DMARC1; p=reject'], ['v=DMARC1; p=none'])).status).toBe('fail');
  });

  test('joins a record published as several strings', () => {
    expect(evaluateDmarc('example.com', txt(['v=DMARC1; p=', 'reject'])).status).toBe('pass');
  });

  test('a DNS failure is a warning, not a pass', () => {
    const result = evaluateDmarc('example.com', { records: [], error: 'timeout' });
    expect(result.status).toBe('warning');
    expect(result.currentValue).toBe('Unable to check');
  });
});

describe('DKIM', () => {
  const lookups = (entries: Record<string, TxtLookup>) => new Map(Object.entries(entries));

  test('a 2048-bit key passes', () => {
    const result = evaluateDkim('example.com', ['google'], lookups({ google: txt([`v=DKIM1; k=rsa; p=${KEY_2048}`]) }));
    expect(result.status).toBe('pass');
  });

  test('strips whitespace and split strings inside the key before measuring', () => {
    const spaced = KEY_2048.replace(/(.{64})/g, '$1 ');
    const result = evaluateDkim('example.com', ['google'], lookups({ google: txt(['v=DKIM1; k=rsa; p=' + spaced.slice(0, 200), spaced.slice(200)]) }));
    expect(result.status).toBe('pass');
  });

  test('a 1024-bit key warns', () => {
    const result = evaluateDkim('example.com', ['google'], lookups({ google: txt([`v=DKIM1; k=rsa; p=${KEY_1024}`]) }));
    expect(result.status).toBe('warning');
  });

  test('an empty p= is a revoked key and fails', () => {
    const result = evaluateDkim('example.com', ['google'], lookups({ google: txt(['v=DKIM1; k=rsa; p=']) }));
    expect(result.status).toBe('fail');
    expect(result.currentValue).toMatch(/revoked/i);
  });

  test('passes when any selector has a valid key', () => {
    const result = evaluateDkim(
      'example.com',
      ['google', 'selector1'],
      lookups({ google: txt(['v=DKIM1; p=']), selector1: txt([`v=DKIM1; k=rsa; p=${KEY_2048}`]) })
    );
    expect(result.status).toBe('pass');
    expect(result.currentValue).toMatch(/selector1/);
  });

  test('fails with the selectors it tried when none exist', () => {
    const result = evaluateDkim('example.com', ['google', 's2'], lookups({ google: txt(), s2: txt() }));
    expect(result.status).toBe('fail');
    expect(result.issues?.[0]).toMatch(/google, s2/);
  });

  test('reads selectors from DKIM_SELECTORS', async () => {
    process.env.DKIM_SELECTORS = 'k1, K2';
    mockDns({ txt: { 'k2._domainkey.example.com': [[`v=DKIM1; k=rsa; p=${KEY_2048}`]] } });
    const result = await dnsCheckService.checkDKIM('example.com');
    expect(result.status).toBe('pass');
    expect(dns.promises.resolveTxt).toHaveBeenCalledWith('k1._domainkey.example.com');
    expect(dns.promises.resolveTxt).toHaveBeenCalledWith('k2._domainkey.example.com');
  });

  test('defaults to the google selector', async () => {
    mockDns({ txt: { 'google._domainkey.example.com': [[`v=DKIM1; k=rsa; p=${KEY_2048}`]] } });
    expect((await dnsCheckService.checkDKIM('example.com')).status).toBe('pass');
  });
});

describe('MX', () => {
  const mx = (...records: Array<[number, string]>) => ({
    records: records.map(([priority, exchange]) => ({ priority, exchange })),
  });

  test('smtp.google.com at the top priority passes', () => {
    expect(evaluateMx('example.com', mx([1, 'smtp.google.com'])).status).toBe('pass');
  });

  test('the legacy aspmx family passes', () => {
    const result = evaluateMx(
      'example.com',
      mx([1, 'ASPMX.L.GOOGLE.COM.'], [5, 'alt1.aspmx.l.google.com'], [5, 'alt2.aspmx.l.google.com'], [10, 'alt3.aspmx.l.google.com'])
    );
    expect(result.status).toBe('pass');
  });

  test('warns when a non-Google record has the best priority', () => {
    const result = evaluateMx('example.com', mx([5, 'mx.gateway.example.net'], [10, 'smtp.google.com']));
    expect(result.status).toBe('warning');
  });

  test('warns when a non-Google record ties Google for the best priority', () => {
    expect(evaluateMx('example.com', mx([1, 'mx.gateway.example.net'], [1, 'smtp.google.com'])).status).toBe('warning');
  });

  test('passes with a note when only backups are non-Google', () => {
    const result = evaluateMx('example.com', mx([1, 'smtp.google.com'], [20, 'backup.example.net']));
    expect(result.status).toBe('pass');
    expect(result.issues).toHaveLength(1);
  });

  test('fails with no Google MX', () => {
    expect(evaluateMx('example.com', mx([10, 'mail.example.net'])).status).toBe('fail');
  });

  test('fails with no MX records, including an ENODATA lookup', async () => {
    expect(evaluateMx('example.com', mx()).status).toBe('fail');
    mockDns({});
    const result = await dnsCheckService.checkMX('example.com');
    expect(result.status).toBe('fail');
    expect(result.currentValue).toBe('No MX records');
  });

  test('a DNS timeout is a warning, not a pass or fail', async () => {
    jest.spyOn(dns.promises, 'resolveMx').mockRejectedValue(Object.assign(new Error('timed out'), { code: 'ETIMEOUT' }));
    expect((await dnsCheckService.checkMX('example.com')).status).toBe('warning');
  });
});

describe('domains', () => {
  test('puts the primary first and dedupes allowed domains', () => {
    expect(domainsToCheck('Example.com')).toEqual(['example.com', 'subsidiary.com']);
  });

  test('skips values that are not domains', () => {
    expect(domainsToCheck('localhost')).toEqual(['example.com', 'subsidiary.com']);
  });

  test('checkAllDNS returns SPF, DKIM, DMARC, and MX', async () => {
    mockDns({
      txt: {
        'example.com': [['v=spf1 include:_spf.google.com ~all']],
        'google._domainkey.example.com': [[`v=DKIM1; k=rsa; p=${KEY_2048}`]],
        '_dmarc.example.com': [['v=DMARC1; p=reject']],
      },
      mx: { 'example.com': [{ priority: 1, exchange: 'smtp.google.com' }] },
    });
    const records = await dnsCheckService.checkAllDNS('example.com');
    expect(records.map((r) => [r.type, r.status])).toEqual([
      ['SPF', 'pass'],
      ['DKIM', 'pass'],
      ['DMARC', 'pass'],
      ['MX', 'pass'],
    ]);
  });
});
