import * as dns from 'dns';
import { getAllowedDomains } from '../utils/validation';

export type DNSRecordType = 'SPF' | 'DKIM' | 'DMARC' | 'MX';
export type DNSStatus = 'pass' | 'warning' | 'fail';

export interface DNSRecord {
  type: DNSRecordType;
  domain: string;
  status: DNSStatus;
  /** Short value for the "Current" column. */
  currentValue: string;
  record?: string;
  recommendation?: string;
  issues?: string[];
}

/** Lookup result: the TXT strings per record, or why the lookup produced nothing. */
export interface TxtLookup {
  records: string[][];
  /** Set when DNS failed for a reason other than "no such record". */
  error?: string;
}

/** Base64 length of a 2048-bit RSA public key is about 392, a 1024-bit key about 216. */
const DKIM_2048_MIN_LENGTH = 300;
const DEFAULT_DKIM_SELECTORS = ['google'];

const NO_RECORD_CODES = new Set(['ENODATA', 'ENOTFOUND', 'NXDOMAIN']);

async function lookupTxt(name: string): Promise<TxtLookup> {
  try {
    return { records: await dns.promises.resolveTxt(name) };
  } catch (error: any) {
    if (NO_RECORD_CODES.has(error?.code)) return { records: [] };
    return { records: [], error: error?.message || String(error) };
  }
}

function joinStrings(records: string[][]): string[] {
  return records.map((strings) => strings.join(''));
}

function lookupFailure(type: DNSRecordType, domain: string, error: string): DNSRecord {
  return {
    type,
    domain,
    status: 'warning',
    currentValue: 'Unable to check',
    issues: [`DNS lookup failed: ${error}`],
  };
}

/** Split a `tag=value; tag=value` record. Tag names are lowercased; the first occurrence of a tag wins. */
function parseTags(record: string): Map<string, string> {
  const tags = new Map<string, string>();
  for (const part of record.split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf('=');
    if (eq < 0) continue;
    const name = trimmed.slice(0, eq).trim().toLowerCase();
    if (name && !tags.has(name)) tags.set(name, trimmed.slice(eq + 1).trim());
  }
  return tags;
}

function dmarcRecords(lookup: TxtLookup): string[] {
  return joinStrings(lookup.records).filter((r) => /^v\s*=\s*DMARC1\s*(;|$)/i.test(r.trim()));
}

/** The DMARC `p` tag, lowercased. `sp` never stands in for it. */
export function dmarcPolicy(lookup: TxtLookup): string | null {
  const found = dmarcRecords(lookup);
  if (found.length !== 1) return null;
  return parseTags(found[0]).get('p')?.toLowerCase() || null;
}

export function evaluateDmarc(domain: string, lookup: TxtLookup): DNSRecord {
  if (lookup.error) return lookupFailure('DMARC', domain, lookup.error);

  const found = dmarcRecords(lookup);
  if (found.length === 0) {
    return {
      type: 'DMARC',
      domain,
      status: 'fail',
      currentValue: 'Not found',
      recommendation:
        'Publish a DMARC record at _dmarc. Start with p=none and reporting, then move to p=quarantine or p=reject.',
      issues: ['DMARC record not found'],
    };
  }
  if (found.length > 1) {
    return {
      type: 'DMARC',
      domain,
      status: 'fail',
      currentValue: `${found.length} DMARC records`,
      record: found.join(' | '),
      recommendation: 'Publish exactly one DMARC record. Receivers ignore DMARC when more than one exists.',
      issues: [`Found ${found.length} DMARC records. Receivers ignore DMARC when more than one exists.`],
    };
  }

  const record = found[0];
  const tags = parseTags(record);
  const policy = tags.get('p')?.toLowerCase();

  if (policy === 'reject' || policy === 'quarantine') {
    const pct = tags.has('pct') ? parseInt(tags.get('pct') as string, 10) : 100;
    const partial = Number.isFinite(pct) && pct < 100;
    return {
      type: 'DMARC',
      domain,
      status: 'pass',
      currentValue: `p=${policy}`,
      record,
      recommendation: partial
        ? `Raise pct to 100 so p=${policy} applies to all mail that fails DMARC.`
        : 'DMARC is enforcing.',
      issues: partial
        ? [`pct=${pct}: p=${policy} applies to only ${pct}% of failing mail. Raise it to 100 once reports look clean.`]
        : undefined,
    };
  }

  if (policy === 'none') {
    return {
      type: 'DMARC',
      domain,
      status: 'warning',
      currentValue: 'p=none',
      record,
      recommendation:
        'p=none only monitors. Review the DMARC reports, then move to p=quarantine or p=reject.',
      issues: ['DMARC policy is p=none (monitoring only). Spoofed mail is still delivered.'],
    };
  }

  return {
    type: 'DMARC',
    domain,
    status: 'fail',
    currentValue: policy ? `Invalid p=${policy}` : 'No policy (p=)',
    record,
    recommendation: 'Add a valid p= tag (none, quarantine, or reject). The sp= tag does not replace p=.',
    issues: [policy ? `Unknown DMARC policy: ${policy}` : 'DMARC record is missing the p= policy tag'],
  };
}

export function evaluateSpf(domain: string, lookup: TxtLookup, dmarcEnforcing: boolean): DNSRecord {
  if (lookup.error) return lookupFailure('SPF', domain, lookup.error);

  const found = joinStrings(lookup.records)
    .map((r) => r.trim())
    .filter((r) => /^v=spf1(\s|$)/i.test(r));

  if (found.length === 0) {
    return {
      type: 'SPF',
      domain,
      status: 'fail',
      currentValue: 'Not found',
      recommendation: 'Publish one SPF record that lists every legitimate sender and ends in -all.',
      issues: ['SPF record not found'],
    };
  }
  if (found.length > 1) {
    return {
      type: 'SPF',
      domain,
      status: 'fail',
      currentValue: `${found.length} SPF records`,
      record: found.join(' | '),
      recommendation: 'Merge the SPF records into one. Receivers treat more than one as a permanent error.',
      issues: [`Found ${found.length} SPF records. Receivers return permerror and SPF fails for every message.`],
    };
  }

  const record = found[0];
  const terms = record.split(/\s+/).slice(1);
  const all = terms.map((t) => t.match(/^([+\-~?]?)all$/i)).find(Boolean);
  const hasRedirect = terms.some((t) => /^redirect=/i.test(t));

  const base = { type: 'SPF' as const, domain, record };
  if (!all) {
    if (hasRedirect) {
      return {
        ...base,
        status: 'pass',
        currentValue: 'redirect=',
        recommendation: 'SPF policy comes from the redirect target. Confirm that record ends in -all or ~all.',
        issues: ['No all mechanism. The redirect= modifier supplies the policy, so check the target domain.'],
      };
    }
    return {
      ...base,
      status: 'warning',
      currentValue: 'No all mechanism',
      recommendation: 'End the SPF record with -all (or ~all with an enforcing DMARC policy).',
      issues: ['SPF record has no all mechanism, so unlisted senders get a neutral result.'],
    };
  }

  const qualifier = all[1] || '+';
  if (qualifier === '-') {
    return { ...base, status: 'pass', currentValue: '-all (hard fail)', recommendation: 'SPF is configured with hard fail.' };
  }
  if (qualifier === '~') {
    if (dmarcEnforcing) {
      return {
        ...base,
        status: 'pass',
        currentValue: '~all with enforcing DMARC',
        recommendation: 'Soft fail is acceptable because DMARC enforces the policy. Google recommends ~all.',
      };
    }
    return {
      ...base,
      status: 'warning',
      currentValue: '~all (soft fail)',
      recommendation: 'Use -all, or keep ~all and set DMARC to p=quarantine or p=reject.',
      issues: ['SPF uses ~all and DMARC is not enforcing. Receivers may still accept spoofed mail.'],
    };
  }
  if (qualifier === '?') {
    return {
      ...base,
      status: 'warning',
      currentValue: '?all (neutral)',
      recommendation: 'Replace ?all with -all, or ~all with an enforcing DMARC policy.',
      issues: ['SPF ends in ?all, which tells receivers not to judge unlisted senders.'],
    };
  }
  return {
    ...base,
    status: 'fail',
    currentValue: '+all (allows any sender)',
    recommendation: 'Replace +all with -all immediately. +all lets anyone send as this domain.',
    issues: ['SPF ends in +all (or a bare all). Any server on the internet passes SPF for this domain.'],
  };
}

export function evaluateDkim(domain: string, selectors: string[], lookups: Map<string, TxtLookup>): DNSRecord {
  type Outcome = 'strong' | 'weak' | 'revoked' | 'invalid' | 'missing' | 'error';
  const outcomes = selectors.map((selector) => {
    const lookup = lookups.get(selector) as TxtLookup;
    if (lookup.error) return { selector, outcome: 'error' as Outcome, detail: lookup.error };
    const joined = joinStrings(lookup.records)
      .map((r) => r.trim())
      .find((r) => parseTags(r).has('p'));
    if (!joined) return { selector, outcome: 'missing' as Outcome };

    const tags = parseTags(joined);
    const version = tags.get('v');
    if (version && version.toUpperCase() !== 'DKIM1') return { selector, outcome: 'invalid' as Outcome };
    const key = (tags.get('p') ?? '').replace(/\s+/g, '');
    if (!key) return { selector, outcome: 'revoked' as Outcome };
    if (!/^[A-Za-z0-9+/]+=*$/.test(key)) return { selector, outcome: 'invalid' as Outcome };
    return {
      selector,
      outcome: (key.length < DKIM_2048_MIN_LENGTH ? 'weak' : 'strong') as Outcome,
      record: `${joined.replace(/\s+/g, '').slice(0, 100)}...`,
    };
  });

  const tried = selectors.join(', ');
  const strong = outcomes.find((o) => o.outcome === 'strong');
  if (strong) {
    return {
      type: 'DKIM',
      domain,
      status: 'pass',
      currentValue: `Valid 2048-bit key (${strong.selector})`,
      record: strong.record,
      recommendation: 'DKIM is configured.',
    };
  }

  const weak = outcomes.find((o) => o.outcome === 'weak');
  if (weak) {
    return {
      type: 'DKIM',
      domain,
      status: 'warning',
      currentValue: `Key under 2048-bit (${weak.selector})`,
      record: weak.record,
      recommendation: 'Generate a 2048-bit DKIM key in the Admin console and publish the new TXT record.',
      issues: [`Selector ${weak.selector} publishes a key shorter than 2048 bits.`],
    };
  }

  const failed = outcomes.find((o) => o.outcome === 'error');
  if (failed && outcomes.every((o) => o.outcome === 'error' || o.outcome === 'missing')) {
    return lookupFailure('DKIM', domain, failed.detail as string);
  }

  const revoked = outcomes.filter((o) => o.outcome === 'revoked');
  if (revoked.length > 0) {
    return {
      type: 'DKIM',
      domain,
      status: 'fail',
      currentValue: 'Key revoked (empty p=)',
      recommendation:
        'Publish a new DKIM key. An empty p= tag means the key was revoked, so signed mail fails validation.',
      issues: revoked.map((o) => `Selector ${o.selector} has an empty p= tag (revoked key).`),
    };
  }

  return {
    type: 'DKIM',
    domain,
    status: 'fail',
    currentValue: 'Not found',
    recommendation:
      'Turn on DKIM signing in the Admin console and publish the TXT record. If the domain uses a custom selector, set DKIM_SELECTORS.',
    issues: [`No valid DKIM record found for selector(s): ${tried}.`],
  };
}

const GOOGLE_MX = [
  /^smtp\.google\.com$/,
  /^aspmx\.l\.google\.com$/,
  /^alt\d+\.aspmx\.l\.google\.com$/,
  /^aspmx\d+\.googlemail\.com$/,
];

function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.$/, '');
}

function isGoogleMx(host: string): boolean {
  const name = normalizeHost(host);
  return GOOGLE_MX.some((pattern) => pattern.test(name));
}

export function evaluateMx(
  domain: string,
  result: { records: Array<{ exchange: string; priority: number }>; error?: string }
): DNSRecord {
  if (result.error) return lookupFailure('MX', domain, result.error);

  const records = result.records;
  if (records.length === 0) {
    return {
      type: 'MX',
      domain,
      status: 'fail',
      currentValue: 'No MX records',
      recommendation: 'Publish Google MX records (smtp.google.com at priority 1) so Gmail receives mail for this domain.',
      issues: ['No MX records found. Mail for this domain cannot be delivered to Google Workspace.'],
    };
  }

  const summary = [...records]
    .sort((a, b) => a.priority - b.priority)
    .map((r) => `${r.priority} ${normalizeHost(r.exchange)}`)
    .join(', ');
  const google = records.filter((r) => isGoogleMx(r.exchange));
  if (google.length === 0) {
    return {
      type: 'MX',
      domain,
      status: 'fail',
      currentValue: 'No Google MX',
      record: summary,
      recommendation:
        'Point the primary MX record at smtp.google.com. If a mail gateway sits in front of Google on purpose, waive this check with that reason.',
      issues: ['No MX record points to Google. Gmail does not receive mail for this domain directly.'],
    };
  }

  const lowest = Math.min(...records.map((r) => r.priority));
  const googleLowest = Math.min(...google.map((r) => r.priority));
  const others = records.filter((r) => !isGoogleMx(r.exchange));
  if (googleLowest > lowest || others.some((r) => r.priority === googleLowest)) {
    return {
      type: 'MX',
      domain,
      status: 'warning',
      currentValue: 'Google MX is not the top priority',
      record: summary,
      recommendation:
        'Give the Google MX record the lowest priority number. If a gateway handles mail first on purpose, waive this check with that reason.',
      issues: ['A non-Google MX record has the same or a better priority than Google. Mail may bypass Google first.'],
    };
  }

  return {
    type: 'MX',
    domain,
    status: 'pass',
    currentValue: 'Google MX is primary',
    record: summary,
    recommendation: 'MX records point to Google.',
    issues: others.length > 0 ? ['Non-Google MX records exist at a lower priority. Confirm they are intended backups.'] : undefined,
  };
}

function dkimSelectors(): string[] {
  const selectors = (process.env.DKIM_SELECTORS || '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  return selectors.length > 0 ? Array.from(new Set(selectors)) : DEFAULT_DKIM_SELECTORS;
}

/** The primary domain first, then every other allowed sign-in domain, lowercased and deduplicated. */
export function domainsToCheck(primary: string): string[] {
  const seen = new Set<string>();
  for (const domain of [primary, ...getAllowedDomains()]) {
    const clean = (domain || '').trim().toLowerCase();
    if (clean.includes('.')) seen.add(clean);
  }
  return Array.from(seen);
}

export class DNSCheckService {
  async checkSPF(domain: string): Promise<DNSRecord> {
    const [spf, dmarc] = await Promise.all([lookupTxt(domain), lookupTxt(`_dmarc.${domain}`)]);
    return evaluateSpf(domain, spf, ['reject', 'quarantine'].includes(dmarcPolicy(dmarc) ?? ''));
  }

  async checkDKIM(domain: string, selectors: string[] = dkimSelectors()): Promise<DNSRecord> {
    const entries = await Promise.all(
      selectors.map(async (selector) => [selector, await lookupTxt(`${selector}._domainkey.${domain}`)] as const)
    );
    return evaluateDkim(domain, selectors, new Map(entries));
  }

  async checkDMARC(domain: string): Promise<DNSRecord> {
    return evaluateDmarc(domain, await lookupTxt(`_dmarc.${domain}`));
  }

  async checkMX(domain: string): Promise<DNSRecord> {
    try {
      return evaluateMx(domain, { records: await dns.promises.resolveMx(domain) });
    } catch (error: any) {
      if (NO_RECORD_CODES.has(error?.code)) return evaluateMx(domain, { records: [] });
      return evaluateMx(domain, { records: [], error: error?.message || String(error) });
    }
  }

  /** SPF, DKIM, DMARC, and MX for one domain. DMARC is looked up once and shared with the SPF score. */
  async checkAllDNS(domain: string): Promise<DNSRecord[]> {
    const selectors = dkimSelectors();
    const [spfTxt, dmarcTxt, dkim, mx] = await Promise.all([
      lookupTxt(domain),
      lookupTxt(`_dmarc.${domain}`),
      this.checkDKIM(domain, selectors),
      this.checkMX(domain),
    ]);
    const enforcing = ['reject', 'quarantine'].includes(dmarcPolicy(dmarcTxt) ?? '');
    return [evaluateSpf(domain, spfTxt, enforcing), dkim, evaluateDmarc(domain, dmarcTxt), mx];
  }
}

export const dnsCheckService = new DNSCheckService();
