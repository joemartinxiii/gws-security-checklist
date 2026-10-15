import { isDeepStrictEqual } from 'util';
import { getDelegatedAccessToken } from '../config/google.config';
import { parseRetryAfterMs } from '../utils/retryAfter';

/**
 * Thin wrapper around the Cloud Identity Policy API (`policies.list`).
 *
 * We call the REST endpoint directly with a delegated bearer token instead of
 * going through the googleapis client: the pinned googleapis release predates
 * the `cloudidentity.policies` resource, and a raw fetch keeps us independent
 * of client-library churn while giving us the untyped setting `value` object
 * as-is.
 *
 * The Policy API requires a **super administrator** subject and the
 * `cloud-identity.policies.readonly` scope, with `cloudidentity.googleapis.com`
 * enabled. When any of those are missing the load fails and callers fall back
 * to treating the affected checks as "manual".
 */

const POLICIES_ENDPOINT = 'https://cloudidentity.googleapis.com/v1/policies';

/** Prefer fewer pages — Cloud Identity accepts up to this many per list call. */
const PAGE_SIZE = 1000;
/** Brief pause between pages to avoid burst rate limits on large tenants. */
const INTER_PAGE_DELAY_MS = 150;
/** Retries for transient 429 / 5xx (exponential backoff + Retry-After). */
const MAX_FETCH_ATTEMPTS = 5;
const BASE_BACKOFF_MS = 800;
/** Stop paging a policy list that never ends. */
const MAX_POLICY_PAGES = 200;

/**
 * Settings whose fields are reduced one by one: each field comes from the
 * greatest-sortOrder policy that has it. Every other setting takes all of its
 * fields from the greatest-sortOrder policy. Source: Policy API concepts,
 * "Reducers for settings".
 */
const MERGE_REDUCER_SETTINGS = new Set([
  'api_controls.unconfigured_third_party_apps',
  'calendar.interoperability',
  'calendar.primary_calendar_max_allowed_external_sharing',
  'calendar.secondary_calendar_max_allowed_external_sharing',
  'chat.chat_history',
  'chat.external_chat_restriction',
  'drive_and_docs.drive_sdk',
  'gmail.email_image_proxy_bypass',
  'gmail.imap_access',
  'gmail.mail_delegation',
  'gmail.name_format',
  'groups_for_business.groups_sharing',
  'security.less_secure_apps',
  'security.super_admin_account_recovery',
  'security.user_account_recovery',
  'workspace_marketplace.apps_access_options',
]);

interface RawPolicyQuery {
  query?: string;
  orgUnit?: string;
  group?: string;
  sortOrder?: number | string;
}

interface RawPolicy {
  name?: string;
  policyQuery?: RawPolicyQuery;
  setting?: { type?: string; value?: Record<string, unknown> };
  type?: string; // 'ADMIN' | 'SYSTEM'
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Fetch one policies.list page with retries on 429 / 5xx.
 * WorkspaceService.withRetry covers googleapis clients; this path uses raw fetch.
 */
async function fetchPoliciesPage(
  url: string,
  token: string
): Promise<{ policies: RawPolicy[]; nextPageToken?: string }> {
  let lastError: Error | null = null;

  for (let attempt = 0; attempt < MAX_FETCH_ATTEMPTS; attempt++) {
    try {
      const resp = await fetch(url, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (resp.ok) {
        const data = (await resp.json()) as {
          policies?: RawPolicy[];
          nextPageToken?: string;
        };
        return {
          policies: Array.isArray(data.policies) ? data.policies : [],
          nextPageToken: data.nextPageToken,
        };
      }

      const body = await resp.text().catch(() => '');
      const retryable = resp.status === 429 || resp.status >= 500;

      if (retryable && attempt < MAX_FETCH_ATTEMPTS - 1) {
        const headerWait = parseRetryAfterMs(resp.headers.get('retry-after'));
        // Cap single wait so Cloud Run request doesn't hang forever.
        const waitMs = Math.min(headerWait ?? BASE_BACKOFF_MS * Math.pow(2, attempt), 15_000);
        console.warn(
          `Cloud Identity Policy API HTTP ${resp.status} (attempt ${attempt + 1}/${MAX_FETCH_ATTEMPTS}); retrying in ${waitMs}ms`
        );
        await sleep(waitMs);
        continue;
      }

      console.error(
        `Cloud Identity Policy API HTTP ${resp.status}:`,
        body.slice(0, 500)
      );
      throw new Error(`Policy API HTTP ${resp.status}`);
    } catch (error) {
      if (error instanceof Error && error.message.startsWith('Policy API HTTP')) {
        throw error;
      }
      // Network blip — retry
      lastError = error instanceof Error ? error : new Error(String(error));
      if (attempt < MAX_FETCH_ATTEMPTS - 1) {
        const waitMs = Math.min(BASE_BACKOFF_MS * Math.pow(2, attempt), 15_000);
        console.warn(
          `Cloud Identity Policy API network error (attempt ${attempt + 1}/${MAX_FETCH_ATTEMPTS}): ${lastError.message}; retrying in ${waitMs}ms`
        );
        await sleep(waitMs);
        continue;
      }
      throw lastError;
    }
  }

  throw lastError || new Error('Policy API request failed after retries');
}

export interface PolicyLookup {
  /** True when a policy for the requested setting type was returned. */
  found: boolean;
  /** The setting value object (camelCase fields), or null when not found. */
  value: Record<string, unknown> | null;
  /**
   * Number of other org units or groups whose admin policy differs from
   * `value`. Zero when every other scope matches the root or has no policy.
   */
  overrideCount: number;
  /** True when `value` comes only from policies limited to certain licenses. */
  licenseConditional: boolean;
}

/** An org unit or group that sets its own value for a setting. */
export interface PolicyScope {
  kind: 'orgUnit' | 'group';
  id: string;
  value: Record<string, unknown>;
}

interface SnapshotMeta {
  /** True when the policy list was cut off before the last page. */
  partial?: boolean;
  warnings?: string[];
}

const ROOT_UNKNOWN_WARNING =
  'The top-level org unit could not be identified from the policy list, so org-wide values may reflect an override on a child org unit.';

/** Strip the leading `settings/` from a setting type identifier. */
function normalizeType(type?: string): string {
  if (!type) return '';
  return type.startsWith('settings/') ? type.slice('settings/'.length) : type;
}

function sortOrderOf(policy: RawPolicy): number {
  const n = Number(policy.policyQuery?.sortOrder ?? 0);
  return Number.isFinite(n) ? n : 0;
}

/** Org unit ID without the `orgUnits/` prefix, or null for a customer-wide policy. */
function bareOrgUnit(policy: RawPolicy): string | null {
  const orgUnit = policy.policyQuery?.orgUnit;
  return orgUnit ? orgUnit.replace(/^orgUnits\//, '') : null;
}

function isLicenseScoped(policy: RawPolicy): boolean {
  return /entity\.licenses/.test(policy.policyQuery?.query ?? '');
}

/** Ascending precedence: a greater sortOrder wins, and ADMIN wins a tie. */
function byPrecedence(a: RawPolicy, b: RawPolicy): number {
  const diff = sortOrderOf(a) - sortOrderOf(b);
  if (diff !== 0) return diff;
  return Number(a.type === 'ADMIN') - Number(b.type === 'ADMIN');
}

function reduceValues(settingType: string, ascending: RawPolicy[]): Record<string, unknown> {
  if (!MERGE_REDUCER_SETTINGS.has(settingType)) {
    return ascending[ascending.length - 1].setting?.value ?? {};
  }
  const merged: Record<string, unknown> = {};
  for (const policy of ascending) {
    for (const [field, next] of Object.entries(policy.setting?.value ?? {})) {
      const previous = merged[field];
      merged[field] = Array.isArray(previous) && Array.isArray(next) ? [...previous, ...next] : next;
    }
  }
  return merged;
}

/** The root OU is the one Google attaches its SYSTEM defaults to. */
function deriveRootOrgUnit(policies: RawPolicy[]): string | null {
  const counts = new Map<string, number>();
  for (const policy of policies) {
    if (policy.type !== 'SYSTEM' || policy.policyQuery?.group) continue;
    const orgUnit = bareOrgUnit(policy);
    if (orgUnit) counts.set(orgUnit, (counts.get(orgUnit) ?? 0) + 1);
  }
  const ranked = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  if (ranked.length === 0) return null;
  if (ranked.length > 1 && ranked[0][1] === ranked[1][1]) return null;
  return ranked[0][0];
}

/**
 * An immutable, in-memory view of a customer's admin policies indexed by
 * setting type. Built once per audit run.
 */
export class PolicySnapshot {
  readonly available: boolean;
  readonly error?: string;
  /** Bare ID of the root org unit, or null when it cannot be identified. */
  readonly rootOrgUnitId: string | null;
  /** True when the policy list was cut off, so some policies may be missing. */
  readonly partial: boolean;
  /** Plain-language notes about how complete or reliable the snapshot is. */
  readonly warnings: string[];
  private readonly byType = new Map<string, RawPolicy[]>();

  constructor(policies: RawPolicy[], available: boolean, error?: string, meta: SnapshotMeta = {}) {
    this.available = available;
    this.error = error;
    this.partial = meta.partial === true;
    this.warnings = [...(meta.warnings ?? [])];
    this.rootOrgUnitId = deriveRootOrgUnit(policies);
    if (available && policies.length > 0 && this.rootOrgUnitId === null) {
      this.warnings.push(ROOT_UNKNOWN_WARNING);
    }
    for (const p of policies) {
      const key = normalizeType(p.setting?.type);
      if (!key) continue;
      const list = this.byType.get(key) ?? [];
      list.push(p);
      this.byType.set(key, list);
    }
  }

  /**
   * The org unit treated as the root for one setting. Without an identified
   * root, the org unit of the lowest-sortOrder non-group policy stands in.
   */
  private rootFor(list: RawPolicy[]): { orgUnit: string | null } | null {
    if (this.rootOrgUnitId !== null) return { orgUnit: this.rootOrgUnitId };
    const orgWide = list.filter((p) => !p.policyQuery?.group).sort(byPrecedence);
    return orgWide.length > 0 ? { orgUnit: bareOrgUnit(orgWide[0]) } : null;
  }

  private static isRoot(policy: RawPolicy, root: { orgUnit: string | null }): boolean {
    if (policy.policyQuery?.group) return false;
    const orgUnit = bareOrgUnit(policy);
    return orgUnit === null || orgUnit === root.orgUnit;
  }

  /**
   * Resolve the root org unit's effective value for a setting type. Policies
   * for child org units and groups never feed this value; they only count as
   * overrides when their own value differs.
   */
  get(settingType: string): PolicyLookup {
    const list = this.byType.get(settingType) ?? [];
    const root = this.rootFor(list);
    const rootPolicies = root ? list.filter((p) => PolicySnapshot.isRoot(p, root)) : [];
    if (rootPolicies.length === 0) {
      return { found: false, value: null, overrideCount: 0, licenseConditional: false };
    }

    const unconditional = rootPolicies.filter((p) => !isLicenseScoped(p));
    const licenseConditional = unconditional.length === 0;
    const pool = licenseConditional ? rootPolicies : unconditional;
    const value = reduceValues(settingType, [...pool].sort(byPrecedence));

    const merge = MERGE_REDUCER_SETTINGS.has(settingType);
    const overrideCount = this.overrides(settingType).filter((scope) =>
      merge
        ? Object.keys(scope.value).some((field) => !isDeepStrictEqual(value[field], scope.value[field]))
        : !isDeepStrictEqual(value, scope.value)
    ).length;

    return { found: true, value, overrideCount, licenseConditional };
  }

  /**
   * Every org unit or group outside the root that has an admin policy for the
   * setting, with the value from its highest-precedence policy.
   */
  overrides(settingType: string): PolicyScope[] {
    const list = this.byType.get(settingType) ?? [];
    const root = this.rootFor(list);
    if (!root) return [];

    const scopes = new Map<string, { policy: RawPolicy; kind: PolicyScope['kind'] }>();
    for (const policy of list) {
      if (policy.type !== 'ADMIN' || PolicySnapshot.isRoot(policy, root)) continue;
      const group = policy.policyQuery?.group;
      const id = group || policy.policyQuery?.orgUnit || '';
      const key = `${group ? 'group' : 'orgUnit'}:${id}`;
      const kept = scopes.get(key);
      if (!kept || byPrecedence(kept.policy, policy) < 0) {
        scopes.set(key, { policy, kind: group ? 'group' : 'orgUnit' });
      }
    }
    return [...scopes.entries()].map(([key, { policy, kind }]) => ({
      kind,
      id: key.slice(key.indexOf(':') + 1),
      value: policy.setting?.value ?? {},
    }));
  }

  /** All policies matching a setting type (e.g. for rule.dlp counts). */
  all(settingType: string): RawPolicy[] {
    return this.byType.get(settingType) ?? [];
  }

  /** Every setting type present in this snapshot. */
  settingTypes(): string[] {
    return [...this.byType.keys()];
  }
}

export class PolicyService {
  /**
   * Fetch every admin policy for the customer of `subject` (a super admin).
   * Never throws: on failure it returns an unavailable snapshot so the audit
   * can degrade to manual checks.
   */
  async loadOrgPolicies(subject: string): Promise<PolicySnapshot> {
    try {
      const token = await getDelegatedAccessToken(subject);
      const policies: RawPolicy[] = [];
      let pageToken: string | undefined;
      let pageIndex = 0;
      const warnings: string[] = [];
      let partial = false;

      do {
        if (pageIndex > 0 && INTER_PAGE_DELAY_MS > 0) {
          await sleep(INTER_PAGE_DELAY_MS);
        }

        const url = new URL(POLICIES_ENDPOINT);
        url.searchParams.set('pageSize', String(PAGE_SIZE));
        if (pageToken) url.searchParams.set('pageToken', pageToken);

        const page = await fetchPoliciesPage(url.toString(), token);
        policies.push(...page.policies);
        pageToken = page.nextPageToken;
        pageIndex += 1;

        // An empty page that still returns a token would loop forever.
        if (pageToken && (page.policies.length === 0 || pageIndex >= MAX_POLICY_PAGES)) {
          partial = true;
          warnings.push(
            `The policy list was cut off after ${pageIndex} pages. Results may be incomplete.`
          );
          break;
        }
      } while (pageToken);

      return new PolicySnapshot(policies, true, undefined, { partial, warnings });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return new PolicySnapshot([], false, message);
    }
  }
}

export const policyService = new PolicyService();

// --- Value helpers ----------------------------------------------------------

/**
 * Read a field from a setting value, tolerating both camelCase (what the JSON
 * API returns) and snake_case (as documented) spellings.
 */
export function readField(
  value: Record<string, unknown> | null | undefined,
  ...names: string[]
): unknown {
  if (!value) return undefined;
  for (const name of names) {
    if (name in value) return value[name];
    const snake = name.replace(/[A-Z]/g, (m) => `_${m.toLowerCase()}`);
    if (snake in value) return value[snake];
    const camel = name.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
    if (camel in value) return value[camel];
  }
  return undefined;
}

export function readBool(
  value: Record<string, unknown> | null | undefined,
  ...names: string[]
): boolean | undefined {
  const v = readField(value, ...names);
  return typeof v === 'boolean' ? v : undefined;
}

export function readString(
  value: Record<string, unknown> | null | undefined,
  ...names: string[]
): string | undefined {
  const v = readField(value, ...names);
  return typeof v === 'string' ? v : undefined;
}
