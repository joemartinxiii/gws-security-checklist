import { WorkspaceService } from './workspace.service';
import { dnsCheckService, domainsToCheck, type DNSRecord } from './dns-check.service';
import { chromePolicyService, ChromePolicyApiError } from './chrome-policy.service';
import {
  policyService,
  PolicySnapshot,
  PolicyLookup,
  readBool,
  readField,
  readString,
} from './policy.service';
import type { PolicyApiMeta, Severity, HardeningStatistics } from './securityAuditStore';
import { collectTwoSvUsers, type TwoSvReport } from './twoSvReport';

export type { Severity };

export interface HardeningCheck {
  id: string;
  category: string;
  name: string;
  description: string;
  /**
   * `info` marks org-dependent settings that have no universal "right" answer
   * (e.g. mail delegation, calendar sharing) — surfaced for awareness, not
   * graded against a target.
   */
  status: 'pass' | 'warning' | 'fail' | 'manual' | 'info';
  /** How this check was resolved — used by the UI to explain manual items. */
  source: 'auto' | 'manual';
  /** MSP prioritization for client findings lists. */
  severity: Severity;
  currentValue?: any;
  recommendedValue?: any;
  /** Business risk in plain language (why this matters to the client). */
  rationale: string;
  /** Advisory guidance: what to do, when to bend, how to scope. */
  recommendation: string;
  adminConsoleUrl?: string;
  issues?: string[];
}

/** Static definition of a checklist item. CHECKLIST.md lists every item. */
interface CheckMeta {
  id: string;
  category: string;
  name: string;
  description: string;
  severity: Severity;
  /** Short target state, shown in the "Recommended" column. */
  recommendedValue: string;
  /** Why this matters in a client conversation. */
  rationale: string;
  /** Actionable guidance (how / exceptions). */
  recommendation: string;
  adminConsoleUrl?: string;
}

type EvalResult = {
  status: HardeningCheck['status'];
  currentValue: string;
  issues?: string[];
};

type Evaluator = (value: Record<string, unknown>, lookup: PolicyLookup) => EvalResult;

const HUMAN_ENUM: Record<string, string> = {
  EXTERNAL_FREE_BUSY_ONLY: 'Free/busy only',
  EXTERNAL_ALL_INFO_READ_ONLY: 'See all info',
  EXTERNAL_ALL_INFO_READ_WRITE: 'See + change',
  EXTERNAL_ALL_INFO_READ_WRITE_MANAGE: 'Manage sharing',
  DISALLOWED: 'Off (internal only)',
  ALLOWLISTED_DOMAINS: 'Allowlisted domains only',
  ALLOWED: 'On (anyone external)',
  PRIVATE_TO_OWNER: 'Private to owner',
  LINK_SHARING_PRIVATE: 'Private to owner',
  PRIMARY_AUDIENCE_WITH_LINK: 'Anyone in org with link',
  PRIMARY_AUDIENCE_WITH_LINK_OR_SEARCH: 'Org with link or search',
  RECIPIENTS_ONLY: 'Recipients only',
  RECIPIENTS_OR_AUDIENCE: 'Recipients or audience',
  RECIPIENTS_OR_AUDIENCE_OR_PUBLIC: 'Recipients, audience, or public',
  ALL_ELIGIBLE_USERS: 'All users',
  ELIGIBLE_INTERNAL_USERS: 'Internal users',
  NONE: 'None',
};

function humanEnum(v: string | undefined): string {
  if (!v) return 'Unknown';
  return HUMAN_ENUM[v] ?? v;
}

const CORE_SERVICE_NAMES: Record<string, string> = {
  appsheet: 'AppSheet',
  calendar: 'Calendar',
  cloud_search: 'Cloud Search',
  drive_and_docs: 'Drive and Docs',
  gmail: 'Gmail',
  chat: 'Chat',
  meet: 'Meet',
  vault: 'Vault',
  voice: 'Voice',
  groups_for_business: 'Groups',
  keep: 'Keep',
  sites: 'Sites',
  tasks: 'Tasks',
};

function serviceEnabled(value: Record<string, unknown> | null | undefined): boolean | undefined {
  const state = readString(value, 'serviceState');
  if (state) {
    const upper = state.toUpperCase();
    if (upper.includes('DISABLED') || upper === 'OFF') return false;
    if (upper.includes('ENABLED') || upper === 'ON') return true;
    return undefined;
  }
  return readBool(value, 'serviceStatus', 'enabled', 'enableService');
}

function joinNames(names: string[]): string {
  if (names.length <= 12) return names.join(', ');
  return `${names.slice(0, 12).join(', ')} + ${names.length - 12} more`;
}

function serviceLabel(id: string): string {
  if (CORE_SERVICE_NAMES[id]) return CORE_SERVICE_NAMES[id];
  return id
    .split('_')
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

export interface TwoSvCount {
  enforced: number;
  total: number;
  /** False when the Directory listing still had another page at the cap. */
  complete: boolean;
}

/**
 * Page through Directory users.list. A truncated count must not be scored as
 * a full-org pass.
 */
export async function countEnforced2sv(
  listPage: (pageToken?: string) => Promise<{
    users?: Array<{ isEnforcedIn2Sv?: boolean }>;
    nextPageToken?: string;
  }>,
  maxUsers = 50000
): Promise<TwoSvCount> {
  let pageToken: string | undefined;
  let enforced = 0;
  let total = 0;
  let complete = true;
  do {
    const page = await listPage(pageToken);
    const users = page.users || [];
    total += users.length;
    enforced += users.filter((user) => user.isEnforcedIn2Sv === true).length;
    pageToken = page.nextPageToken || undefined;
    // An empty page that still advertises another page would loop forever.
    if (pageToken && (users.length === 0 || total >= maxUsers)) {
      complete = false;
      break;
    }
  } while (pageToken);
  return { enforced, total, complete };
}

export function summarize2svCoverage(
  enforced: number,
  total: number,
  complete: boolean
): { status: 'pass' | 'warning' | 'fail'; currentValue: string } {
  const rate = total > 0 ? enforced / total : 0;
  const pct = Math.round(rate * 100);
  const counted = `${pct}% enforced (${enforced}/${total} users)`;
  if (total === 0) {
    return { status: 'warning', currentValue: 'No users returned by Directory' };
  }
  if (!complete) {
    return {
      status: rate > 0.5 ? 'warning' : 'fail',
      currentValue: `${counted}; directory listing stopped early, so this cannot pass`,
    };
  }
  return {
    status: rate > 0.8 ? 'pass' : rate > 0.5 ? 'warning' : 'fail',
    currentValue: counted,
  };
}

export interface TwoSvEnforcement {
  status: 'pass' | 'warning' | 'fail';
  currentValue: string;
  issues: string[];
}

type EnforcementState = { state: 'on' | 'scheduled' | 'off'; from?: Date };

/** `enforced_from` unset means 2-Step Verification is not enforced. */
function enforcementState(value: Record<string, unknown> | null, now: Date): EnforcementState {
  const raw = readString(value, 'enforcedFrom');
  const from = raw ? new Date(raw) : undefined;
  if (!from || Number.isNaN(from.getTime())) return { state: 'off' };
  return { state: from.getTime() <= now.getTime() ? 'on' : 'scheduled', from };
}

function isoDay(date: Date | undefined): string {
  return date ? date.toISOString().slice(0, 10) : 'an unknown date';
}

function scopeCountLabel(count: number): string {
  return `${count} org unit${count === 1 ? '' : 's'} or group${count === 1 ? '' : 's'}`;
}

/**
 * Score 2-Step Verification enforcement from the root org unit's policy.
 * Org units and groups with their own enforcement date refine the result.
 */
export function evaluate2svEnforcement(snapshot: PolicySnapshot, now: Date = new Date()): TwoSvEnforcement {
  const type = 'security.two_step_verification_enforcement';
  const root = enforcementState(snapshot.get(type).value, now);
  const others = snapshot.overrides(type).map((scope) => enforcementState(scope.value, now));
  const notEnforced = others.filter((other) => other.state !== 'on').length;
  const active = others.filter((other) => other.state !== 'off').length;

  if (root.state === 'on') {
    if (notEnforced > 0) {
      return {
        status: 'warning',
        currentValue: `Enforced at the top level since ${isoDay(root.from)}, but not for ${scopeCountLabel(notEnforced)}`,
        issues: [
          `${scopeCountLabel(notEnforced)} turn enforcement off or start it later than the top-level org unit.`,
        ],
      };
    }
    return {
      status: 'pass',
      currentValue: `Enforced for all users since ${isoDay(root.from)}`,
      issues: [],
    };
  }
  if (root.state === 'scheduled') {
    return {
      status: 'warning',
      currentValue: `Enforcement starts ${isoDay(root.from)}`,
      issues: ['Enforcement is scheduled for the future. Users are not required to use 2-Step Verification until then.'],
    };
  }
  if (active > 0) {
    return {
      status: 'warning',
      currentValue: `Enforced for ${scopeCountLabel(active)} only`,
      issues: ['The top-level org unit does not enforce 2-Step Verification, so users outside those scopes are not required to use it.'],
    };
  }
  return {
    status: 'fail',
    currentValue: 'Not enforced',
    issues: ['No enforcement date is set for the top-level org unit.'],
  };
}

const FACTOR_SET_LABELS: Record<string, string> = {
  ALL: 'Any method',
  PASSKEY_ONLY: 'Security keys or passkeys only',
  PASSKEY_PLUS_SECURITY_CODE: 'Passkeys plus security codes',
  PASSKEY_PLUS_IP_BOUND_SECURITY_CODE: 'Passkeys plus IP-bound security codes',
  NO_TELEPHONY: 'Any method except phone',
};

/** Factor sets that limit sign-in to security keys or passkeys (with optional codes). */
const PHISHING_RESISTANT_FACTOR_SETS = new Set([
  'PASSKEY_ONLY',
  'PASSKEY_PLUS_SECURITY_CODE',
  'PASSKEY_PLUS_IP_BOUND_SECURITY_CODE',
]);

function factorSetLabel(set: string): string {
  return FACTOR_SET_LABELS[set] ?? set;
}

export function evaluatePasswordPolicy(value: Record<string, unknown>): EvalResult {
  const strength = readString(value, 'allowedStrength');
  const enforced = readBool(value, 'enforceRequirementsAtLogin') === true;
  const minRaw = Number(readField(value, 'minimumLength'));
  const min = Number.isFinite(minRaw) && minRaw > 0 ? minRaw : undefined;
  const isStrong = strength === 'STRONG';
  const longEnough = min !== undefined && min >= 12;

  const issues: string[] = [];
  if (isStrong && !longEnough) {
    issues.push(
      min === undefined
        ? 'The minimum password length is not set. Google’s default is 8 characters.'
        : `The minimum password length is ${min}. Use at least 12.`
    );
  }
  if (isStrong && !enforced) {
    issues.push('Strength and length are not enforced at sign-in, so existing weak passwords keep working.');
  }

  return {
    status: !isStrong ? 'fail' : longEnough && enforced ? 'pass' : 'warning',
    currentValue: [
      `Strength: ${strength ?? 'unknown'}`,
      min !== undefined ? `min length: ${min}` : null,
      `enforced at login: ${enforced ? 'yes' : 'no'}`,
    ]
      .filter(Boolean)
      .join(', '),
    issues: issues.length ? issues : undefined,
  };
}

const SEVERITY_WEIGHT: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const STATUS_CREDIT: Partial<Record<HardeningCheck['status'], number>> = {
  pass: 1,
  warning: 0.5,
  fail: 0,
};

/**
 * Severity-weighted pass rate over graded checks (pass, warning, fail), 0-100.
 * Null when nothing was graded.
 */
export function computeHardeningScore(
  checks: Array<Pick<HardeningCheck, 'status' | 'severity'>>
): number | null {
  let weight = 0;
  let earned = 0;
  for (const check of checks) {
    const credit = STATUS_CREDIT[check.status];
    if (credit === undefined) continue;
    const w = SEVERITY_WEIGHT[check.severity] ?? 1;
    weight += w;
    earned += w * credit;
  }
  return weight === 0 ? null : Math.round((earned / weight) * 100);
}

/** Map raw errors to stable operator/client copy — never surface Google JSON. */
export function humanizeApiFailure(error: unknown, context: string): string {
  const msg = error instanceof Error ? error.message : String(error ?? '');
  if (/429|rate.?limit|RESOURCE_EXHAUSTED|quota/i.test(msg)) {
    return `${context}: temporarily rate-limited by Google. Wait a minute and run the audit again.`;
  }
  if (/403|PERMISSION_DENIED|forbidden/i.test(msg)) {
    return `${context}: permission denied. Run as a super admin with the required API scopes enabled.`;
  }
  if (/401|UNAUTHENTICATED/i.test(msg)) {
    return `${context}: authentication failed. Check domain-wide delegation and service account setup.`;
  }
  if (/404|NOT_FOUND/i.test(msg)) {
    return `${context}: API not found. Enable the API in Google Cloud for this project.`;
  }
  const http = msg.match(/HTTP\s+(\d{3})/i) || msg.match(/\b(\d{3})\b/);
  if (http) {
    return `${context}: request failed (HTTP ${http[1]}). Verify API enablement and admin privileges.`;
  }
  if (msg.includes('{') || msg.length > 160) {
    return `${context}: request failed. Verify API enablement, scopes, and super-admin access.`;
  }
  return msg ? `${context}: ${msg}` : `${context}: request failed.`;
}

export function policyApiMetaFromSnapshot(snapshot: PolicySnapshot): PolicyApiMeta {
  if (snapshot.available) {
    const meta: PolicyApiMeta = { available: true };
    if (snapshot.warnings.length > 0) meta.warnings = [...snapshot.warnings];
    if (snapshot.partial) meta.partial = true;
    return meta;
  }
  const raw = snapshot.error || '';
  let code = 'unavailable';
  if (/HTTP\s*429|429|rate.?limit|RESOURCE_EXHAUSTED/i.test(raw)) code = 'http_429';
  else if (/HTTP\s*503|503/i.test(raw)) code = 'http_503';
  else if (/HTTP\s*403|403/i.test(raw)) code = 'http_403';
  else if (/HTTP\s*401|401/i.test(raw)) code = 'http_401';
  else if (/HTTP\s*404|404/i.test(raw)) code = 'http_404';

  return {
    available: false,
    code,
    message: humanizeApiFailure(raw || 'unavailable', 'Cloud Identity Policy API'),
  };
}

/**
 * Transient Google throttling / outage — do not replace a good last-run with a
 * mostly-manual degraded snapshot. Config issues (403/401) are not transient.
 */
export function isTransientPolicyFailure(meta: PolicyApiMeta): boolean {
  if (meta.available) return false;
  return meta.code === 'http_429' || meta.code === 'http_503';
}

/** Google's published defaults for `drive_and_docs.external_sharing`. */
const EXTERNAL_SHARING_DEFAULTS: Record<string, unknown> = {
  externalSharingMode: 'ALLOWED',
  allowReceivingExternalFiles: true,
  warnForExternalSharing: true,
  allowNonGoogleInvites: true,
  allowPublishingFiles: true,
  accessCheckerSuggestions: 'RECIPIENTS_OR_AUDIENCE_OR_PUBLIC',
  allowedPartiesForDistributingContent: 'ALL_ELIGIBLE_USERS',
};

function sharingFlag(value: Record<string, unknown>, field: string): boolean {
  return readBool(value, field) ?? (EXTERNAL_SHARING_DEFAULTS[field] as boolean);
}

function externalSharingOff(value: Record<string, unknown>): boolean {
  return (readString(value, 'externalSharingMode') ?? 'ALLOWED') === 'DISALLOWED';
}

export class HardeningService extends WorkspaceService {
  // --- Generic builders -----------------------------------------------------

  private baseFrom(meta: CheckMeta): Omit<HardeningCheck, 'status' | 'source'> {
    return {
      id: meta.id,
      category: meta.category,
      name: meta.name,
      description: meta.description,
      severity: meta.severity,
      recommendedValue: meta.recommendedValue,
      rationale: meta.rationale,
      recommendation: meta.recommendation,
      adminConsoleUrl: meta.adminConsoleUrl,
    };
  }

  /** A check that cannot be read via API and must be verified in the console. */
  private manualCheck(meta: CheckMeta, reason: string): HardeningCheck {
    return {
      ...this.baseFrom(meta),
      status: 'manual',
      source: 'manual',
      currentValue: 'Manual review',
      issues: [reason],
    };
  }

  /**
   * A check resolved from a Cloud Identity policy value. Falls back to a manual
   * result when the Policy API is unavailable or the setting isn't returned
   * (unless `evaluateOnMissing` is set, for array/presence-based checks where an
   * absent policy is itself meaningful).
   */
  private policyCheck(
    snapshot: PolicySnapshot,
    meta: CheckMeta,
    settingType: string,
    evaluate: Evaluator,
    options: { evaluateOnMissing?: boolean; defaultValue?: Record<string, unknown> } = {}
  ): HardeningCheck {
    const base = this.baseFrom(meta);

    if (!snapshot.available) {
      return {
        ...base,
        status: 'manual',
        source: 'manual',
        currentValue: 'Manual review',
        issues: [
          'Automated read unavailable — verify this setting in the Admin console until Policy API access is restored.',
        ],
      };
    }

    const lookup = snapshot.get(settingType);
    if (!lookup.found && !options.evaluateOnMissing) {
      if (options.defaultValue) {
        const assumed: PolicyLookup = {
          found: true,
          value: options.defaultValue,
          overrideCount: 0,
          licenseConditional: false,
        };
        const result = evaluate(options.defaultValue, assumed);
        const issues = result.issues ? [...result.issues] : [];
        issues.push('No admin policy is saved. This value is Google’s published default.');
        return {
          ...base,
          status: result.status,
          source: 'auto',
          currentValue: `${result.currentValue} (Google default)`,
          issues,
        };
      }
      return {
        ...base,
        status: 'manual',
        source: 'manual',
        currentValue: 'Not explicitly configured',
        issues: [
          'No org policy returned — a Google default likely applies. Confirm the intended setting in the Admin console.',
        ],
      };
    }

    const result = evaluate(lookup.value ?? {}, lookup);
    const issues = result.issues ? [...result.issues] : [];
    issues.push(...this.lookupNotes([lookup]));

    return {
      ...base,
      status: result.status,
      source: 'auto',
      currentValue: result.currentValue,
      issues: issues.length ? issues : undefined,
    };
  }

  private lookupNotes(lookups: PolicyLookup[]): string[] {
    const notes: string[] = [];
    const overrides = lookups.reduce((sum, lookup) => sum + lookup.overrideCount, 0);
    if (overrides > 0) {
      notes.push(
        `Showing the top-level org unit. ${overrides} other ${
          overrides === 1 ? 'org unit or group overrides' : 'org units or groups override'
        } this setting.`
      );
    }
    if (lookups.some((lookup) => lookup.licenseConditional)) {
      notes.push(
        'The value shown applies only to users with a specific license. Users without that license may have a different value.'
      );
    }
    return notes;
  }

  /**
   * A check that depends on several settings at once (for example POP and
   * IMAP). `defaults` supplies Google's published value for a setting with no
   * saved policy; a setting with neither is passed to `evaluate` as null.
   */
  private policyCheckAll(
    snapshot: PolicySnapshot,
    meta: CheckMeta,
    settingTypes: string[],
    evaluate: (values: Array<Record<string, unknown> | null>) => EvalResult,
    defaults: Record<string, Record<string, unknown>> = {}
  ): HardeningCheck {
    const base = this.baseFrom(meta);
    if (!snapshot.available) {
      return {
        ...base,
        status: 'manual',
        source: 'manual',
        currentValue: 'Manual review',
        issues: [
          'Automated read unavailable. Verify this setting in the Admin console until Policy API access is restored.',
        ],
      };
    }

    const lookups = settingTypes.map((type) => snapshot.get(type));
    const values = lookups.map((lookup, i) =>
      lookup.found ? lookup.value : (defaults[settingTypes[i]] ?? null)
    );
    if (values.every((value) => value === null)) {
      return {
        ...base,
        status: 'manual',
        source: 'manual',
        currentValue: 'Not explicitly configured',
        issues: [
          'No org policy returned. A Google default likely applies. Confirm the intended setting in the Admin console.',
        ],
      };
    }

    const result = evaluate(values);
    const issues = [...(result.issues ?? []), ...this.lookupNotes(lookups)];
    return {
      ...base,
      status: result.status,
      source: 'auto',
      currentValue: result.currentValue,
      issues: issues.length ? issues : undefined,
    };
  }

  // --- Administrator accounts -----------------------------------------------

  /** Page through Directory users.list for one query. Never loops on an empty page. */
  private async listDirectoryUsers(
    admin: any,
    query: string,
    fields: string,
    maxPages = 20
  ): Promise<Array<Record<string, any>>> {
    const users: Array<Record<string, any>> = [];
    let pageToken: string | undefined;
    let pages = 0;
    do {
      const response = await this.withRetry(() =>
        admin.users.list({
          customer: 'my_customer',
          maxResults: 500,
          query,
          pageToken,
          fields: `${fields},nextPageToken`,
        })
      );
      const page: Array<Record<string, any>> = response.data.users || [];
      users.push(...page);
      pageToken = response.data.nextPageToken || undefined;
      pages += 1;
      if (pageToken && (page.length === 0 || pages >= maxPages)) break;
    } while (pageToken);
    return users.filter((user) => user.suspended !== true);
  }

  async checkSuperAdminCount(userEmail: string): Promise<HardeningCheck> {
    const meta: CheckMeta = {
      id: 'super-admin-count',
      category: 'Administrator Accounts',
      name: 'Super Admin Count',
      description: 'Number of active super admin accounts',
      severity: 'critical',
      recommendedValue: '2 to 4 super admins',
      rationale:
        'Super admins can read all data and change every setting. A single super admin leaves no backup if that person is locked out or leaves. Too many super admins gives attackers more high-value accounts to phish.',
      recommendation:
        'Keep two to four super admins. Use named accounts, not shared ones. Give day-to-day admins a delegated admin role with only the privileges they need.',
      adminConsoleUrl: 'https://admin.google.com/ac/roles',
    };
    try {
      const admin = await this.adminFor(userEmail);
      const admins = await this.listDirectoryUsers(admin, 'isAdmin=true', 'users(primaryEmail,suspended)');
      return this.evaluateSuperAdminCount(meta, admins.length);
    } catch (error: unknown) {
      return this.manualCheck(meta, humanizeApiFailure(error, 'Directory user list'));
    }
  }

  private evaluateSuperAdminCount(meta: CheckMeta, count: number): HardeningCheck {
    const base = this.baseFrom(meta);
    const currentValue = `${count} super admin${count === 1 ? '' : 's'}`;
    if (count >= 2 && count <= 4) {
      return { ...base, status: 'pass', source: 'auto', currentValue };
    }
    const issue =
      count === 0
        ? 'Directory returned no active super admins. Confirm the signed-in account has the privileges to list users.'
        : count === 1
          ? 'Only one super admin exists, so there is no backup if that account is lost or locked out.'
          : `${count} super admins is more than needed. Move day-to-day admins to delegated admin roles.`;
    return { ...base, status: 'warning', source: 'auto', currentValue, issues: [issue] };
  }

  async checkAdminTwoSv(userEmail: string): Promise<HardeningCheck> {
    const meta: CheckMeta = {
      id: 'admin-2sv',
      category: 'Administrator Accounts',
      name: 'Admin 2-Step Verification',
      description: '2-Step Verification enrollment for super admins and delegated admins',
      severity: 'critical',
      recommendedValue: 'Every admin enrolled',
      rationale:
        'A stolen admin password without a second factor gives an attacker control of the tenant. Admin accounts are the first thing attackers go after.',
      recommendation:
        'Enroll every super admin and delegated admin in 2-Step Verification now. Use security keys for these accounts where possible.',
      adminConsoleUrl: 'https://admin.google.com/ac/security/2sv',
    };
    try {
      const admin = await this.adminFor(userEmail);
      const fields = 'users(primaryEmail,isEnrolledIn2Sv,suspended)';
      const superAdmins = await this.listDirectoryUsers(admin, 'isAdmin=true', fields);
      const delegated = await this.listDirectoryUsers(admin, 'isDelegatedAdmin=true', fields);
      return this.evaluateAdminTwoSv(meta, superAdmins, delegated);
    } catch (error: unknown) {
      return this.manualCheck(meta, humanizeApiFailure(error, 'Directory user list'));
    }
  }

  private evaluateAdminTwoSv(
    meta: CheckMeta,
    superAdmins: Array<Record<string, any>>,
    delegated: Array<Record<string, any>>
  ): HardeningCheck {
    const base = this.baseFrom(meta);
    const superEmails = new Set(superAdmins.map((user) => user.primaryEmail));
    const delegatedOnly = delegated.filter((user) => !superEmails.has(user.primaryEmail));
    const missingSuper = superAdmins.filter((user) => user.isEnrolledIn2Sv !== true);
    const missingDelegated = delegatedOnly.filter((user) => user.isEnrolledIn2Sv !== true);
    const total = superAdmins.length + delegatedOnly.length;
    const enrolled = total - missingSuper.length - missingDelegated.length;
    const currentValue = `${enrolled} of ${total} admins enrolled`;

    const issues: string[] = [];
    if (missingSuper.length > 0) {
      issues.push(`Super admins not enrolled: ${joinNames(missingSuper.map((user) => user.primaryEmail))}.`);
    }
    if (missingDelegated.length > 0) {
      issues.push(`Delegated admins not enrolled: ${joinNames(missingDelegated.map((user) => user.primaryEmail))}.`);
    }
    if (total === 0) {
      issues.push('Directory returned no active admins. Confirm the signed-in account has the privileges to list users.');
    }

    const status: HardeningCheck['status'] =
      missingSuper.length > 0 ? 'fail' : missingDelegated.length > 0 || total === 0 ? 'warning' : 'pass';
    return {
      ...base,
      status,
      source: 'auto',
      currentValue,
      issues: issues.length ? issues : undefined,
    };
  }

  private administratorAccountPolicyChecks(snapshot: PolicySnapshot): HardeningCheck[] {
    return [
      this.policyCheck(
        snapshot,
        {
          id: 'super-admin-recovery',
          category: 'Administrator Accounts',
          name: 'Super Admin Account Recovery',
          description: 'Whether super admins can recover their own accounts',
          severity: 'high',
          recommendedValue: 'Off',
          rationale:
            'Self-service recovery lets anyone who controls a super admin’s recovery phone or email take over that account. Super admin accounts are too powerful to rely on that path.',
          recommendation:
            'Turn self-service recovery off for super admins. Keep two or more super admins so one can reset the other.',
          adminConsoleUrl: 'https://admin.google.com/ac/security',
        },
        'security.super_admin_account_recovery',
        (value) => {
          const enabled = readBool(value, 'enableAccountRecovery') ?? false;
          return {
            status: enabled ? 'warning' : 'pass',
            currentValue: enabled ? 'Self-service recovery on' : 'Self-service recovery off',
          };
        },
        { defaultValue: { enableAccountRecovery: false } }
      ),
    ];
  }

  // --- Authentication -------------------------------------------------------

  /**
   * 2-Step Verification enforcement. The root org unit's
   * `security.two_step_verification_enforcement` policy is the primary signal.
   * The Directory per-user ratio (active users only) is supporting detail, and
   * the fallback when the Policy API is unavailable.
   */
  async check2FAEnforcement(
    userEmail: string,
    snapshot?: PolicySnapshot,
    now: Date = new Date()
  ): Promise<HardeningCheck> {
    const meta: CheckMeta = {
      id: '2fa-enforcement',
      category: 'Authentication',
      name: '2-Step Verification',
      description: 'Two-step verification enforcement across users',
      severity: 'critical',
      recommendedValue: 'Enforced for all users',
      rationale:
        'Account takeover is the most common path into a Workspace tenant. Without enforced 2-Step Verification, a phished password is often enough to read mail, reset other accounts, and move data.',
      recommendation:
        'Enforce 2-Step Verification for the whole organization, with a short grace period for new users. Enroll admins and externally facing roles first. Check the enforcement date in the Admin console if it is scheduled for the future.',
      adminConsoleUrl: 'https://admin.google.com/ac/security/2sv',
    };

    let counted: TwoSvCount | null = null;
    let countError: unknown;
    try {
      const admin = await this.adminFor(userEmail);
      counted = await countEnforced2sv(async (pageToken) => {
        const usersResponse = await this.withRetry(() =>
          admin.users.list({
            customer: 'my_customer',
            maxResults: 500,
            query: 'isSuspended=false',
            pageToken,
            fields: 'users(isEnforcedIn2Sv),nextPageToken',
          })
        );
        return {
          users: usersResponse.data.users || [],
          nextPageToken: usersResponse.data.nextPageToken,
        };
      });
    } catch (error: unknown) {
      countError = error;
    }
    const ratio = counted
      ? summarize2svCoverage(counted.enforced, counted.total, counted.complete)
      : null;

    if (snapshot?.available) {
      const policy = evaluate2svEnforcement(snapshot, now);
      const issues = [...policy.issues];
      issues.push(
        ratio
          ? `Per-user check: ${ratio.currentValue} among active users.`
          : humanizeApiFailure(countError, 'Directory user list')
      );
      return {
        ...this.baseFrom(meta),
        status: policy.status,
        source: 'auto',
        currentValue: policy.currentValue,
        issues,
      };
    }

    if (!ratio) {
      return {
        ...this.baseFrom(meta),
        status: 'warning',
        source: 'auto',
        currentValue: 'Unable to measure',
        issues: [humanizeApiFailure(countError, 'Directory user list')],
      };
    }
    return {
      ...this.baseFrom(meta),
      status: ratio.status,
      source: 'auto',
      currentValue: ratio.currentValue,
      issues: [
        'The Policy API is unavailable, so this result comes from per-user enforcement flags for active users. Confirm the organization-wide setting in the Admin console.',
      ],
    };
  }

  /**
   * Per-user 2-step enrollment and enforcement for every Directory user,
   * suspended users included. Keeps name and email.
   */
  async listTwoSvUsers(userEmail: string): Promise<TwoSvReport> {
    const admin = await this.adminFor(userEmail);
    return collectTwoSvUsers(async (pageToken) => {
      const usersResponse = await this.withRetry(() =>
        admin.users.list({
          customer: 'my_customer',
          maxResults: 500,
          pageToken,
          fields:
            'users(primaryEmail,name(fullName,givenName,familyName),isEnrolledIn2Sv,isEnforcedIn2Sv),nextPageToken',
        })
      );
      return {
        users: usersResponse.data.users || [],
        nextPageToken: usersResponse.data.nextPageToken,
      };
    });
  }

  private authenticationChecks(snapshot: PolicySnapshot): HardeningCheck[] {
    return [
      this.policyCheck(
        snapshot,
        {
          id: 'password-policy',
          category: 'Authentication',
          name: 'Strong Password Policy',
          description: 'Password strength and enforcement requirements',
          severity: 'high',
          recommendedValue: 'Strong, 12+ characters, enforced at login',
          rationale:
            'Weak or reused passwords remain a major breach vector, especially for accounts that are not yet on hardware keys or strong 2SV methods.',
          recommendation:
            'Require strong passwords with a minimum length of 12 and enforce the requirements at sign-in. Pair with 2SV rather than relying on password strength alone.',
          adminConsoleUrl: 'https://admin.google.com/ac/security/passwordmanagement',
        },
        'security.password',
        evaluatePasswordPolicy,
        {
          defaultValue: {
            allowedStrength: 'STRONG',
            minimumLength: 8,
            enforceRequirementsAtLogin: false,
          },
        }
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'advanced-protection',
          category: 'Authentication',
          name: 'Advanced Protection Program',
          description: 'User self-enrollment in the Advanced Protection Program',
          severity: 'medium',
          recommendedValue: 'Enrollment enabled',
          rationale:
            'Advanced Protection adds phishing-resistant controls for high-risk users (executives, finance, admins). Allowing self-enrollment makes that path available without forcing it on everyone.',
          recommendation:
            'Leave self-enrollment on. For VIP / admin cohorts, consider requiring Advanced Protection or security keys as a separate engagement item.',
          adminConsoleUrl: 'https://admin.google.com/ac/security/advanced-protection',
        },
        'security.advanced_protection_program',
        (value) => {
          const enabled = readBool(value, 'enableAdvancedProtectionSelfEnrollment');
          return {
            status: enabled ? 'pass' : 'warning',
            currentValue: enabled ? 'Enrollment enabled' : 'Enrollment disabled',
          };
        }
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'security-keys',
          category: 'Authentication',
          name: 'Security Keys for High-Value Accounts',
          description: 'Whether any org unit or group is limited to security keys or passkeys',
          severity: 'high',
          recommendedValue: 'Security keys or passkeys for admins and high-value accounts',
          rationale:
            'Text-message and app codes can be phished. Security keys and passkeys resist phishing, which matters most for admins, finance, and executives.',
          recommendation:
            'Create an org unit or group for admins and other high-value accounts and limit its 2-Step Verification methods to security keys or passkeys. Keep other users on the broader set of methods if keys are not practical for them.',
          adminConsoleUrl: 'https://admin.google.com/ac/security/2sv',
        },
        'security.two_step_verification_enforcement_factor',
        (value, lookup) => {
          const rootSet = lookup.found
            ? (readString(value, 'allowedSignInFactorSet') ?? 'ALL')
            : 'ALL';
          const restricted = (set: string | undefined) => !!set && PHISHING_RESISTANT_FACTOR_SETS.has(set);
          const scopes = snapshot
            .overrides('security.two_step_verification_enforcement_factor')
            .filter((scope) => restricted(readString(scope.value, 'allowedSignInFactorSet')));
          const rootLabel = `Top-level: ${factorSetLabel(rootSet)}`;
          if (restricted(rootSet) || scopes.length > 0) {
            return {
              status: 'pass',
              currentValue: scopes.length
                ? `${rootLabel}. Keys or passkeys required for ${scopeCountLabel(scopes.length)}`
                : rootLabel,
            };
          }
          return {
            status: 'info',
            currentValue: `${rootLabel}. No org unit or group requires security keys or passkeys`,
          };
        },
        { evaluateOnMissing: true }
      ),
    ];
  }

  // --- Email ----------------------------------------------------------------

  private emailChecks(snapshot: PolicySnapshot): HardeningCheck[] {
    const gmailUserSettings = 'https://admin.google.com/ac/apps/gmail/usersettings';
    const gmailEndUser = 'https://admin.google.com/ac/apps/gmail/enduseraccess';
    const gmailSafety = 'https://admin.google.com/ac/apps/gmail/safety';
    const gmailSpam = 'https://admin.google.com/ac/apps/gmail/spam';
    const gmailCompliance = 'https://admin.google.com/ac/apps/gmail/compliance';

    return [
      this.manualCheck(
        {
          id: 'gmail-read-receipts',
          category: 'Email',
          name: 'Email Read Receipts',
          description: 'Whether users can request read receipts',
          severity: 'low',
          recommendedValue: 'Do not allow',
          rationale:
            'Read receipts can leak when a message was opened and are rarely required for SMB operations. They add little business value and some privacy friction.',
          recommendation:
            'Set to Do not allow unless the client has a documented workflow that depends on receipts. Confirm in the Admin console.',
          adminConsoleUrl: gmailUserSettings,
        },
        'Google does not publish this setting. Verify it in the Admin console.'
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'gmail-delegation',
          category: 'Email',
          name: 'Mail Delegation',
          description: 'Whether users can delegate mailbox access to others',
          severity: 'medium',
          recommendedValue: 'OFF unless there is a business need',
          rationale:
            'Delegation grants another person full mailbox access. That is appropriate for executive assistants or shared inboxes, but org-wide enablement expands the blast radius of compromised accounts.',
          recommendation:
            'Prefer OFF by default. Where needed (EA support, shared roles), enable only for specific OUs/groups and document owners. This is a business choice — not an automatic fail when on.',
          adminConsoleUrl: gmailUserSettings,
        },
        'gmail.mail_delegation',
        (value) => {
          const enabled = readBool(value, 'enableMailDelegation');
          return {
            status: enabled ? 'info' : 'pass',
            currentValue: enabled ? 'Delegation allowed' : 'Delegation off',
          };
        }
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'gmail-confidential-mode',
          category: 'Email',
          name: 'Confidential Mode',
          description: 'Whether users can send confidential-mode email',
          severity: 'low',
          recommendedValue: 'ON',
          rationale:
            'Confidential mode gives users expiring links and copy/download restrictions for sensitive messages — a lightweight control when full DLP is unavailable.',
          recommendation:
            'Keep ON for most tenants. Educate users that it is not a substitute for classification/DLP on regulated data.',
          adminConsoleUrl: gmailUserSettings,
        },
        'gmail.confidential_mode',
        (value) => {
          const enabled = readBool(value, 'enableConfidentialMode');
          return {
            status: enabled ? 'pass' : 'warning',
            currentValue: enabled ? 'On' : 'Off',
          };
        }
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'gmail-restrict-delivery',
          category: 'Email',
          name: 'Email Receiving Security',
          description: 'Restrict inbound delivery to allowlisted domains',
          severity: 'medium',
          recommendedValue: 'Allowlist trusted domains when appropriate',
          rationale:
            'Restricting who can deliver mail into the tenant reduces spam and spoofed-partner noise. Over-restriction can break legitimate suppliers — apply only when the business model fits.',
          recommendation:
            'For closed partner ecosystems, add restrict-delivery rules for trusted domains. For typical SMBs that receive mail from the public internet, leave open and rely on SPF/DKIM/DMARC + phishing protections instead.',
          adminConsoleUrl: 'https://admin.google.com/ac/apps/gmail/compliance',
        },
        'gmail.restrict_delivery',
        (value) => {
          const rules = value['restrictDeliveryRules'];
          const count = Array.isArray(rules) ? rules.length : 0;
          return {
            status: count > 0 ? 'pass' : 'info',
            currentValue: count > 0 ? `${count} restrict-delivery rule(s)` : 'No inbound restrictions',
          };
        },
        { evaluateOnMissing: true }
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'gmail-external-warning',
          category: 'Email',
          name: 'Warn for External Recipients',
          description: 'Warn users before replying to external recipients / sending externally',
          severity: 'high',
          recommendedValue: 'ON',
          rationale:
            'A banner before sending outside the organization is one of the few controls that stops accidental disclosure of internal threads and attachments. That pattern shows up constantly in SMB incidents, and the user friction is low.',
          recommendation:
            'Turn the external-recipient warning ON.',
          adminConsoleUrl: gmailEndUser,
        },
        'gmail.external_recipient_warning',
        (value) => {
          const enabled = readBool(value, 'enabled');
          return {
            status: enabled ? 'pass' : 'warning',
            currentValue: enabled ? 'On' : 'Off',
          };
        },
        { defaultValue: { enabled: true } }
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'gmail-enhanced-scanning',
          category: 'Email',
          name: 'Enhanced Pre-Delivery Scanning',
          description: 'Improved detection of suspicious content before delivery',
          severity: 'high',
          recommendedValue: 'ON',
          rationale:
            'Pre-delivery scanning improves detection of malicious content before it lands in the inbox — one of the highest-value free mail defenses Google offers.',
          recommendation:
            'Keep enhanced pre-delivery message scanning ON for all users. There is rarely a valid reason to disable it for an SMB.',
          adminConsoleUrl: gmailSafety,
        },
        'gmail.enhanced_pre_delivery_message_scanning',
        (value) => {
          const enabled = readBool(value, 'enableImprovedSuspiciousContentDetection');
          return {
            status: enabled ? 'pass' : 'warning',
            currentValue: enabled ? 'On' : 'Off',
          };
        }
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'gmail-spam-bypass',
          category: 'Email',
          name: 'Spam Filter Bypass',
          description: 'Approved-sender lists that bypass spam filtering',
          severity: 'high',
          recommendedValue: 'No broad bypasses',
          rationale:
            'Bypassing spam filters for “trusted” senders is a common attacker pivot: once an allowlisted address is compromised or spoofed, malicious mail skips controls.',
          recommendation:
            'Avoid org-wide warning-banner hides and broad bypass lists. Prefer narrow exceptions with an owner and review date. Never hide warnings for all senders. If an approved sender list must exist, require authentication for every entry and list full email addresses, not domains.',
          adminConsoleUrl: gmailSpam,
        },
        'gmail.spam_override_lists',
        (value) => {
          const rules = value['spamOverride'];
          const list = Array.isArray(rules) ? (rules as Record<string, unknown>[]) : [];
          const hidesAll = list.some((r) => readBool(r, 'hideWarningBannerForAll') === true);
          const bypasses = list.some(
            (r) =>
              readBool(r, 'bypassInternalSenders') === true ||
              readBool(r, 'bypassSelectedSenders') === true ||
              readBool(r, 'hideWarningBannerFromSelectedSenders') === true
          );
          if (hidesAll) {
            return { status: 'fail', currentValue: 'Warnings hidden for all senders' };
          }
          if (bypasses) {
            return {
              status: 'warning',
              currentValue: 'Some spam bypass configured',
              issues: this.approvedSenderFindings(snapshot, list),
            };
          }
          return { status: 'pass', currentValue: 'No spam bypasses' };
        },
        { evaluateOnMissing: true }
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'gmail-auto-forwarding',
          category: 'Email',
          name: 'Automatic Forwarding',
          description: 'Whether users can auto-forward incoming mail externally',
          severity: 'medium',
          recommendedValue: 'OFF unless there is a business need',
          rationale:
            'Automatic forwarding can copy inbound mail to an external address, which is also a post-compromise exfiltration path. Many businesses use it on purpose for ticketing, archival, or a shared inbox.',
          recommendation:
            'Prefer OFF by default. Where a process needs it, allow it for a specific OU or group, name an owner, and record that choice. On is not an automatic fail.',
          adminConsoleUrl: gmailEndUser,
        },
        'gmail.auto_forwarding',
        (value) => {
          const enabled = readBool(value, 'enableAutoForwarding');
          return {
            status: enabled ? 'info' : 'pass',
            currentValue: enabled ? 'Allowed' : 'Off',
          };
        },
        { defaultValue: { enableAutoForwarding: true } }
      ),
      this.policyCheckAll(
        snapshot,
        {
          id: 'gmail-pop-imap',
          category: 'Email',
          name: 'POP and IMAP Access',
          description: 'Whether users can read Gmail from POP or IMAP mail clients',
          severity: 'high',
          recommendedValue: 'POP and IMAP off',
          rationale:
            'POP and IMAP let desktop and third-party mail clients copy a whole mailbox. Those clients often skip modern sign-in protections, which makes them a quiet path for data theft after a password leak.',
          recommendation:
            'Turn POP and IMAP off for everyone. If an app or device still needs one of them, enable it only for the OU or group that uses it and plan a move to OAuth-based access.',
          adminConsoleUrl: gmailEndUser,
        },
        ['gmail.pop_access', 'gmail.imap_access'],
        ([pop, imap]) => {
          const popOn = pop ? readBool(pop, 'enablePopAccess') : undefined;
          const imapOn = imap ? readBool(imap, 'enableImapAccess') : undefined;
          const label = (on: boolean | undefined) => (on === undefined ? 'unknown' : on ? 'on' : 'off');
          const currentValue = `POP: ${label(popOn)}, IMAP: ${label(imapOn)}`;
          if (popOn === true || imapOn === true) return { status: 'warning', currentValue };
          if (popOn === false && imapOn === false) return { status: 'pass', currentValue };
          return {
            status: 'manual',
            currentValue,
            issues: ['One of the two settings was not returned. Confirm it in the Admin console.'],
          };
        }
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'gmail-comprehensive-storage',
          category: 'Email',
          name: 'Comprehensive Mail Storage',
          description: 'Whether a copy of all sent and received mail is stored in user mailboxes',
          severity: 'medium',
          recommendedValue: 'On',
          rationale:
            'Without it, mail sent or received through non-Gmail mailboxes can be missing from the user’s Gmail. That weakens Vault searches and makes deleted evidence harder to recover.',
          recommendation:
            'Turn comprehensive mail storage on, especially if the client uses Vault or routes mail through other systems.',
          adminConsoleUrl: gmailCompliance,
        },
        'gmail.comprehensive_mail_storage',
        (value) => {
          const ruleId = readString(value, 'ruleId');
          const states = readField(snapshot.get('gmail.rule_states').value, 'ruleStates');
          const turnedOff =
            !!ruleId &&
            Array.isArray(states) &&
            states.some((state) => {
              const entry = state as Record<string, unknown>;
              return readString(entry, 'ruleId') === ruleId && readBool(entry, 'enabled') === false;
            });
          const on = !!ruleId && !turnedOff;
          return {
            status: on ? 'pass' : 'warning',
            currentValue: on ? 'On' : 'Off',
          };
        },
        { evaluateOnMissing: true }
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'gmail-ip-allowlist',
          category: 'Email',
          name: 'Email IP Allowlist',
          description: 'IP addresses whose mail skips spam filtering',
          severity: 'medium',
          recommendedValue: 'No IP addresses listed',
          rationale:
            'Mail from an allowlisted IP address is not marked as spam. If that address range is shared or compromised, malicious mail goes straight to the inbox.',
          recommendation:
            'Leave the allowlist empty. Put inbound gateways in the inbound gateway settings instead. If a partner server must be listed, use a single address, not a CIDR range.',
          adminConsoleUrl: gmailSpam,
        },
        'gmail.email_spam_filter_ip_allowlist',
        (value) => {
          const raw = readField(value, 'allowedIpAddresses');
          const addresses = Array.isArray(raw) ? raw : [];
          return {
            status: addresses.length === 0 ? 'pass' : 'warning',
            currentValue:
              addresses.length === 0
                ? 'No IP addresses listed'
                : `${addresses.length} IP address${addresses.length === 1 ? '' : 'es'} or range${addresses.length === 1 ? '' : 's'} listed`,
          };
        },
        { defaultValue: { allowedIpAddresses: [] } }
      ),
    ];
  }

  /**
   * Problems with the approved sender lists behind a spam bypass: entries that
   * skip authentication and entries that are whole domains. The bypass rule
   * names lists by id or name; when none match, every saved list is checked.
   */
  private approvedSenderFindings(snapshot: PolicySnapshot, overrides: Record<string, unknown>[]): string[] {
    const referenced = new Set<string>();
    for (const rule of overrides) {
      for (const key of ['bypassSenderAllowlist', 'hideWarningBannerSenderAllowlist']) {
        const entries = readField(rule, key);
        if (!Array.isArray(entries)) continue;
        for (const entry of entries) {
          const text = typeof entry === 'string' ? entry : readString(entry as Record<string, unknown>, 'value');
          if (text) referenced.add(text);
        }
      }
    }

    const lists: Record<string, unknown>[] = [];
    for (const policy of snapshot.all('gmail.email_address_lists')) {
      const value = policy.setting?.value;
      const nested = readField(value, 'emailAddressList');
      if (Array.isArray(nested)) lists.push(...(nested as Record<string, unknown>[]));
      else if (value) lists.push(value);
    }
    const matched = lists.filter(
      (list) => referenced.has(readString(list, 'id') ?? '') || referenced.has(readString(list, 'name') ?? '')
    );

    const entries = (matched.length > 0 ? matched : lists).flatMap((list) => {
      const addresses = readField(readField(list, 'addressList') as Record<string, unknown>, 'address');
      return Array.isArray(addresses) ? (addresses as Record<string, unknown>[]) : [];
    });
    const unauthenticated = entries.filter((entry) => readBool(entry, 'requireAddressVerification') !== true);
    const domains = entries.filter((entry) => !(readString(entry, 'address') ?? '').includes('@'));

    const findings: string[] = [];
    if (unauthenticated.length > 0) {
      findings.push(
        `${unauthenticated.length} approved sender${unauthenticated.length === 1 ? '' : 's'} do${unauthenticated.length === 1 ? 'es' : ''} not require authentication. A spoofed message from these senders skips spam checks.`
      );
    }
    if (domains.length > 0) {
      findings.push(
        `${domains.length} approved sender${domains.length === 1 ? ' is a whole domain' : 's are whole domains'}. Use full email addresses instead.`
      );
    }
    return findings;
  }

  // --- Advanced Phishing & Malware -----------------------------------------

  private phishingMalwareChecks(snapshot: PolicySnapshot): HardeningCheck[] {
    const gmailSafety = 'https://admin.google.com/ac/apps/gmail/safety';
    const allSomeNone = (flags: (boolean | undefined)[]): HardeningCheck['status'] => {
      const on = flags.filter((f) => f === true).length;
      if (on === flags.length) return 'pass';
      if (on === 0) return 'fail';
      return 'warning';
    };

    return [
      this.policyCheck(
        snapshot,
        {
          id: 'phishing-attachments',
          category: 'Advanced Phishing & Malware',
          name: 'Attachments',
          description: 'Protection against unsafe attachments from untrusted senders',
          severity: 'critical',
          recommendedValue: 'All protections on',
          rationale:
            'Malicious attachments remain a primary malware delivery method. Google’s attachment safety controls block encrypted, scripted, and anomalous file types from untrusted senders.',
          recommendation:
            'Enable all attachment protections (encrypted attachments, scripts, anomalous types). Exceptions for known partners should be rare and time-bound.',
          adminConsoleUrl: gmailSafety,
        },
        'gmail.email_attachment_safety',
        (value) => {
          const enc = readBool(value, 'enableEncryptedAttachmentProtection');
          const scr = readBool(value, 'enableAttachmentWithScriptsProtection');
          const anom = readBool(value, 'enableAnomalousAttachmentProtection');
          return {
            status: allSomeNone([enc, scr, anom]),
            currentValue: `Encrypted: ${enc ? 'on' : 'off'}, scripts: ${scr ? 'on' : 'off'}, anomalous: ${anom ? 'on' : 'off'}`,
          };
        }
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'phishing-links',
          category: 'Advanced Phishing & Malware',
          name: 'External Links & Images',
          description: 'Protection against unsafe links and external images',
          severity: 'critical',
          recommendedValue: 'All protections on',
          rationale:
            'Credential-harvesting and malware links often hide behind shorteners or untrusted hosts. Scanning links/images and warning on untrusted URLs reduces successful phishing.',
          recommendation:
            'Enable shortener scanning, external image scanning, and aggressive warnings on untrusted links for all users.',
          adminConsoleUrl: gmailSafety,
        },
        'gmail.links_and_external_images',
        (value) => {
          const shortener = readBool(value, 'enableShortenerScanning');
          const images = readBool(value, 'enableExternalImageScanning');
          const aggressive = readBool(value, 'enableAggressiveWarningsOnUntrustedLinks');
          return {
            status: allSomeNone([shortener, images, aggressive]),
            currentValue: `Shortener scan: ${shortener ? 'on' : 'off'}, image scan: ${images ? 'on' : 'off'}, link warnings: ${aggressive ? 'on' : 'off'}`,
          };
        }
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'phishing-spoofing',
          category: 'Advanced Phishing & Malware',
          name: 'Spoofing & Authentication',
          description: 'Protection against spoofing and unauthenticated senders',
          severity: 'critical',
          recommendedValue: 'All protections on',
          rationale:
            'Domain and executive-name spoofing drive BEC (business email compromise) losses. Detecting unauthenticated and spoofed senders is essential for finance and leadership protection.',
          recommendation:
            'Enable all spoofing and authentication detections (domain, employee name, unauthenticated senders, groups). Pair with SPF/DKIM/DMARC at the DNS layer.',
          adminConsoleUrl: gmailSafety,
        },
        'gmail.spoofing_and_authentication',
        (value) => {
          const flags = [
            readBool(value, 'detectDomainNameSpoofing'),
            readBool(value, 'detectEmployeeNameSpoofing'),
            readBool(value, 'detectDomainSpoofingFromUnauthenticatedSenders'),
            readBool(value, 'detectUnauthenticatedEmails'),
            readBool(value, 'detectGroupsSpoofing'),
          ];
          const on = flags.filter((f) => f === true).length;
          return {
            status: allSomeNone(flags),
            currentValue: `${on}/${flags.length} spoofing protections on`,
          };
        }
      ),
    ];
  }

  // --- Calendar -------------------------------------------------------------

  private calendarChecks(snapshot: PolicySnapshot): HardeningCheck[] {
    const calSharing = 'https://admin.google.com/ac/apps/calendar';
    const externalSharingEval = (value: Record<string, unknown>): EvalResult => {
      const mode = readString(value, 'maxAllowedExternalSharing');
      const secure = mode === 'EXTERNAL_FREE_BUSY_ONLY';
      return {
        status: secure ? 'pass' : 'info',
        currentValue: humanEnum(mode),
      };
    };

    return [
      this.policyCheck(
        snapshot,
        {
          id: 'calendar-primary-sharing',
          category: 'Calendar',
          name: 'Primary Calendar Sharing',
          description: 'External sharing level for users’ primary calendars',
          severity: 'medium',
          recommendedValue: 'Org-dependent (free/busy is most private)',
          rationale:
            'Broad external calendar detail can reveal travel, meetings with counsel, M&A activity, or customer names. Free/busy is usually enough for external scheduling.',
          recommendation:
            'Discuss with the client: free/busy-only is the most private default. Broader sharing may be intentional for sales or support teams — document the choice rather than forcing a fail.',
          adminConsoleUrl: calSharing,
        },
        'calendar.primary_calendar_max_allowed_external_sharing',
        externalSharingEval,
        { defaultValue: { maxAllowedExternalSharing: 'EXTERNAL_FREE_BUSY_ONLY' } }
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'calendar-secondary-sharing',
          category: 'Calendar',
          name: 'Secondary Calendar Sharing',
          description: 'External sharing level for secondary calendars',
          severity: 'medium',
          recommendedValue: 'Org-dependent (free/busy is most private)',
          rationale:
            'Secondary calendars (rooms, projects, team schedules) can still leak operational detail outside the organization.',
          recommendation:
            'Align with primary calendar policy unless a specific secondary calendar type needs more openness. Prefer free/busy for external guests.',
          adminConsoleUrl: calSharing,
        },
        'calendar.secondary_calendar_max_allowed_external_sharing',
        externalSharingEval,
        { defaultValue: { maxAllowedExternalSharing: 'EXTERNAL_ALL_INFO_READ_ONLY' } }
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'calendar-external-warning',
          category: 'Calendar',
          name: 'External Invitation Warning',
          description: 'Warn users when inviting guests outside the domain',
          severity: 'low',
          recommendedValue: 'ON',
          rationale:
            'A warning when adding external guests reduces accidental invites that expose meeting titles and attachments.',
          recommendation:
            'Keep the external-guest warning ON (Google’s default). Minimal friction for a useful safeguard.',
          adminConsoleUrl: calSharing,
        },
        'calendar.external_invitations',
        (value) => {
          const warn = readBool(value, 'warnOnInvite');
          return {
            status: warn ? 'pass' : 'warning',
            currentValue: warn ? 'On' : 'Off',
          };
        },
        { defaultValue: { warnOnInvite: true } }
      ),
    ];
  }

  // --- Google Drive ---------------------------------------------------------

  private driveChecks(snapshot: PolicySnapshot): HardeningCheck[] {
    const sharing = 'https://admin.google.com/ac/appsettings/55656082996/sharing';
    const features = 'https://admin.google.com/ac/appsettings/55656082996/data';

    return [
      this.policyCheck(
        snapshot,
        {
          id: 'drive-link-sharing',
          category: 'Google Drive',
          name: 'Link Sharing (external)',
          description: 'Highest level of sharing allowed outside the organization',
          severity: 'high',
          recommendedValue: 'Off or allowlisted domains',
          rationale:
            'Open external sharing makes accidental Drive leakage easy, including “anyone with the link.” Most businesses still need to share with partners, so this is a high finding to tighten, not a critical fail by default.',
          recommendation:
            'Prefer off, or allowlisted domains, for sensitive data. Use specific people or groups when a file must leave the organization. Avoid org-wide “anyone with the link.”',
          adminConsoleUrl: sharing,
        },
        'drive_and_docs.external_sharing',
        (value) => {
          const mode = readString(value, 'externalSharingMode');
          return {
            status: mode === 'DISALLOWED' || mode === 'ALLOWLISTED_DOMAINS' ? 'pass' : 'warning',
            currentValue: humanEnum(mode),
          };
        },
        { defaultValue: EXTERNAL_SHARING_DEFAULTS }
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'drive-general-access',
          category: 'Google Drive',
          name: 'General Access Default',
          description: 'Default visibility applied to newly created items',
          severity: 'high',
          recommendedValue: 'Private to owner',
          rationale:
            'Defaulting new files to org-wide link access causes silent oversharing — people create files assuming privacy while the link is already broadly usable.',
          recommendation:
            'Set the default for new items to Private to owner. Users can still share intentionally; they should not share by accident.',
          adminConsoleUrl: sharing,
        },
        'drive_and_docs.general_access_default',
        (value) => {
          const access = readString(value, 'defaultFileAccess');
          const privateToOwner = access === 'PRIVATE_TO_OWNER' || access === 'LINK_SHARING_PRIVATE';
          return {
            status: privateToOwner ? 'pass' : 'warning',
            currentValue: humanEnum(access),
          };
        },
        { defaultValue: { defaultFileAccess: 'LINK_SHARING_PRIVATE' } }
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'drive-shared-drive-creation',
          category: 'Google Drive',
          name: 'Shared Drive Creation',
          description: 'Whether members can create new shared drives',
          severity: 'medium',
          recommendedValue: 'Restricted to admins',
          rationale:
            'Uncontrolled shared-drive sprawl creates orphaned data owners, inconsistent permissions, and harder offboarding. Admin-gated creation keeps structure intentional.',
          recommendation:
            'For most SMBs, restrict creation to admins (or a small IT/ops group). Self-service can be right for larger orgs with a naming/ownership standard — document that exception.',
          adminConsoleUrl: sharing,
        },
        'drive_and_docs.shared_drive_creation',
        (value) => {
          const allow = readBool(value, 'allowSharedDriveCreation');
          return {
            status: allow === false ? 'pass' : 'warning',
            currentValue: allow === false ? 'Admins only' : 'Users can create',
          };
        }
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'drive-sharing-suggestions',
          category: 'Google Drive',
          name: 'Sharing Suggestions',
          description: 'Access-checker suggestions when sharing files',
          severity: 'low',
          recommendedValue: 'Org-dependent tradeoff',
          rationale:
            'Access suggestions speed collaboration but can nudge users toward broader sharing than intended. Risk tolerance varies by culture and data sensitivity.',
          recommendation:
            'Discuss with the client: keep suggestions if productivity is the priority; tighten if oversharing has been a problem. No universal right answer — record the decision.',
          adminConsoleUrl: sharing,
        },
        'drive_and_docs.external_sharing',
        (value) => {
          const suggestions = readString(value, 'accessCheckerSuggestions');
          return {
            status: 'info',
            currentValue: humanEnum(suggestions),
          };
        },
        { defaultValue: { accessCheckerSuggestions: 'RECIPIENTS_OR_AUDIENCE_OR_PUBLIC' } }
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'drive-external-warning',
          category: 'Google Drive',
          name: 'External Sharing Warning',
          description: 'Warn users when they share files outside the organization',
          severity: 'medium',
          recommendedValue: 'ON',
          rationale:
            'A warning at the moment of sharing catches mistakes, such as picking the wrong person from autocomplete, before a file leaves the organization.',
          recommendation:
            'Keep the external sharing warning ON. It costs users one click and prevents accidental disclosure.',
          adminConsoleUrl: sharing,
        },
        'drive_and_docs.external_sharing',
        (value) => {
          const warn = sharingFlag(value, 'warnForExternalSharing');
          if (!warn && externalSharingOff(value)) {
            return { status: 'pass', currentValue: 'Not needed (external sharing is off)' };
          }
          return { status: warn ? 'pass' : 'warning', currentValue: warn ? 'On' : 'Off' };
        },
        { defaultValue: EXTERNAL_SHARING_DEFAULTS }
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'drive-publishing',
          category: 'Google Drive',
          name: 'Publishing Files to the Web',
          description: 'Whether users can make files visible to anyone with the link',
          severity: 'high',
          recommendedValue: 'Off',
          rationale:
            'A published file can be opened by anyone on the internet and found by search engines. Once a link spreads, the client cannot pull it back.',
          recommendation:
            'Turn publishing off. If marketing or support teams need public documents, allow it for their OU or group only.',
          adminConsoleUrl: sharing,
        },
        'drive_and_docs.external_sharing',
        (value) => {
          const allowed = sharingFlag(value, 'allowPublishingFiles');
          if (allowed && externalSharingOff(value)) {
            return { status: 'pass', currentValue: 'Not possible (external sharing is off)' };
          }
          return {
            status: allowed ? 'warning' : 'pass',
            currentValue: allowed ? 'Users can publish' : 'Publishing off',
          };
        },
        { defaultValue: EXTERNAL_SHARING_DEFAULTS }
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'drive-non-google-invites',
          category: 'Google Drive',
          name: 'Sharing with Non-Google Users',
          description: 'Whether users can share files with people who do not use a Google Account',
          severity: 'medium',
          recommendedValue: 'Off',
          rationale:
            'Visitor sharing sends a PIN to any email address. The client cannot see who controls that address or whether the account behind it is secure.',
          recommendation:
            'Turn this off unless the client works with partners who cannot use Google Accounts. If it is needed, limit it to the OU or group that works with those partners.',
          adminConsoleUrl: sharing,
        },
        'drive_and_docs.external_sharing',
        (value) => {
          const allowed = sharingFlag(value, 'allowNonGoogleInvites');
          if (allowed && externalSharingOff(value)) {
            return { status: 'pass', currentValue: 'Not possible (external sharing is off)' };
          }
          return {
            status: allowed ? 'warning' : 'pass',
            currentValue: allowed ? 'Allowed' : 'Off',
          };
        },
        { defaultValue: EXTERNAL_SHARING_DEFAULTS }
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'drive-receive-external',
          category: 'Google Drive',
          name: 'Receiving External Files',
          description: 'Whether users can receive files from outside the organization',
          severity: 'low',
          recommendedValue: 'Org-dependent',
          rationale:
            'Blocking inbound files stops outsiders from dropping unwanted or malicious files into Drive, but it also blocks normal work with partners and customers.',
          recommendation:
            'Leave this on if the client collaborates with outside parties. If it needs limits, use trust rules to accept files only from named domains or organizations.',
          adminConsoleUrl: sharing,
        },
        'drive_and_docs.external_sharing',
        (value) => {
          const allowed = sharingFlag(value, 'allowReceivingExternalFiles');
          return {
            status: 'info',
            currentValue: allowed ? 'Users can receive external files' : 'Blocked',
          };
        },
        { defaultValue: EXTERNAL_SHARING_DEFAULTS }
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'drive-shared-drive-move',
          category: 'Google Drive',
          name: 'Moving Content to Other Organizations',
          description: 'Who can move files from shared drives into another organization',
          severity: 'medium',
          recommendedValue: 'Internal users only',
          rationale:
            'Anyone allowed to upload or move content to another organization’s shared drive can copy company files out in bulk without a sharing prompt.',
          recommendation:
            'Limit this to internal users, or to no one. Allow it for specific teams only when they have a documented reason.',
          adminConsoleUrl: sharing,
        },
        'drive_and_docs.external_sharing',
        (value) => {
          const parties =
            readString(value, 'allowedPartiesForDistributingContent') ??
            (EXTERNAL_SHARING_DEFAULTS.allowedPartiesForDistributingContent as string);
          return {
            status: parties === 'ALL_ELIGIBLE_USERS' ? 'warning' : 'pass',
            currentValue: humanEnum(parties),
          };
        },
        { defaultValue: EXTERNAL_SHARING_DEFAULTS }
      ),
      this.manualCheck(
        {
          id: 'drive-offline-access',
          category: 'Google Drive',
          name: 'Offline Access',
          description: 'Whether Drive files are available offline',
          severity: 'medium',
          recommendedValue: 'Disabled (or per-OU)',
          rationale:
            'Offline copies on laptops increase data-at-rest exposure if a device is lost or stolen without strong disk encryption and MDM.',
          recommendation:
            'Disable offline access org-wide when possible. If field staff need it, enable per OU and ensure device encryption/MDM. Confirm in the Admin console.',
          adminConsoleUrl: features,
        },
        'Google does not publish this setting. Verify it in the Admin console.'
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'drive-desktop',
          category: 'Google Drive',
          name: 'Drive for Desktop',
          description: 'Whether Google Drive for desktop is allowed',
          severity: 'medium',
          recommendedValue: 'OFF (or specific users)',
          rationale:
            'Drive for desktop syncs cloud files to endpoints, which improves UX but expands the local data footprint and complicates offboarding/lost-device scenarios.',
          recommendation:
            'Default OFF for highly sensitive environments. Where hybrid work requires it, allow for approved OUs only and require encrypted, managed devices.',
          adminConsoleUrl: features,
        },
        'drive_and_docs.drive_for_desktop',
        (value) => {
          const allow = readBool(value, 'allowDriveForDesktop');
          return {
            status: allow === false ? 'pass' : 'warning',
            currentValue: allow === false ? 'Off' : 'Allowed',
          };
        }
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'drive-addons',
          category: 'Google Drive',
          name: 'Docs/Sheets Add-ons',
          description: 'Whether Editor add-ons are allowed',
          severity: 'medium',
          recommendedValue: 'OFF (deploy approved add-ons)',
          rationale:
            'Marketplace add-ons receive document access and can become a supply-chain or data-exfiltration path if users install freely.',
          recommendation:
            'Block open add-on installs. Deploy only add-ons that have been reviewed.',
          adminConsoleUrl: 'https://admin.google.com/ac/apps/editors',
        },
        'workspace_marketplace.apps_access_options',
        (value) => {
          const level = readString(value, 'accessLevel');
          const limited = level === 'ALLOW_NONE' || level === 'ALLOW_LISTED_APPS';
          const label =
            level === 'ALLOW_NONE'
              ? 'No Marketplace apps'
              : level === 'ALLOW_LISTED_APPS'
                ? 'Allowlist only'
                : level === 'ALLOW_ALL'
                  ? 'All Marketplace apps'
                  : humanEnum(level);
          return {
            status: limited ? 'pass' : level === 'ALLOW_ALL' ? 'warning' : 'manual',
            currentValue: label,
          };
        }
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'drive-dlp',
          category: 'Google Drive',
          name: 'DLP (Enterprise)',
          description: 'Data Loss Prevention rules for Drive/Gmail',
          severity: 'high',
          recommendedValue: 'Rules configured when licensed',
          rationale:
            'DLP detects and can block sensitive data (SSN, cards, health identifiers) leaving via Drive or Gmail — critical for regulated or high-value IP clients.',
          recommendation:
            'If the SKU includes data protection, configure block/report rules for high-risk detectors. If not licensed, waive with reason “SKU — not applicable” rather than treating as a security failure.',
          adminConsoleUrl: 'https://admin.google.com/ac/dp',
        },
        'rule.dlp',
        (_value, lookup) => {
          const count = snapshot.all('rule.dlp').length || (lookup.found ? 1 : 0);
          if (count > 0) {
            return { status: 'pass', currentValue: `${count} data protection rule(s)` };
          }
          return {
            status: 'manual',
            currentValue: 'None configured',
            issues: [
              'Enterprise / add-on feature. Configure DLP if licensed; otherwise document as not applicable.',
            ],
          };
        },
        { evaluateOnMissing: true }
      ),
    ];
  }

  // --- Groups ---------------------------------------------------------------

  private groupsChecks(snapshot: PolicySnapshot): HardeningCheck[] {
    const groupsSettings = 'https://admin.google.com/ac/apps/groups';
    const defaults = {
      collaborationCapability: 'DOMAIN_USERS_ONLY',
      createGroupsAccessLevel: 'USERS_IN_DOMAIN',
      ownersCanAllowExternalMembers: false,
      ownersCanAllowIncomingMailFromPublic: true,
    };

    return [
      this.policyCheck(
        snapshot,
        {
          id: 'groups-creation',
          category: 'Groups',
          name: 'Who Can Create Groups',
          description: 'Which users can create new Google Groups',
          severity: 'medium',
          recommendedValue: 'Admins only',
          rationale:
            'Groups often control access to files, shared drives, and apps. When anyone can create one, the client ends up with groups nobody reviews and access nobody can explain.',
          recommendation:
            'Limit group creation to admins. For larger teams, let a small IT or operations group create groups through a request process.',
          adminConsoleUrl: groupsSettings,
        },
        'groups_for_business.groups_sharing',
        (value) => {
          const level =
            readString(value, 'createGroupsAccessLevel') ?? defaults.createGroupsAccessLevel;
          const label =
            level === 'ADMIN_ONLY'
              ? 'Admins only'
              : level === 'USERS_IN_DOMAIN'
                ? 'Anyone in the organization'
                : level === 'ANYONE_CAN_CREATE'
                  ? 'Anyone, including outsiders'
                  : level;
          return { status: level === 'ADMIN_ONLY' ? 'pass' : 'warning', currentValue: label };
        },
        { defaultValue: defaults }
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'groups-external-access',
          category: 'Groups',
          name: 'External Access to Groups',
          description: 'Whether groups can include outside members or accept mail from the public',
          severity: 'medium',
          recommendedValue: 'Organization only, owners cannot open groups to outsiders',
          rationale:
            'Internal groups that accept outside members or public mail leak conversations and can let outsiders reach internal distribution lists. Public posting also gives attackers a spam and phishing path.',
          recommendation:
            'Limit group access to the organization and stop group owners from adding external members or accepting public mail. Allow exceptions for specific groups, such as a support alias, and keep them separate from internal groups.',
          adminConsoleUrl: groupsSettings,
        },
        'groups_for_business.groups_sharing',
        (value) => {
          const capability =
            readString(value, 'collaborationCapability') ?? defaults.collaborationCapability;
          const externalMembers =
            readBool(value, 'ownersCanAllowExternalMembers') ?? defaults.ownersCanAllowExternalMembers;
          const publicMail =
            readBool(value, 'ownersCanAllowIncomingMailFromPublic') ??
            defaults.ownersCanAllowIncomingMailFromPublic;
          const domainOnly = capability === 'DOMAIN_USERS_ONLY';
          const issues: string[] = [];
          if (!domainOnly) issues.push('Groups can be opened to people outside the organization.');
          if (externalMembers) issues.push('Group owners can add external members.');
          if (publicMail) issues.push('Group owners can allow incoming mail from the public.');
          return {
            status: issues.length === 0 ? 'pass' : 'warning',
            currentValue: [
              `Access: ${domainOnly ? 'organization only' : 'anyone can access'}`,
              `external members: ${externalMembers ? 'allowed' : 'blocked'}`,
              `public mail: ${publicMail ? 'allowed' : 'blocked'}`,
            ].join(', '),
            issues: issues.length ? issues : undefined,
          };
        },
        { defaultValue: defaults }
      ),
    ];
  }

  // --- Chat -----------------------------------------------------------------

  private chatChecks(snapshot: PolicySnapshot): HardeningCheck[] {
    return [
      this.policyCheck(
        snapshot,
        {
          id: 'chat-external',
          category: 'Chat',
          name: 'External Chat',
          description: 'Whether users can chat with people outside the organization',
          severity: 'medium',
          recommendedValue: 'Off, or limited to trusted domains',
          rationale:
            'Open external chat gives phishers and scammers a direct line to staff, and it is an easy way to move files and data out of the organization.',
          recommendation:
            'Turn external chat off, or limit it to trusted domains for the partners the client works with. Allow unrestricted external chat only for teams that need it.',
          adminConsoleUrl: 'https://admin.google.com/ac/apps/chat',
        },
        'chat.external_chat_restriction',
        (value) => {
          const allowed = readBool(value, 'allowExternalChat') ?? false;
          const restriction = readString(value, 'externalChatRestriction') ?? 'NO_RESTRICTION';
          if (!allowed) return { status: 'pass', currentValue: 'External chat off' };
          if (restriction === 'TRUSTED_DOMAINS') {
            return { status: 'pass', currentValue: 'Limited to trusted domains' };
          }
          return { status: 'warning', currentValue: 'Unrestricted external chat' };
        },
        { defaultValue: { allowExternalChat: false, externalChatRestriction: 'NO_RESTRICTION' } }
      ),
    ];
  }

  // --- Login challenges -----------------------------------------------------

  private loginChallengeChecks(snapshot: PolicySnapshot): HardeningCheck[] {
    return [
      this.policyCheck(
        snapshot,
        {
          id: 'login-challenges',
          category: 'Login Challenges',
          name: 'Additional Verification',
          description: 'Employee ID login challenge for extra verification',
          severity: 'low',
          recommendedValue: 'Optional (employee ID / recovery email)',
          rationale:
            'Extra login challenges slow account recovery abuse. Value depends on whether the org maintains accurate employee IDs and recovery emails.',
          recommendation:
            'Enable employee-ID or recovery-email challenges if HR data is accurate. Optional for many SMBs — record the decision; off is valid when 2SV is strong.',
          adminConsoleUrl: 'https://admin.google.com/ac/security/lc',
        },
        'security.login_challenges',
        (value) => {
          const enabled = readBool(value, 'enableEmployeeIdChallenge');
          return {
            status: enabled ? 'pass' : 'info',
            currentValue: enabled ? 'Employee ID challenge on' : 'Not configured',
          };
        }
      ),
      this.manualCheck(
        {
          id: 'login-post-sso',
          category: 'Login Challenges',
          name: 'Post-SSO Verification',
          description: 'Extra verification for high-risk apps when SSO is enabled',
          severity: 'high',
          recommendedValue: 'Enabled when SSO is in use',
          rationale:
            'SSO consolidates access: if the IdP session is weak or stolen, high-risk Google apps need an additional check. Post-SSO verification closes that gap.',
          recommendation:
            'If the client uses SSO, enable post-SSO verification for high-risk apps. If no SSO, mark not applicable. Confirm in the Admin console.',
          adminConsoleUrl: 'https://admin.google.com/ac/security/sso',
        },
        'Google does not publish this setting. Verify it in the Admin console.'
      ),
    ];
  }

  // --- Data Download --------------------------------------------------------

  private dataDownloadChecks(snapshot: PolicySnapshot): HardeningCheck[] {
    return [
      this.policyCheck(
        snapshot,
        {
          id: 'google-takeout',
          category: 'Data Download',
          name: 'Google Takeout',
          description: 'Whether users can export data via Google Takeout',
          severity: 'high',
          recommendedValue: 'OFF (allow per-OU as needed)',
          rationale:
            'Takeout lets users bulk-export mail, Drive, and more. Useful for offboarding/legal, but dangerous if every user can self-serve large extracts — especially after compromise or insider risk.',
          recommendation:
            'Disable Takeout for general users. Enable only for approved OUs/groups (HR/legal/offboarding) with a request process.',
          adminConsoleUrl: 'https://admin.google.com/ac/googletakeout/useraccess',
        },
        'takeout.service_status',
        (value) => {
          const state = readString(value, 'serviceState');
          let enabled: boolean | undefined;
          if (state) {
            enabled = state.toUpperCase().includes('ENABLED') || state.toUpperCase() === 'ON';
          } else {
            enabled = readBool(value, 'serviceStatus', 'enabled', 'enableService');
          }
          if (enabled === undefined) {
            return {
              status: 'manual',
              currentValue: 'Unknown',
              issues: ['Could not parse service status — verify in Admin console.'],
            };
          }
          return {
            status: enabled ? 'warning' : 'pass',
            currentValue: enabled ? 'Enabled for all' : 'Disabled',
          };
        }
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'less-secure-apps',
          category: 'Data Download',
          name: 'Less Secure Apps',
          description: 'Access for apps using less secure sign-in technology',
          severity: 'low',
          recommendedValue: 'Disabled',
          rationale:
            'Less secure apps use password-only sign-in that bypasses OAuth and 2SV. Google turned off less secure app access for Workspace accounts in 2024, so this setting rarely has an effect now. Google’s checklist still lists it, so the audit keeps it.',
          recommendation:
            'Disable for all users. Migrate any remaining integrations to OAuth or service accounts. Temporary exceptions should be time-boxed and tracked as waivers.',
          adminConsoleUrl: 'https://admin.google.com/ac/security/lsa',
        },
        'security.less_secure_apps',
        (value) => {
          const allow = readBool(value, 'allowLessSecureApps');
          return {
            status: allow === false ? 'pass' : allow === true ? 'fail' : 'manual',
            currentValue: allow === false ? 'Disabled' : allow === true ? 'Allowed' : 'Unknown',
          };
        },
        { defaultValue: { allowLessSecureApps: false } }
      ),
    ];
  }

  // --- Apps Control ---------------------------------------------------------

  private appsControlChecks(snapshot: PolicySnapshot): HardeningCheck[] {
    const rows = snapshot.settingTypes()
      .filter((type) => type.endsWith('.service_status'))
      .map((type) => {
        const id = type.slice(0, -'.service_status'.length);
        const lookup = snapshot.get(type);
        return {
          id,
          name: serviceLabel(id),
          core: id in CORE_SERVICE_NAMES,
          enabled: serviceEnabled(lookup.value),
        };
      })
      .filter((row) => row.id !== 'takeout');

    const core = rows.filter((row) => row.core);
    const extra = rows.filter((row) => !row.core);
    const expectedCore = new Set(['gmail', 'drive_and_docs', 'calendar']);

    return [
      this.manualCheck(
        {
          id: 'context-aware-access',
          category: 'Apps Control',
          name: 'Context-Aware Access',
          description: 'Access control based on device/context (Enterprise)',
          severity: 'high',
          recommendedValue: 'Configured when licensed',
          rationale:
            'Context-Aware Access gates apps by device posture, IP, and identity context — stopping access from unmanaged or high-risk environments.',
          recommendation:
            'If Enterprise-licensed, define levels for sensitive apps (Admin console, finance systems). If not licensed, waive as “SKU — not applicable.”',
          adminConsoleUrl: 'https://admin.google.com/ac/security/caa',
        },
        'Enterprise-only and context-specific — verify in Admin console.'
      ),
      this.policyCheck(
        snapshot,
        {
          id: 'third-party-apps',
          category: 'Apps Control',
          name: 'Unconfigured Third-Party Apps',
          description: 'Access level for third-party apps the organization has not configured',
          severity: 'high',
          recommendedValue: 'Block all, or sign-in only',
          rationale:
            'Any third-party app a user approves can read mail, files, and contacts with that user’s access. Attackers use fake apps to harvest data without ever stealing a password.',
          recommendation:
            'Set unconfigured apps to blocked, or to sign-in only if the client uses Sign in with Google. Review requests and trust the apps the business needs one by one.',
          adminConsoleUrl: 'https://admin.google.com/ac/owl',
        },
        'api_controls.unconfigured_third_party_apps',
        (value) => {
          const level = readString(value, 'accessLevel') ?? 'ACCESS_LEVEL_UNSPECIFIED';
          if (level === 'BLOCK_ALL') return { status: 'pass', currentValue: 'Blocked' };
          if (level === 'ALLOW_SIGN_IN_ONLY') return { status: 'pass', currentValue: 'Sign-in only' };
          return { status: 'warning', currentValue: 'All access allowed' };
        },
        { defaultValue: { accessLevel: 'ACCESS_LEVEL_UNSPECIFIED' } }
      ),
      this.serviceCatalogCheck(
        {
          id: 'core-apps',
          category: 'Apps Control',
          name: 'Core Apps',
          description: 'Access to core Workspace services per OU/group',
          severity: 'medium',
          recommendedValue: 'Off where not needed',
          rationale:
            'Every enabled app expands the attack and data surface. Contractors, kiosks, and limited-role staff often need only a subset of Workspace.',
          recommendation:
            'Turn off core apps (Drive, Gmail, Meet, etc.) for OUs that should not have them. Document the service catalog with the client.',
          adminConsoleUrl: 'https://admin.google.com/ac/appslist/core',
        },
        snapshot,
        core,
        (listed) => listed.some((row) => expectedCore.has(row.id) && row.enabled === false),
        'info'
      ),
      this.serviceCatalogCheck(
        {
          id: 'additional-apps',
          category: 'Apps Control',
          name: 'Additional Apps',
          description: 'Access to additional Google services per OU/group',
          severity: 'medium',
          recommendedValue: 'Off where not needed',
          rationale:
            'Consumer-oriented Google services (Blogger, Ads, etc.) are rarely required for business tenants and create shadow IT and data-storage surprises.',
          recommendation:
            'Disable additional Google services org-wide unless a specific OU has an approved need. Review annually with the client.',
          adminConsoleUrl: 'https://admin.google.com/ac/appslist/additional',
        },
        snapshot,
        extra,
        (listed) => listed.some((row) => row.enabled === true),
        'pass'
      ),
    ];
  }

  private serviceCatalogCheck(
    meta: CheckMeta,
    snapshot: PolicySnapshot,
    rows: Array<{ id: string; name: string; enabled: boolean | undefined }>,
    isFinding: (rows: Array<{ id: string; name: string; enabled: boolean | undefined }>) => boolean,
    quietStatus: 'info' | 'pass'
  ): HardeningCheck {
    const base = this.baseFrom(meta);
    if (!snapshot.available) {
      return {
        ...base,
        status: 'manual',
        source: 'manual',
        currentValue: 'Manual review',
        issues: [
          'Automated read unavailable — verify this setting in the Admin console until Policy API access is restored.',
        ],
      };
    }
    if (rows.length === 0) {
      return {
        ...base,
        status: 'info',
        source: 'auto',
        currentValue: 'No explicit service changes',
        issues: ['No saved on/off policy for these services. Google defaults apply.'],
      };
    }
    const on = rows.filter((row) => row.enabled === true);
    const off = rows.filter((row) => row.enabled === false);
    const unknown = rows.filter((row) => row.enabled === undefined);
    const parts = [
      on.length ? `On: ${joinNames(on.map((row) => row.name))}` : '',
      off.length ? `Off: ${joinNames(off.map((row) => row.name))}` : '',
      unknown.length ? `Unparsed: ${joinNames(unknown.map((row) => row.name))}` : '',
    ].filter(Boolean);
    return {
      ...base,
      status: isFinding(rows) || unknown.length > 0 ? 'warning' : quietStatus,
      source: 'auto',
      currentValue: parts.join('. '),
    };
  }

  private adminAlertCheck(snapshot: PolicySnapshot): HardeningCheck {
    const meta: CheckMeta = {
      id: 'chrome-admin-alerts',
      category: 'Alerts',
      name: 'Admin Alerts',
      description: 'Alerting for sensitive admin changes',
      severity: 'high',
      recommendedValue: 'Alerts on',
      rationale:
        'Admin password resets and new super admins are high-impact events. Without alerts, compromise of an admin account can go unnoticed.',
      recommendation:
        'Turn on alert rules for admin password resets, new admin assignments, and other sensitive actions. Route to a monitored MSP/client mailbox.',
      adminConsoleUrl: 'https://admin.google.com/ac/reporting/rules',
    };
    const base = this.baseFrom(meta);
    if (!snapshot.available) {
      return {
        ...base,
        status: 'manual',
        source: 'manual',
        currentValue: 'Manual review',
        issues: [
          'Automated read unavailable — verify this setting in the Admin console until Policy API access is restored.',
        ],
      };
    }

    const rules = snapshot.all('rule.system_defined_alerts').map((policy) => {
      const value = policy.setting?.value ?? {};
      const name = readString(value, 'displayName') || 'Unnamed alert';
      const state = (readString(value, 'state') || '').toUpperCase();
      const action = readField(value, 'action');
      let center = '';
      if (action && typeof action === 'object') {
        const config = readField(action as Record<string, unknown>, 'alertCenterConfig');
        if (config && typeof config === 'object') {
          center = (readString(config as Record<string, unknown>, 'status') || '').toUpperCase();
        }
      }
      const active = state === 'ACTIVE' && (center === '' || center === 'ENABLED');
      return { name, active };
    });

    if (rules.length === 0) {
      return {
        ...base,
        status: 'manual',
        source: 'manual',
        currentValue: 'None returned',
        issues: ['No system alert rules were returned. Confirm the alert center in the Admin console.'],
      };
    }

    const active = rules.filter((rule) => rule.active);
    const adminRelated = active.filter((rule) => /admin|password|privilege|super/i.test(rule.name));
    return {
      ...base,
      status: adminRelated.length > 0 ? 'pass' : active.length > 0 ? 'warning' : 'fail',
      source: 'auto',
      currentValue: `${active.length} active, ${rules.length - active.length} inactive`,
      issues:
        adminRelated.length > 0
          ? undefined
          : ['No active rule is named for admin, password, or privilege changes. Confirm those alerts in the alert center.'],
    };
  }

  private dnsCheckToHardening(record: DNSRecord, primaryDomain: string, multiDomain: boolean): HardeningCheck {
    const severity: Severity = record.type === 'MX' ? 'high' : 'critical';
    const rationaleByType: Record<string, string> = {
      SPF: 'SPF tells receiving servers which hosts may send mail for your domain. Without it (or with a soft fail), spoofed mail from your domain is far easier.',
      DKIM:
        'DKIM cryptographically signs outbound mail so receivers can detect tampering and trust your domain’s messages.',
      DMARC:
        'DMARC ties SPF/DKIM together and tells receivers what to do with failures. Without enforcement, spoofed CEO/finance mail remains easy.',
      MX: 'MX records decide where inbound mail goes. If they do not point to Google, the Gmail filtering and DLP controls in this checklist never see the mail.',
    };
    const recommendedByType: Record<string, string> = {
      SPF: 'One record ending in -all',
      DKIM: '2048-bit key published',
      DMARC: 'p=quarantine or p=reject',
      MX: 'Google MX at top priority',
    };
    const recByType: Record<string, string> = {
      SPF: 'Publish a single SPF record covering all legitimate senders and end with -all (hard fail). Avoid +all or overly broad includes.',
      DKIM:
        'Enable Google DKIM in Admin console and publish the TXT record. Prefer 2048-bit keys when the DNS provider allows it.',
      DMARC:
        'Start with p=none + reporting if needed, then move to p=quarantine or p=reject once legitimate mail paths are clean. BEC-prone orgs should not stay on p=none long-term.',
      MX: 'Point the domain’s MX records at Google (smtp.google.com at priority 1).',
    };

    // Soft issues from DNS lookup failures shouldn't look like raw stack traces
    const issues = (record.issues || []).map((i) =>
      /DNS lookup failed/i.test(i)
        ? `DNS lookup could not complete for ${record.type}. Confirm public DNS resolution from this environment.`
        : i
    );
    if (record.record && record.status !== 'pass') issues.push(`Record: ${record.record}`);

    const kind = record.type.toLowerCase();
    const slug = record.domain.replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    const label = `${record.type} Record`;
    return {
      id: record.domain === primaryDomain ? `dns-${kind}` : `dns-${kind}-${slug}`,
      category: 'Email',
      name: multiDomain ? `${label} (${record.domain})` : label,
      description:
        record.type === 'MX' ? 'Inbound mail routing to Google' : `${record.type} email authentication record`,
      status: record.status,
      source: 'auto',
      severity,
      currentValue: record.currentValue,
      recommendedValue: recommendedByType[record.type],
      rationale: rationaleByType[record.type] || `${record.type} email authentication`,
      recommendation: record.recommendation || recByType[record.type] || '',
      issues: issues.length ? issues : undefined,
    };
  }

  // --- Orchestration --------------------------------------------------------

  /**
   * Probe Cloud Identity Policy API (with retries inside policyService).
   * Call this before a full run so transient 429s can abort without writing a
   * degraded snapshot.
   */
  async preflightPolicyApi(userEmail: string): Promise<{
    snapshot: PolicySnapshot;
    policyApi: PolicyApiMeta;
  }> {
    const snapshot = await policyService.loadOrgPolicies(userEmail);
    return { snapshot, policyApi: policyApiMetaFromSnapshot(snapshot) };
  }

  async runAllChecks(
    userEmail: string,
    domain: string,
    /** Reuse a snapshot from preflight to avoid a second Policy list. */
    preloadedSnapshot?: PolicySnapshot
  ): Promise<{
    checks: HardeningCheck[];
    statistics: HardeningStatistics;
    policyApi: PolicyApiMeta;
  }> {
    const checks: HardeningCheck[] = [];

    // Load org policies once (super-admin subject, keyless DWD). Never throws.
    const snapshot =
      preloadedSnapshot ?? (await policyService.loadOrgPolicies(userEmail));
    const policyApi = policyApiMetaFromSnapshot(snapshot);
    // Note: we intentionally do NOT inject a synthetic "Policy API 403" checklist
    // row. Unavailability is returned as policyApi meta for a UI banner; individual
    // policy-backed checks degrade to manual with stable copy.

    // Administrator Accounts and Authentication
    const [superAdminCount, adminTwoSv, twoSvEnforcement] = await Promise.all([
      this.checkSuperAdminCount(userEmail),
      this.checkAdminTwoSv(userEmail),
      this.check2FAEnforcement(userEmail, snapshot),
    ]);
    checks.push(superAdminCount, adminTwoSv);
    checks.push(...this.administratorAccountPolicyChecks(snapshot));
    checks.push(twoSvEnforcement);
    checks.push(...this.authenticationChecks(snapshot));

    // Email: DNS (SPF/DKIM/DMARC/MX)
    const dnsDomains = domainsToCheck(domain);
    if (dnsDomains.length > 0) {
      try {
        const primaryDomain = dnsDomains[0];
        const perDomain = await Promise.all(dnsDomains.map((d) => dnsCheckService.checkAllDNS(d)));
        perDomain.flat().forEach((record) => {
          checks.push(this.dnsCheckToHardening(record, primaryDomain, dnsDomains.length > 1));
        });
      } catch (error: unknown) {
        checks.push({
          id: 'dns-check-error',
          category: 'Email',
          name: 'DNS Checks',
          description: 'DNS record validation for SPF, DKIM, DMARC, and MX',
          status: 'warning',
          source: 'auto',
          severity: 'critical',
          currentValue: 'Unable to check',
          recommendedValue: 'Configured and enforcing',
          rationale:
            'Without SPF, DKIM, and DMARC, attackers can more easily spoof the client’s domain in phishing and BEC campaigns.',
          recommendation:
            'Re-run the audit when DNS is reachable, or verify SPF/DKIM/DMARC records manually in the client’s DNS host.',
          issues: [humanizeApiFailure(error, 'DNS checks')],
        });
      }
    }

    // Email — Gmail policy checks
    checks.push(...this.emailChecks(snapshot));

    // Advanced Phishing & Malware
    checks.push(...this.phishingMalwareChecks(snapshot));

    // Calendar
    checks.push(...this.calendarChecks(snapshot));

    // Groups and Chat
    checks.push(...this.groupsChecks(snapshot));
    checks.push(...this.chatChecks(snapshot));

    // Google Drive
    checks.push(...this.driveChecks(snapshot));

    // Chrome managed browsers
    try {
      const chromeChecks = await chromePolicyService.getAllPolicyChecks(userEmail, snapshot.rootOrgUnitId);
      chromeChecks.forEach((chromeCheck) => {
        checks.push({
          ...chromeCheck,
          description: chromeCheck.name,
          source: chromeCheck.status === 'manual' ? 'manual' : 'auto',
        });
      });
    } catch (error: unknown) {
      checks.push({
        id: 'chrome-policy-api',
        category: 'Chrome Browser',
        name: 'Chrome Policy API',
        description: 'Ability to read Chrome browser policies',
        status: 'warning',
        source: 'auto',
        severity: 'medium',
        currentValue: 'Unavailable',
        recommendedValue: 'API enabled for audits',
        rationale:
          'Without Chrome Policy API access the audit cannot confirm Safe Browsing, download, and update settings for Chrome.',
        recommendation:
          'Enable chromepolicy.googleapis.com and grant the chrome.management.policy.readonly DWD scope, then re-run the audit.',
        issues: [
          error instanceof ChromePolicyApiError ? error.message : humanizeApiFailure(error, 'Chrome Policy API'),
        ],
      });
    }

    checks.push(this.adminAlertCheck(snapshot));

    // Login challenges
    checks.push(...this.loginChallengeChecks(snapshot));

    // Data Download
    checks.push(...this.dataDownloadChecks(snapshot));

    // Apps Control
    checks.push(...this.appsControlChecks(snapshot));

    const statistics: HardeningStatistics = {
      total: checks.length,
      pass: checks.filter((c) => c.status === 'pass').length,
      warning: checks.filter((c) => c.status === 'warning').length,
      fail: checks.filter((c) => c.status === 'fail').length,
      manual: checks.filter((c) => c.status === 'manual').length,
      info: checks.filter((c) => c.status === 'info').length,
      score: computeHardeningScore(checks),
    };

    return { checks, statistics, policyApi };
  }
}

export const hardeningService = new HardeningService();
