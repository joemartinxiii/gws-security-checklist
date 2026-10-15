import { WorkspaceService } from './workspace.service';
import type { Severity } from './securityAuditStore';

export interface ChromePolicyCheck {
  id: string;
  name: string;
  category: string;
  severity: Severity;
  status: 'pass' | 'warning' | 'fail' | 'manual';
  currentValue: string;
  recommendedValue: string;
  rationale: string;
  recommendation: string;
  adminConsoleUrl: string;
  issues?: string[];
}

/** Thrown when the Chrome Policy API itself fails. The message already names the likely cause. */
export class ChromePolicyApiError extends Error {}

type Fields = Record<string, unknown>;

interface Evaluation {
  status: 'pass' | 'warning' | 'fail';
  currentValue: string;
  issues?: string[];
}

interface PolicySpec {
  id: string;
  name: string;
  severity: Severity;
  /** Candidate Policy API schema names, preferred first. The first one that exists and resolves wins. */
  schemas: string[];
  recommendedValue: string;
  rationale: string;
  recommendation: string;
  /** `null` means the policy is not set at the org unit, so Chrome's default applies. */
  evaluate: (value: Fields | null) => Evaluation;
}

const CATEGORY = 'Chrome Browser';
const ADMIN_CONSOLE_URL = 'https://admin.google.com/ac/chrome/settings/user';
const SCHEMA_NAMESPACE_FILTER = 'name=chrome.users';
const SCHEMA_PAGE_SIZE = 1000;
const RESOLVE_PAGE_SIZE = 100;
const MAX_PAGES = 10;

/** Case-insensitive field lookup, so a casing change in the API does not read as "unset". */
function field(value: Fields, name: string): unknown {
  const key = Object.keys(value).find((k) => k.toLowerCase() === name.toLowerCase());
  return key === undefined ? undefined : value[key];
}

function enumField(value: Fields, name: string): string | undefined {
  const raw = field(value, name);
  return typeof raw === 'string' && raw ? raw.toUpperCase() : undefined;
}

/** Proto JSON drops false, so a missing bool on a set policy reads as false. */
function boolField(value: Fields, name: string): boolean {
  return field(value, name) === true;
}

function listField(value: Fields, name: string): string[] {
  const raw = field(value, name);
  const items = Array.isArray(raw) ? raw : typeof raw === 'string' ? raw.split(',') : [];
  return items.map((i) => String(i).trim()).filter(Boolean);
}

function overridable(value: Fields, name: string): boolean {
  return enumField(value, name) === 'RECOMMENDED';
}

function unrecognized(what: string, raw: string | undefined): Evaluation {
  return {
    status: 'warning',
    currentValue: `Unrecognized value${raw ? ` (${raw})` : ''}`,
    issues: [`Chrome returned a ${what} value this audit does not recognize. Review the setting in the Admin console.`],
  };
}

/**
 * Schema and field names match what customers.policySchemas.list returns for
 * the chrome.users namespace. The audit still confirms each schema exists for
 * the tenant before it resolves anything.
 */
const POLICIES: PolicySpec[] = [
  {
    id: 'chrome-relaunch-notification',
    name: 'Relaunch Notification',
    severity: 'medium',
    schemas: [
      'chrome.users.RelaunchNotificationWithDurationV2',
      'chrome.users.RelaunchNotificationWithDuration',
    ],
    recommendedValue: 'Force relaunch after a period',
    rationale:
      'Chrome applies a security update only after the browser restarts. Users who never restart stay on a vulnerable version for weeks.',
    recommendation:
      'Set Relaunch notification to force a relaunch after a period, so Chrome restarts itself after the notice window. A notice period of a few days is a common starting point.',
    evaluate: (value) => {
      if (!value) {
        return {
          status: 'fail',
          currentValue: 'Not set (Chrome default: no relaunch notice)',
          issues: ['Without a relaunch policy, Chrome only shows a menu indicator and users can postpone updates indefinitely.'],
        };
      }
      const mode = enumField(value, 'relaunchNotificationEnum');
      if (mode === 'REQUIRED') return { status: 'pass', currentValue: 'Force relaunch after a period' };
      if (mode === 'RECOMMENDED') {
        return {
          status: 'warning',
          currentValue: 'Recommend relaunch only',
          issues: ['Users can dismiss the notice and keep the old version. Use "Force relaunch after a period".'],
        };
      }
      if (mode === 'NO_NOTIFICATION' || mode === undefined) {
        return { status: 'fail', currentValue: 'No relaunch notification' };
      }
      return unrecognized('relaunch notification', mode);
    },
  },
  {
    id: 'chrome-safe-browsing',
    name: 'Safe Browsing Protection',
    severity: 'high',
    schemas: ['chrome.users.SafeBrowsingProtectionLevel'],
    recommendedValue: 'Standard or Enhanced, users cannot override',
    rationale:
      'Safe Browsing blocks known phishing and malware sites. If users can turn it off, one click removes the protection.',
    recommendation:
      'Set Safe Browsing protection to Standard or Enhanced and do not allow users to override it. Enhanced shares more browsing data with Google, so confirm that with the client first.',
    evaluate: (value) => {
      if (!value) {
        return {
          status: 'warning',
          currentValue: 'Not set (Chrome default: standard protection, users can turn it off)',
          issues: ['Standard protection is on by default, but users can switch it off. Enforce it so they cannot.'],
        };
      }
      const level = enumField(value, 'safeBrowsingProtectionLevel');
      const label = level === 'ENHANCED_PROTECTION' ? 'Enhanced' : 'Standard';
      if (level === 'STANDARD_PROTECTION' || level === 'ENHANCED_PROTECTION') {
        if (overridable(value, 'safeBrowsingProtectionLevelCategoryItemPolicyMode')) {
          return {
            status: 'warning',
            currentValue: `${label} protection, users can override`,
            issues: ['The setting is a recommendation. Users can still turn Safe Browsing off.'],
          };
        }
        return { status: 'pass', currentValue: `${label} protection, enforced` };
      }
      if (level === 'NO_PROTECTION') {
        return {
          status: 'fail',
          currentValue: 'Safe Browsing is off',
          issues: ['Safe Browsing is never active for this org unit.'],
        };
      }
      if (level === 'USER_CHOICE' || level === undefined) {
        return {
          status: 'warning',
          currentValue: 'User choice',
          issues: ['Users decide whether Safe Browsing runs. Set it to Standard or Enhanced.'],
        };
      }
      return unrecognized('Safe Browsing', level);
    },
  },
  {
    id: 'chrome-safe-browsing-bypass',
    name: 'Safe Browsing Warning Bypass',
    severity: 'high',
    schemas: ['chrome.users.DisableSafeBrowsingProceedAnyway'],
    recommendedValue: 'Users cannot bypass warnings',
    rationale:
      'When users can click through a Safe Browsing warning, a phishing or malware page is one click away.',
    recommendation:
      'Turn on "Disable bypassing Safe Browsing warnings". If a trusted site is flagged by mistake, add it to the Safe Browsing allowed domains instead of letting everyone bypass warnings.',
    evaluate: (value) => {
      if (!value) {
        return {
          status: 'fail',
          currentValue: 'Not set (Chrome default: users can bypass warnings)',
          issues: ['Users can proceed past phishing and malware warnings.'],
        };
      }
      return boolField(value, 'disableSafeBrowsingProceedAnyway')
        ? { status: 'pass', currentValue: 'Users cannot bypass warnings' }
        : {
            status: 'fail',
            currentValue: 'Users can bypass warnings',
            issues: ['Users can proceed past phishing and malware warnings.'],
          };
    },
  },
  {
    id: 'chrome-password-manager',
    name: 'Password Manager',
    severity: 'low',
    schemas: ['chrome.users.PasswordManager'],
    recommendedValue: 'Allowed',
    rationale:
      'A built-in password manager gives users a safer option than reusing passwords or keeping them in notes. Chrome allows it by default.',
    recommendation:
      'Leave the Chrome password manager allowed. If the client standardizes on another password manager and blocks this one on purpose, waive this check with that reason.',
    evaluate: (value) => {
      if (!value) return { status: 'pass', currentValue: 'Allowed (Chrome default)' };
      const enabled = enumField(value, 'passwordManagerEnabled');
      if (enabled === 'FALSE') {
        return {
          status: 'fail',
          currentValue: 'Never allowed',
          issues: ['The Chrome password manager is blocked for this org unit.'],
        };
      }
      if (enabled === 'TRUE') return { status: 'pass', currentValue: 'Always allowed' };
      if (enabled === 'UNSET' || enabled === undefined) {
        return { status: 'pass', currentValue: 'Allowed (users decide)' };
      }
      return unrecognized('password manager', enabled);
    },
  },
  {
    id: 'chrome-download-restrictions',
    name: 'Download Restrictions',
    severity: 'high',
    schemas: ['chrome.users.DownloadRestrictions'],
    recommendedValue: 'Block malicious downloads',
    rationale:
      'Without download restrictions, users can save and open files that Safe Browsing already flags as malicious.',
    recommendation:
      'Set Download restrictions to "Block malicious downloads". The stricter options also block dangerous file types and cause false positives, so use them only for high-risk org units.',
    evaluate: (value) => {
      if (!value) {
        return {
          status: 'fail',
          currentValue: 'Not set (Chrome default: no special restrictions)',
          issues: ['Chrome lets users keep files that Safe Browsing flags as malicious.'],
        };
      }
      const mode = enumField(value, 'safeBrowsingDownloadRestrictions');
      const labels: Record<string, string> = {
        BLOCK_ALL_MALICIOUS_DOWNLOAD: 'Block malicious downloads',
        BLOCK_DANGEROUS_DOWNLOAD: 'Block malicious downloads and dangerous file types',
        BLOCK_POTENTIALLY_DANGEROUS_DOWNLOAD: 'Block malicious, uncommon, and dangerous downloads',
        BLOCK_ALL_DOWNLOAD: 'Block all downloads',
      };
      if (mode === 'NO_SPECIAL_RESTRICTIONS' || mode === undefined) {
        return {
          status: 'fail',
          currentValue: 'No special restrictions',
          issues: ['Chrome lets users keep files that Safe Browsing flags as malicious.'],
        };
      }
      if (labels[mode]) {
        if (overridable(value, 'downloadRestrictionsPolicyMode')) {
          return {
            status: 'warning',
            currentValue: `${labels[mode]}, users can override`,
            issues: ['The setting is a recommendation. Users can still override the block.'],
          };
        }
        return { status: 'pass', currentValue: labels[mode] };
      }
      return unrecognized('download restriction', mode);
    },
  },
  {
    id: 'chrome-site-isolation',
    name: 'Site Isolation',
    severity: 'medium',
    schemas: ['chrome.users.SiteIsolationBrowser'],
    recommendedValue: 'Require site isolation for all sites',
    rationale:
      'Site isolation runs each site in its own process, so a malicious page has a harder time reading data from another site.',
    recommendation:
      'Keep site isolation on and set it to "Require site isolation for all websites" so users cannot opt out.',
    evaluate: (value) => {
      if (!value) return { status: 'pass', currentValue: 'On (Chrome default on desktop)' };
      return boolField(value, 'sitePerProcess')
        ? { status: 'pass', currentValue: 'Required for all sites' }
        : {
            status: 'warning',
            currentValue: 'Not required (users can opt out)',
            issues: ['Site isolation stays on by default, but users can turn it off. Set it to required.'],
          };
    },
  },
  {
    id: 'chrome-allowed-domains',
    name: 'Allowed Domains for Google Sign-in',
    severity: 'medium',
    schemas: ['chrome.users.SecondaryGoogleAccountSignin'],
    recommendedValue: 'Only your Workspace domains',
    rationale:
      'Without a domain limit, users can sign in to Google services with personal accounts and move work data out of the organization.',
    recommendation:
      'Set "Sign-in to secondary accounts" to allow only your Workspace domains (AllowedDomainsForApps). This blocks personal Google accounts in Chrome and can break legitimate external collaboration, so roll it out one org unit at a time.',
    evaluate: (value) => {
      if (!value) {
        return {
          status: 'warning',
          currentValue: 'Not set (Chrome default: any Google account)',
          issues: ['Users can sign in to Google services with any account, including personal ones.'],
        };
      }
      const domains = listField(value, 'allowedDomainsForApps');
      if (domains.length > 0) {
        const shown = domains.slice(0, 5).join(', ');
        return {
          status: 'pass',
          currentValue: `Limited to ${shown}${domains.length > 5 ? ` + ${domains.length - 5} more` : ''}`,
        };
      }
      if (enumField(value, 'secondaryGoogleAccountSigninAllowed') === 'FALSE') {
        return {
          status: 'pass',
          currentValue: 'Secondary account sign-in blocked',
          issues: ['No domain list is set. Sign-in to secondary accounts is blocked outright instead.'],
        };
      }
      return {
        status: 'warning',
        currentValue: 'No domain limit',
        issues: ['Users can sign in to Google services with any account, including personal ones.'],
      };
    },
  },
];

function errorText(error: any): string {
  const data = error?.response?.data?.error ?? error?.errors?.[0] ?? {};
  const reasons = JSON.stringify(data?.details ?? data?.errors ?? '');
  return [error?.message, error?.code, error?.response?.status, data?.status, data?.message, reasons]
    .filter((p) => p !== undefined && p !== null && p !== '')
    .join(' ');
}

function chromeApiMessage(error: unknown): string {
  const text = errorText(error);
  if (/SERVICE_DISABLED|has not been used in project|accessNotConfigured|API .* is not enabled/i.test(text)) {
    return 'Chrome Policy API is not enabled for the Google Cloud project. Enable chromepolicy.googleapis.com and run the audit again.';
  }
  if (/unauthorized_client|invalid_grant|not authorized for any of the scopes|UNAUTHENTICATED|\b401\b/i.test(text)) {
    return 'Google rejected the delegated sign-in. Grant the chrome.management.policy.readonly scope to the service account in domain-wide delegation and run the audit again.';
  }
  if (/PERMISSION_DENIED|forbidden|\b403\b/i.test(text)) {
    return 'Chrome Policy API denied access. Likely causes: the chrome.management.policy.readonly scope is not granted in domain-wide delegation, or the signed-in admin cannot manage Chrome settings.';
  }
  if (/NOT_FOUND|\b404\b/i.test(text)) {
    return 'Chrome Policy API returned not found. Likely causes: the API is not enabled, or this Workspace has no Chrome policies configured.';
  }
  if (/RESOURCE_EXHAUSTED|rate.?limit|\b429\b/i.test(text)) {
    return 'Chrome Policy API is rate-limited. Wait a minute and run the audit again.';
  }
  return 'Chrome Policy API request failed. Likely causes: the API is not enabled, the scope is not granted, or no Chrome policies are configured.';
}

export class ChromePolicyService extends WorkspaceService {
  private notVerified(spec: PolicySpec, issue: string): ChromePolicyCheck {
    return this.toCheck(spec, { status: 'manual', currentValue: 'Not verified', issues: [issue] });
  }

  private toCheck(
    spec: PolicySpec,
    result: { status: ChromePolicyCheck['status']; currentValue: string; issues?: string[] }
  ): ChromePolicyCheck {
    return {
      id: spec.id,
      name: spec.name,
      category: CATEGORY,
      severity: spec.severity,
      status: result.status,
      currentValue: result.currentValue,
      recommendedValue: spec.recommendedValue,
      rationale: spec.rationale,
      recommendation: spec.recommendation,
      adminConsoleUrl: ADMIN_CONSOLE_URL,
      issues: result.issues?.length ? result.issues : undefined,
    };
  }

  /** Every chrome.users schema name the tenant exposes, lowercased. */
  private async listSchemaNames(chromePolicy: any): Promise<Set<string>> {
    const names = new Set<string>();
    let pageToken: string | undefined;
    for (let page = 0; page < MAX_PAGES; page++) {
      const response = await this.withRetry(() =>
        chromePolicy.customers.policySchemas.list({
          parent: 'customers/my_customer',
          filter: SCHEMA_NAMESPACE_FILTER,
          pageSize: SCHEMA_PAGE_SIZE,
          pageToken,
        })
      );
      for (const schema of response.data?.policySchemas ?? []) {
        const full: string = schema.schemaName || String(schema.name || '').split('/policySchemas/')[1] || '';
        if (full) names.add(full.toLowerCase());
      }
      pageToken = response.data?.nextPageToken || undefined;
      if (!pageToken) break;
    }
    return names;
  }

  /** Resolved field values for one schema at the org unit, or null when the policy is not set. */
  private async resolveSchema(chromePolicy: any, orgUnitId: string, schema: string): Promise<Fields | null> {
    let pageToken: string | undefined;
    for (let page = 0; page < MAX_PAGES; page++) {
      const response = await this.withRetry(() =>
        chromePolicy.customers.policies.resolve({
          customer: 'customers/my_customer',
          requestBody: {
            policyTargetKey: { targetResource: `orgunits/${orgUnitId}` },
            policySchemaFilter: schema,
            pageSize: RESOLVE_PAGE_SIZE,
            pageToken,
          },
        })
      );
      const match = (response.data?.resolvedPolicies ?? []).find(
        (p: any) => String(p?.value?.policySchema ?? '').toLowerCase() === schema.toLowerCase()
      );
      if (match) return (match.value?.value as Fields) ?? {};
      pageToken = response.data?.nextPageToken || undefined;
      if (!pageToken) break;
    }
    return null;
  }

  /**
   * Score Google's Chrome checklist items against the root org unit.
   * Throws ChromePolicyApiError when the Chrome Policy API fails, so the audit
   * can show one warning instead of seven guesses.
   */
  async getAllPolicyChecks(userEmail: string, rootOrgUnitId: string | null): Promise<ChromePolicyCheck[]> {
    if (!rootOrgUnitId) {
      return POLICIES.map((spec) =>
        this.notVerified(
          spec,
          'The root org unit could not be identified from Cloud Identity policies, so Chrome policies were not read.'
        )
      );
    }

    try {
      const chromePolicy = await this.chromePolicyFor(userEmail);
      const available = await this.listSchemaNames(chromePolicy);

      return await Promise.all(
        POLICIES.map(async (spec) => {
          const existing = spec.schemas.filter((s) => available.has(s.toLowerCase()));
          if (existing.length === 0) {
            return this.notVerified(
              spec,
              `Chrome Policy API did not list a matching schema. Tried: ${spec.schemas.join(', ')}.`
            );
          }
          for (const schema of existing) {
            const value = await this.resolveSchema(chromePolicy, rootOrgUnitId, schema);
            if (value) return this.toCheck(spec, spec.evaluate(value));
          }
          return this.toCheck(spec, spec.evaluate(null));
        })
      );
    } catch (error) {
      throw new ChromePolicyApiError(chromeApiMessage(error));
    }
  }
}

export const chromePolicyService = new ChromePolicyService();
