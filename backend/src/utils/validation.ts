export function validateEmail(email: string): { valid: boolean; error?: string } {
  if (!email || typeof email !== 'string') {
    return { valid: false, error: 'Email is required' };
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return { valid: false, error: 'Invalid email format' };
  }

  if (email.length > 254) {
    return { valid: false, error: 'Email too long' };
  }

  return { valid: true };
}

export function validateDomain(domain: string): { valid: boolean; error?: string } {
  if (!domain || typeof domain !== 'string') {
    return { valid: false, error: 'Domain is required' };
  }

  const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  if (!domainRegex.test(domain)) {
    return { valid: false, error: 'Invalid domain format' };
  }

  if (domain.length > 253) {
    return { valid: false, error: 'Domain too long' };
  }

  return { valid: true };
}

/**
 * Domains permitted for this install: WORKSPACE_DOMAIN plus GWS_ALLOWED_DOMAINS.
 * Used for the login gate.
 */
export function getAllowedDomains(): string[] {
  const domains = new Set<string>();
  const primary = process.env.WORKSPACE_DOMAIN?.trim().toLowerCase();
  if (primary) domains.add(primary);
  for (const d of process.env.GWS_ALLOWED_DOMAINS?.split(',') || []) {
    const trimmed = d.trim().toLowerCase();
    if (trimmed) domains.add(trimmed);
  }
  return Array.from(domains);
}

/**
 * True if the email belongs to a permitted Workspace domain. If no domains are
 * configured (misconfiguration), returns false so we fail closed in production.
 */
export function isEmailInAllowedDomain(email: string): boolean {
  const domain = String(email || '')
    .split('@')[1]
    ?.toLowerCase();
  if (!domain) return false;
  const allowed = getAllowedDomains();
  if (allowed.length === 0) return false;
  return allowed.includes(domain);
}

export function isDomainAllowed(domain: string): boolean {
  const d = String(domain || '')
    .trim()
    .toLowerCase();
  if (!d) return false;
  const allowed = getAllowedDomains();
  if (allowed.length === 0) return false;
  return allowed.includes(d);
}

/** True if two emails are the same mailbox (case-insensitive). */
export function emailsEqual(a: string, b: string): boolean {
  return String(a || '').trim().toLowerCase() === String(b || '').trim().toLowerCase();
}

/**
 * GWS_AUDIT_READERS: exact email addresses (comma-separated, case-insensitive)
 * that may read stored audit results without being super admins.
 */
export function getAuditReaders(): Set<string> {
  const readers = new Set<string>();
  for (const entry of process.env.GWS_AUDIT_READERS?.split(',') || []) {
    const email = entry.trim().toLowerCase();
    if (email) readers.add(email);
  }
  return readers;
}

export const WAIVER_CHECK_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,79}$/;
export const WAIVER_REASON_MAX_LENGTH = 1000;

/** Normalize and validate a waiver. Returns the trimmed reason or an error message. */
export function validateWaiver(
  checkId: unknown,
  reason: unknown
): { reason: string } | { error: string } {
  if (typeof checkId !== 'string' || !WAIVER_CHECK_ID_PATTERN.test(checkId)) {
    return { error: 'checkId must be lowercase letters, digits, and hyphens (80 characters max)' };
  }
  const trimmed = typeof reason === 'string' ? reason.trim() : '';
  if (!trimmed) {
    return { error: 'reason is required' };
  }
  if (trimmed.length > WAIVER_REASON_MAX_LENGTH) {
    return { error: `reason must be ${WAIVER_REASON_MAX_LENGTH} characters or fewer` };
  }
  return { reason: trimmed };
}
