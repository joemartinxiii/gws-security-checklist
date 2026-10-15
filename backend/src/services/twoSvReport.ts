/**
 * Directory users.list rows for the 2FA report.
 * `admin.directory.user` / `.readonly` already returns these fields.
 */
export interface TwoSvUserRow {
  name: string;
  email: string;
  enrolled: boolean;
  enforced: boolean;
}

export interface TwoSvDirectoryUser {
  primaryEmail?: string | null;
  name?: { fullName?: string | null; givenName?: string | null; familyName?: string | null } | null;
  isEnrolledIn2Sv?: boolean | null;
  isEnforcedIn2Sv?: boolean | null;
}

export interface TwoSvDirectoryPage {
  users?: TwoSvDirectoryUser[] | null;
  nextPageToken?: string | null;
}

export interface TwoSvReport {
  generatedAt: string;
  truncated: boolean;
  users: TwoSvUserRow[];
}

/** Stop paging so a huge tenant cannot hold the request open indefinitely. */
export const TWO_SV_USER_CAP = 50000;

function displayName(user: TwoSvDirectoryUser, email: string): string {
  const full = (user.name?.fullName || '').trim();
  if (full) return full;
  const given = (user.name?.givenName || '').trim();
  const family = (user.name?.familyName || '').trim();
  const joined = `${given} ${family}`.trim();
  return joined || email;
}

export async function collectTwoSvUsers(
  listPage: (pageToken?: string) => Promise<TwoSvDirectoryPage>,
  maxUsers = TWO_SV_USER_CAP
): Promise<TwoSvReport> {
  const users: TwoSvUserRow[] = [];
  const seen = new Set<string>();
  let pageToken: string | undefined;
  let truncated = false;

  do {
    const page = await listPage(pageToken);
    const batch = page.users || [];
    for (const user of batch) {
      const email = (user.primaryEmail || '').trim();
      if (!email) continue;
      const key = email.toLowerCase();
      if (seen.has(key)) continue;
      if (users.length >= maxUsers) {
        truncated = true;
        break;
      }
      seen.add(key);
      users.push({
        name: displayName(user, email),
        email,
        enrolled: user.isEnrolledIn2Sv === true,
        enforced: user.isEnforcedIn2Sv === true,
      });
    }

    const next = page.nextPageToken || undefined;
    if (truncated) break;
    if (users.length >= maxUsers && next) {
      truncated = true;
      break;
    }
    if (next && batch.length === 0) {
      truncated = true;
      break;
    }
    pageToken = next;
  } while (pageToken);

  users.sort((a, b) => a.name.localeCompare(b.name) || a.email.localeCompare(b.email));

  return {
    generatedAt: new Date().toISOString(),
    truncated,
    users,
  };
}

export function twoSvUsersToCsv(users: TwoSvUserRow[]): string {
  const header = 'Name,Email,2FA Enrolled,2FA Enforced';
  const lines = users.map((user) =>
    [user.name, user.email, user.enrolled ? 'Yes' : 'No', user.enforced ? 'Yes' : 'No']
      .map(escapeCsv)
      .join(',')
  );
  return [header, ...lines].join('\n');
}

function escapeCsv(value: string): string {
  const flattened = value.replace(/\r\n|\n|\r/g, ' ');
  const neutralized = /^[=+\-@\t]/.test(flattened) ? `'${flattened}` : flattened;
  const stringValue = neutralized.replace(/"/g, '""');
  if (stringValue.includes(',') || stringValue.includes('"')) {
    return `"${stringValue}"`;
  }
  return stringValue;
}
