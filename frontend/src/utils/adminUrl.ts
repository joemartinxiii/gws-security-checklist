const ADMIN_CONSOLE_PREFIX = 'https://admin.google.com/';

/** Returns the URL only when it is an https link on admin.google.com. */
export function safeAdminConsoleUrl(url: unknown): string | undefined {
  if (typeof url !== 'string' || !url.startsWith(ADMIN_CONSOLE_PREFIX)) return undefined;
  try {
    const parsed = new URL(url);
    if (parsed.origin !== 'https://admin.google.com') return undefined;
    return parsed.href;
  } catch {
    return undefined;
  }
}
