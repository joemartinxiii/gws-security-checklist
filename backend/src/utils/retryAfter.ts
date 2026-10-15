/**
 * Parse a Retry-After header (delay in seconds, or an HTTP-date) into
 * milliseconds. Returns null when the value is missing or unreadable.
 */
export function parseRetryAfterMs(
  header: string | number | null | undefined,
  now: number = Date.now()
): number | null {
  if (header === null || header === undefined || header === '') return null;
  const text = String(header).trim();
  if (/^\d+(\.\d+)?$/.test(text)) {
    return Math.round(Number(text) * 1000);
  }
  const at = Date.parse(text);
  if (Number.isNaN(at)) return null;
  return Math.max(0, at - now);
}
