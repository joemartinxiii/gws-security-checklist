import { CookieOptions } from 'express';

/** HttpOnly session cookie name (read by auth middleware). */
export const SESSION_COOKIE_NAME = 'sessionToken';

/** Short-lived cookie holding OAuth `state` for CSRF protection on the callback. */
export const OAUTH_STATE_COOKIE_NAME = 'oauth_state';

/**
 * Parse durations into milliseconds.
 * Supports plain seconds, or values like 24h / 8h / 15m / 3600s.
 */
export function parseDurationMs(raw: string, fallbackMs: number): number {
  const m = raw.trim().match(/^(\d+)([smhd])?$/i);
  if (!m) return fallbackMs;
  const n = parseInt(m[1], 10);
  const unit = (m[2] || 's').toLowerCase();
  const mult =
    unit === 'd' ? 86400000 : unit === 'h' ? 3600000 : unit === 'm' ? 60000 : 1000;
  return n * mult;
}

/** Idle window. The browser cookie and the token both use this. Default 15 minutes. */
export function idleTimeoutMs(): number {
  return parseDurationMs(process.env.IDLE_TIMEOUT || '15m', 15 * 60 * 1000);
}

/** Hard stop from the original sign-in, even if the admin keeps working. Default 1 hour. */
export function absoluteSessionMs(): number {
  return parseDurationMs(process.env.JWT_EXPIRES_IN || '1h', 60 * 60 * 1000);
}

export function sessionMaxAgeMs(): number {
  return idleTimeoutMs();
}

/**
 * Cookie options for the app session.
 * - Production (Cloud Run HTTPS, same-origin SPA+API): Secure + HttpOnly + SameSite=Lax
 * - Development: Secure=false so localhost over HTTP works
 */
export function sessionCookieOptions(maxAgeMs: number = sessionMaxAgeMs()): CookieOptions {
  const isProd = process.env.NODE_ENV === 'production';
  return {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax',
    path: '/',
    maxAge: maxAgeMs,
  };
}

export function clearCookieOptions(): CookieOptions {
  const isProd = process.env.NODE_ENV === 'production';
  return {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax',
    path: '/',
    maxAge: 0,
  };
}

export function oauthStateCookieOptions(): CookieOptions {
  const isProd = process.env.NODE_ENV === 'production';
  return {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax',
    path: '/',
    maxAge: 10 * 60 * 1000, // 10 minutes for the OAuth round-trip
  };
}
