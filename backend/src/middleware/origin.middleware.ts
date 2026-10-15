import { Request, Response, NextFunction } from 'express';

const UNSAFE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const LOCAL_DEV_ORIGIN = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/i;

function normalizeOrigin(origin: string): string {
  return origin.trim().replace(/\/+$/, '').toLowerCase();
}

function configuredOrigins(): string[] {
  return (process.env.CORS_ORIGIN || '')
    .split(',')
    .map(normalizeOrigin)
    .filter(Boolean);
}

function isAllowedOrigin(req: Request, origin: string, isProduction: boolean): boolean {
  const candidate = normalizeOrigin(origin);
  const configured = configuredOrigins();
  if (configured.includes(candidate)) return true;
  if (!isProduction) return LOCAL_DEV_ORIGIN.test(candidate);
  // Production without CORS_ORIGIN: the SPA is served by this app, so same host only.
  return configured.length === 0 && candidate === normalizeOrigin(`${req.protocol}://${req.get('host') || ''}`);
}

/**
 * CSRF guard for state-changing API calls. A present Origin header must match
 * the app origin. Without Origin, production accepts only requests the browser
 * marks same-origin (or user-initiated) through Sec-Fetch-Site.
 */
export function requireSameOrigin(req: Request, res: Response, next: NextFunction): void {
  if (!UNSAFE_METHODS.has(req.method)) {
    next();
    return;
  }

  const isProduction = process.env.NODE_ENV === 'production';
  const origin = req.get('origin');

  if (origin) {
    if (isAllowedOrigin(req, origin, isProduction)) {
      next();
      return;
    }
  } else if (!isProduction) {
    next();
    return;
  } else {
    const fetchSite = req.get('sec-fetch-site');
    if (fetchSite === 'same-origin' || fetchSite === 'none') {
      next();
      return;
    }
  }

  res.status(403).json({ error: 'Cross-origin request blocked.' });
}
