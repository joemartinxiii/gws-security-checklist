import { Request, Response, NextFunction } from 'express';
import { authService } from '../services/auth.service';
import { clearCookieOptions, SESSION_COOKIE_NAME, sessionCookieOptions } from '../utils/sessionCookie';

export interface AuthRequest extends Request {
  user?: {
    email: string;
    name: string;
    picture?: string;
  };
  accessToken?: string;
}

/**
 * Prefer HttpOnly session cookie. Outside production, accept Authorization
 * Bearer for automation (Playwright, live tests, curl). The SPA does not store
 * tokens, and production ignores the header.
 */
function extractSessionToken(req: Request): string | undefined {
  const cookieToken = req.cookies?.[SESSION_COOKIE_NAME];
  if (cookieToken && typeof cookieToken === 'string' && cookieToken.length > 0) {
    return cookieToken;
  }
  if (process.env.NODE_ENV === 'production') return undefined;
  const header = req.headers.authorization;
  if (header?.startsWith('Bearer ')) {
    const bearer = header.slice(7).trim();
    if (bearer) return bearer;
  }
  return undefined;
}

/**
 * Middleware to verify JWT session token (cookie, or Bearer outside production).
 */
export async function authenticateSession(
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const token = extractSessionToken(req);

    if (!token) {
      res.status(401).json({ error: 'No authentication token provided' });
      return;
    }

    const session = await authService.verifySessionToken(token);
    req.user = { email: session.email, name: session.name, picture: session.picture };
    if (req.cookies?.[SESSION_COOKIE_NAME]) {
      const refreshed = await authService.refreshSessionToken(session);
      if (refreshed) {
        res.cookie(SESSION_COOKIE_NAME, refreshed.token, sessionCookieOptions(refreshed.maxAgeMs));
      }
    }
    next();
  } catch {
    if (req.cookies?.[SESSION_COOKIE_NAME]) {
      res.clearCookie(SESSION_COOKIE_NAME, clearCookieOptions());
    }
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}
