import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { getOAuth2Client, getTokensFromCode } from '../config/google.config';
import {
  deleteAdminSession,
  getAdminSession,
  saveAdminSession,
  updateAdminSession,
} from './securityAuditStore';
import { absoluteSessionMs, idleTimeoutMs } from '../utils/sessionCookie';

/** How long the previous cookie still works after a request replaces it. */
export const SESSION_ROTATION_GRACE_MS = 10_000;

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('CRITICAL: JWT_SECRET environment variable not set!');
  throw new Error('JWT_SECRET environment variable is required');
}
// TypeScript now knows JWT_SECRET is defined
const jwtSecret: string = JWT_SECRET;

export interface AuthTokens {
  accessToken: string;
  refreshToken?: string;
  expiresAt: number;
}

export interface UserInfo {
  email: string;
  name: string;
  picture?: string;
}

export interface SessionClaims extends UserInfo {
  sid: string;
  authTime: number;
  lastActivity: number;
}

const KNOWN_SESSION_ERRORS = new Set([
  'Session idle timeout',
  'Session ended',
  'Session revoked',
]);

function newSid(): string {
  return crypto.randomBytes(16).toString('hex');
}

function rethrowKnown(error: unknown): never {
  if (error instanceof Error && KNOWN_SESSION_ERRORS.has(error.message)) throw error;
  throw new Error('Invalid or expired token');
}

export class AuthService {
  /**
   * Exchange OAuth2 code for tokens
   */
  async exchangeCodeForTokens(code: string): Promise<AuthTokens> {
    const tokens = await getTokensFromCode(code);
    
    if (!tokens.access_token) {
      throw new Error('No access token received');
    }

    const expiresAt = tokens.expiry_date 
      ? new Date(tokens.expiry_date).getTime()
      : Date.now() + 3600000; // Default 1 hour

    return {
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      expiresAt,
    };
  }

  /**
   * Get user info from OAuth2 token
   */
  async getUserInfo(accessToken: string): Promise<UserInfo> {
    const oauth2Client = getOAuth2Client();
    oauth2Client.setCredentials({ access_token: accessToken });

    const oauth2 = (await import('googleapis')).google.oauth2({ version: 'v2', auth: oauth2Client });
    const { data } = await oauth2.userinfo.get();

    return {
      email: data.email || '',
      name: data.name || '',
      picture: data.picture || undefined,
    };
  }

  /**
   * Create a JWT for a new sign-in. Replaces any session this admin already has.
   * The token expires at the idle window. authTime does not move.
   */
  async createSessionToken(userInfo: UserInfo): Promise<string> {
    const now = nowSeconds();
    const claims: SessionClaims = {
      email: userInfo.email,
      name: userInfo.name,
      picture: userInfo.picture,
      sid: newSid(),
      authTime: now,
      lastActivity: now,
    };
    await saveAdminSession({
      sid: claims.sid,
      email: claims.email,
      name: claims.name,
      picture: claims.picture,
      authTime: claims.authTime,
      lastActivity: claims.lastActivity,
    });
    return this.signSession(claims);
  }

  /**
   * Verify a JWT. Rejects it after 15 minutes without a request, and 1 hour
   * after the original sign-in. The session id must still be the one on file,
   * or the previous id inside the short replacement window.
   */
  async verifySessionToken(token: string): Promise<SessionClaims> {
    try {
      const decoded = jwt.verify(token, jwtSecret, { algorithms: ['HS256'] }) as jwt.JwtPayload & {
        email?: string;
        name?: string;
        picture?: string;
        sid?: string;
        authTime?: number;
        lastActivity?: number;
      };
      if (!decoded.email || !decoded.name || !decoded.iat) {
        throw new Error('Invalid token payload');
      }
      const authTime = decoded.authTime ?? decoded.iat;
      const lastActivity = decoded.lastActivity ?? decoded.iat;
      const now = nowSeconds();
      if (now - lastActivity > Math.floor(idleTimeoutMs() / 1000)) {
        throw new Error('Session idle timeout');
      }
      if (now - authTime > Math.floor(absoluteSessionMs() / 1000)) {
        throw new Error('Session ended');
      }
      if (!decoded.sid) {
        throw new Error('Session revoked');
      }
      const record = await getAdminSession(decoded.email);
      const nowMs = Date.now();
      const current = record?.sid === decoded.sid && record.authTime === authTime;
      const previous =
        record?.previousSid === decoded.sid &&
        record.authTime === authTime &&
        typeof record.previousSidUntil === 'number' &&
        nowMs < record.previousSidUntil;
      if (!current && !previous) {
        throw new Error('Session revoked');
      }
      return {
        email: decoded.email,
        name: decoded.name,
        picture: decoded.picture,
        sid: decoded.sid,
        authTime,
        lastActivity,
      };
    } catch (error) {
      rethrowKnown(error);
    }
  }

  /**
   * Replace the cookie after a real request. The previous cookie works for a
   * few seconds so two requests in flight do not sign each other out. The new
   * token expires 15 minutes from now, or sooner if the 1-hour limit is closer.
   */
  async refreshSessionToken(session: SessionClaims): Promise<{ token: string; maxAgeMs: number }> {
    const now = nowSeconds();
    const stored = await updateAdminSession(session.email, (current) => {
      if (!current || current.authTime !== session.authTime) {
        throw new Error('Session revoked');
      }
      const nowMs = Date.now();
      if (current.sid === session.sid) {
        return {
          ...current,
          previousSid: current.sid,
          previousSidUntil: nowMs + SESSION_ROTATION_GRACE_MS,
          sid: newSid(),
          lastActivity: now,
        };
      }
      if (
        current.previousSid === session.sid &&
        typeof current.previousSidUntil === 'number' &&
        nowMs < current.previousSidUntil
      ) {
        return { ...current, lastActivity: now };
      }
      throw new Error('Session revoked');
    });
    const claims: SessionClaims = {
      email: stored.email,
      name: stored.name,
      picture: stored.picture,
      sid: stored.sid,
      authTime: stored.authTime,
      lastActivity: stored.lastActivity,
    };
    const token = this.signSession(claims);
    const absoluteLeftMs = (claims.authTime + Math.floor(absoluteSessionMs() / 1000) - now) * 1000;
    return { token, maxAgeMs: Math.min(idleTimeoutMs(), Math.max(absoluteLeftMs, 1000)) };
  }

  /**
   * Logout. Deletes the stored session when this token is the current cookie
   * or the previous cookie still inside the replacement window.
   */
  async revokeSessionToken(token: string): Promise<void> {
    try {
      const decoded = jwt.verify(token, jwtSecret, {
        algorithms: ['HS256'],
        ignoreExpiration: true,
      }) as jwt.JwtPayload & { email?: string; sid?: string };
      if (!decoded.email || !decoded.sid) return;
      const record = await getAdminSession(decoded.email);
      if (!record) return;
      const nowMs = Date.now();
      const current = record.sid === decoded.sid;
      const previous =
        record.previousSid === decoded.sid &&
        typeof record.previousSidUntil === 'number' &&
        nowMs < record.previousSidUntil;
      if (current || previous) {
        await deleteAdminSession(decoded.email);
      }
    } catch {
      return;
    }
  }

  private signSession(claims: SessionClaims): string {
    const now = nowSeconds();
    const absoluteEnd = claims.authTime + Math.floor(absoluteSessionMs() / 1000);
    const idleEnd = now + Math.floor(idleTimeoutMs() / 1000);
    const ttlSeconds = Math.max(Math.min(absoluteEnd, idleEnd) - now, 1);
    return jwt.sign(
      {
        email: claims.email,
        name: claims.name,
        picture: claims.picture,
        sid: claims.sid,
        authTime: claims.authTime,
        lastActivity: claims.lastActivity,
      },
      jwtSecret,
      { algorithm: 'HS256', expiresIn: ttlSeconds }
    );
  }

}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

export const authService = new AuthService();
