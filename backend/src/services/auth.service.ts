import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { getGoogleConfig, getOAuth2Client, getTokensFromCode } from '../config/google.config';
import {
  AdminSessionRecord,
  deleteAdminSession,
  getAdminSession,
  saveAdminSession,
  updateAdminSession,
} from './securityAuditStore';
import { absoluteSessionMs, idleTimeoutMs } from '../utils/sessionCookie';

/**
 * A new session id is issued once the current one is this old. The previous id
 * keeps working for the grace period, which must outlast the longest request
 * (Cloud Run times out at 300 seconds) so a long audit does not sign the user out.
 */
export const SESSION_ROTATE_AFTER_SECONDS = 5 * 60;
export const SESSION_ROTATION_GRACE_MS = 6 * 60 * 1000;

/** lastActivity is written at most this often to stay under the GCS per-object write rate. */
export const SESSION_ACTIVITY_WRITE_SECONDS = 60;

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('CRITICAL: JWT_SECRET environment variable not set!');
  throw new Error('JWT_SECRET environment variable is required');
}
// TypeScript now knows JWT_SECRET is defined
const jwtSecret: string = JWT_SECRET;

export interface AuthTokens {
  accessToken: string;
  idToken?: string;
  refreshToken?: string;
  expiresAt: number;
}

/** Claims from a verified Google ID token. */
export interface VerifiedIdentity {
  sub: string;
  email: string;
  emailVerified: boolean;
  hd?: string;
  name?: string;
  picture?: string;
}

export interface UserInfo {
  email: string;
  name: string;
  picture?: string;
  sub?: string;
}

export interface SessionClaims extends UserInfo {
  sid: string;
  authTime: number;
  lastActivity: number;
}

/** Claims plus the stored record state the request was checked against. */
export interface VerifiedSession extends SessionClaims {
  /** The id on file. Differs from `sid` when the request used the previous id. */
  currentSid: string;
  sidIssuedAt: number;
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
   * Exchange OAuth2 code for tokens, proving possession of the PKCE verifier.
   */
  async exchangeCodeForTokens(code: string, codeVerifier: string): Promise<AuthTokens> {
    const tokens = await getTokensFromCode(code, codeVerifier);

    if (!tokens.access_token) {
      throw new Error('No access token received');
    }

    const expiresAt = tokens.expiry_date 
      ? new Date(tokens.expiry_date).getTime()
      : Date.now() + 3600000; // Default 1 hour

    return {
      accessToken: tokens.access_token,
      idToken: tokens.id_token || undefined,
      refreshToken: tokens.refresh_token,
      expiresAt,
    };
  }

  /**
   * Verify the ID token signature, issuer, expiry, and audience (our client ID).
   * The caller applies the domain and email policy to the returned claims.
   */
  async verifyIdToken(idToken: string): Promise<VerifiedIdentity> {
    const { clientId } = getGoogleConfig();
    if (!clientId) throw new Error('GOOGLE_CLIENT_ID is not configured');
    const ticket = await getOAuth2Client().verifyIdToken({ idToken, audience: clientId });
    const payload = ticket.getPayload();
    if (!payload?.sub) throw new Error('ID token has no subject');
    return {
      sub: payload.sub,
      email: payload.email || '',
      emailVerified: payload.email_verified === true,
      hd: payload.hd,
      name: payload.name,
      picture: payload.picture,
    };
  }

  /**
   * Create a JWT for a new sign-in. Replaces any session this admin already has.
   * authTime does not move.
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
      sidIssuedAt: now,
      email: claims.email,
      name: claims.name,
      picture: claims.picture,
      sub: userInfo.sub,
      authTime: claims.authTime,
      lastActivity: claims.lastActivity,
    });
    return this.signSession(claims);
  }

  /**
   * Verify a JWT against the stored session. Rejects it 1 hour after the
   * original sign-in, and after 15 minutes without a request (measured from the
   * stored lastActivity, which is written at most once a minute). The session id
   * must be the one on file, or the previous id inside its grace period.
   */
  async verifySessionToken(token: string): Promise<VerifiedSession> {
    try {
      const decoded = jwt.verify(token, jwtSecret, { algorithms: ['HS256'] }) as jwt.JwtPayload & {
        email?: string;
        name?: string;
        picture?: string;
        sid?: string;
        authTime?: number;
      };
      if (!decoded.email || !decoded.name || !decoded.iat) {
        throw new Error('Invalid token payload');
      }
      const authTime = decoded.authTime ?? decoded.iat;
      const now = nowSeconds();
      if (now - authTime > Math.floor(absoluteSessionMs() / 1000)) {
        throw new Error('Session ended');
      }
      if (!decoded.sid) {
        throw new Error('Session revoked');
      }
      const record = await getAdminSession(decoded.email);
      if (!record || record.authTime !== authTime) {
        throw new Error('Session revoked');
      }
      const current = record.sid === decoded.sid;
      const previous = isPreviousSidValid(record, decoded.sid);
      if (!current && !previous) {
        throw new Error('Session revoked');
      }
      if (now - record.lastActivity > Math.floor(idleTimeoutMs() / 1000)) {
        throw new Error('Session idle timeout');
      }
      return {
        email: decoded.email,
        name: decoded.name,
        picture: decoded.picture,
        sub: record.sub,
        sid: decoded.sid,
        currentSid: record.sid,
        sidIssuedAt: record.sidIssuedAt,
        authTime,
        lastActivity: record.lastActivity,
      };
    } catch (error) {
      rethrowKnown(error);
    }
  }

  /**
   * Housekeeping after a verified cookie request. Returns a replacement cookie
   * when the session id was rotated, or when the request used the previous id
   * and the browser should move to the current one. Returns null when nothing
   * needs to change. The session id rotates once it is 5 minutes old, and
   * lastActivity is written at most once a minute. A storage failure never
   * ends the session. Only a revoked session throws.
   */
  async refreshSessionToken(
    session: VerifiedSession
  ): Promise<{ token: string; maxAgeMs: number } | null> {
    const now = nowSeconds();
    const usedPrevious = session.sid !== session.currentSid;
    const rotateDue = !usedPrevious && now - session.sidIssuedAt >= SESSION_ROTATE_AFTER_SECONDS;
    const touchDue = now - session.lastActivity >= SESSION_ACTIVITY_WRITE_SECONDS;
    if (!rotateDue && !touchDue && !usedPrevious) return null;

    if (!rotateDue && !touchDue) {
      return this.cookieFor({ ...session, sid: session.currentSid }, now);
    }

    try {
      const stored = await updateAdminSession(session.email, (current) => {
        if (!current || current.authTime !== session.authTime) {
          throw new Error('Session revoked');
        }
        if (current.sid === session.sid) {
          if (now - current.sidIssuedAt >= SESSION_ROTATE_AFTER_SECONDS) {
            return {
              ...current,
              previousSid: current.sid,
              previousSidUntil: Date.now() + SESSION_ROTATION_GRACE_MS,
              sid: newSid(),
              sidIssuedAt: now,
              lastActivity: now,
            };
          }
        } else if (!isPreviousSidValid(current, session.sid)) {
          throw new Error('Session revoked');
        }
        if (now - current.lastActivity < SESSION_ACTIVITY_WRITE_SECONDS) return current;
        return { ...current, lastActivity: now };
      });
      return this.cookieFor(
        {
          email: stored.email,
          name: stored.name,
          picture: stored.picture,
          sid: stored.sid,
          authTime: stored.authTime,
          lastActivity: stored.lastActivity,
        },
        now
      );
    } catch (error) {
      if (error instanceof Error && KNOWN_SESSION_ERRORS.has(error.message)) throw error;
      console.error('Session refresh failed:', error);
      return null;
    }
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
      if (record.sid === decoded.sid || isPreviousSidValid(record, decoded.sid)) {
        await deleteAdminSession(decoded.email);
      }
    } catch {
      return;
    }
  }

  private cookieFor(claims: SessionClaims, now: number): { token: string; maxAgeMs: number } {
    const absoluteLeftMs = (claims.authTime + Math.floor(absoluteSessionMs() / 1000) - now) * 1000;
    return {
      token: this.signSession(claims),
      maxAgeMs: Math.min(idleTimeoutMs(), Math.max(absoluteLeftMs, 1000)),
    };
  }

  /**
   * The token lives until the absolute limit. Idle expiry is enforced against
   * the stored record, because the token is reissued only on rotation.
   */
  private signSession(claims: SessionClaims): string {
    const now = nowSeconds();
    const absoluteEnd = claims.authTime + Math.floor(absoluteSessionMs() / 1000);
    const ttlSeconds = Math.max(absoluteEnd - now, 1);
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

function isPreviousSidValid(record: AdminSessionRecord, sid: string): boolean {
  return (
    record.previousSid === sid &&
    typeof record.previousSidUntil === 'number' &&
    Date.now() < record.previousSidUntil
  );
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

export const authService = new AuthService();
