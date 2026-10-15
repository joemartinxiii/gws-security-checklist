import jwt from 'jsonwebtoken';
import { getOAuth2Client, getTokensFromCode } from '../config/google.config';
import { absoluteSessionMs, idleTimeoutMs } from '../utils/sessionCookie';

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
  authTime: number;
  lastActivity: number;
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
   * Create a JWT for a new sign-in. The token expires at the idle window.
   * authTime is the original sign-in and does not move.
   */
  createSessionToken(userInfo: UserInfo): string {
    const now = nowSeconds();
    return this.signSession({
      email: userInfo.email,
      name: userInfo.name,
      picture: userInfo.picture,
      authTime: now,
      lastActivity: now,
    });
  }

  /**
   * Verify a JWT. Rejects it after 15 minutes without a request, and 8 hours
   * after the original sign-in. Tokens from before idle tracking use iat.
   */
  verifySessionToken(token: string): SessionClaims {
    try {
      const decoded = jwt.verify(token, jwtSecret) as jwt.JwtPayload & {
        email?: string;
        name?: string;
        picture?: string;
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
      return {
        email: decoded.email,
        name: decoded.name,
        picture: decoded.picture,
        authTime,
        lastActivity,
      };
    } catch (error) {
      if (error instanceof Error && (error.message === 'Session idle timeout' || error.message === 'Session ended')) {
        throw error;
      }
      throw new Error('Invalid or expired token');
    }
  }

  /**
   * Replace the cookie after a real request. The new token expires 15 minutes
   * from now, or sooner if the 8-hour sign-in limit is closer.
   */
  refreshSessionToken(session: SessionClaims): { token: string; maxAgeMs: number } {
    const now = nowSeconds();
    const claims: SessionClaims = { ...session, lastActivity: now };
    const token = this.signSession(claims);
    const absoluteLeftMs = (claims.authTime + Math.floor(absoluteSessionMs() / 1000) - now) * 1000;
    return { token, maxAgeMs: Math.min(idleTimeoutMs(), Math.max(absoluteLeftMs, 1000)) };
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
        authTime: claims.authTime,
        lastActivity: claims.lastActivity,
      },
      jwtSecret,
      { expiresIn: ttlSeconds }
    );
  }

}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

export const authService = new AuthService();
