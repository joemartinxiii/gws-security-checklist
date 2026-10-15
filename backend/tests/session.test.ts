import jwt from 'jsonwebtoken';
import { authService } from '../src/services/auth.service';

const secret = process.env.JWT_SECRET as string;

function tokenAt(authTime: number, lastActivity: number): string {
  return jwt.sign(
    {
      email: 'admin@example.com',
      name: 'Admin',
      authTime,
      lastActivity,
    },
    secret,
    { expiresIn: '1h' }
  );
}

describe('session idle timeout', () => {
  it('accepts a new sign-in and expires the token at the idle window', () => {
    const token = authService.createSessionToken({ email: 'admin@example.com', name: 'Admin' });
    const session = authService.verifySessionToken(token);
    expect(session.email).toBe('admin@example.com');
    const decoded = jwt.decode(token) as jwt.JwtPayload;
    expect(decoded.exp! - decoded.iat!).toBeLessThanOrEqual(15 * 60);
    expect(decoded.exp! - decoded.iat!).toBeGreaterThan(14 * 60);
  });

  it('rejects a token that has been idle for more than 15 minutes', () => {
    const now = Math.floor(Date.now() / 1000);
    const token = tokenAt(now - 20 * 60, now - 16 * 60);
    expect(() => authService.verifySessionToken(token)).toThrow('Session idle timeout');
  });

  it('rejects a session older than 8 hours even when the last request was recent', () => {
    const now = Math.floor(Date.now() / 1000);
    const token = tokenAt(now - 9 * 60 * 60, now);
    expect(() => authService.verifySessionToken(token)).toThrow('Session ended');
  });

  it('replaces an active session with a new 15-minute token', () => {
    const now = Math.floor(Date.now() / 1000);
    const session = authService.verifySessionToken(tokenAt(now - 60, now - 60));
    const refreshed = authService.refreshSessionToken(session);
    const decoded = jwt.decode(refreshed.token) as jwt.JwtPayload;
    expect(decoded.lastActivity).toBeGreaterThanOrEqual(now);
    expect(refreshed.maxAgeMs).toBe(15 * 60 * 1000);
    expect(authService.verifySessionToken(refreshed.token).email).toBe('admin@example.com');
  });
});
