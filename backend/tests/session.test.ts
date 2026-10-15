import jwt from 'jsonwebtoken';
import { authService } from '../src/services/auth.service';
import { deleteAdminSession, getAdminSession, saveAdminSession } from '../src/services/securityAuditStore';

const secret = process.env.JWT_SECRET as string;
const email = 'admin@example.com';

function tokenAt(authTime: number, lastActivity: number): string {
  return jwt.sign(
    {
      email,
      name: 'Admin',
      authTime,
      lastActivity,
    },
    secret,
    { algorithm: 'HS256', expiresIn: '1h' }
  );
}

afterEach(async () => {
  await deleteAdminSession(email);
});

describe('session idle timeout', () => {
  it('accepts a new sign-in and expires the token at the idle window', async () => {
    const token = await authService.createSessionToken({ email, name: 'Admin' });
    const session = await authService.verifySessionToken(token);
    expect(session.email).toBe(email);
    const decoded = jwt.decode(token) as jwt.JwtPayload;
    expect(decoded.exp! - decoded.iat!).toBeLessThanOrEqual(15 * 60);
    expect(decoded.exp! - decoded.iat!).toBeGreaterThan(14 * 60);
  });

  it('rejects a token that has been idle for more than 15 minutes', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = tokenAt(now - 20 * 60, now - 16 * 60);
    await expect(authService.verifySessionToken(token)).rejects.toThrow('Session idle timeout');
  });

  it('rejects a session older than 1 hour even when the last request was recent', async () => {
    const now = Math.floor(Date.now() / 1000);
    const token = tokenAt(now - 2 * 60 * 60, now);
    await expect(authService.verifySessionToken(token)).rejects.toThrow('Session ended');
  });

  it('rejects a token signed with a different algorithm', async () => {
    const token = jwt.sign({ email, name: 'Admin', sid: 'abc', authTime: 1, lastActivity: 1 }, secret, {
      algorithm: 'HS512',
      expiresIn: '15m',
    });
    await expect(authService.verifySessionToken(token)).rejects.toThrow('Invalid or expired token');
  });

  it('replaces the session id and keeps the previous cookie briefly', async () => {
    const token = await authService.createSessionToken({ email, name: 'Admin' });
    const session = await authService.verifySessionToken(token);
    const refreshed = await authService.refreshSessionToken(session);
    const decoded = jwt.decode(refreshed.token) as jwt.JwtPayload;
    expect(decoded.sid).not.toBe(session.sid);
    expect(decoded.lastActivity).toBeGreaterThanOrEqual(session.lastActivity);
    expect(refreshed.maxAgeMs).toBe(15 * 60 * 1000);
    await expect(authService.verifySessionToken(refreshed.token)).resolves.toMatchObject({ email });
    await expect(authService.verifySessionToken(token)).resolves.toMatchObject({ email });

    const record = await getAdminSession(email);
    expect(record).not.toBeNull();
    await saveAdminSession({ ...record!, previousSidUntil: Date.now() - 1 });
    await expect(authService.verifySessionToken(token)).rejects.toThrow('Session revoked');
    await expect(authService.verifySessionToken(refreshed.token)).resolves.toMatchObject({ email });
  });

  it('a second sign-in revokes the first cookie immediately', async () => {
    const first = await authService.createSessionToken({ email, name: 'Admin' });
    const second = await authService.createSessionToken({ email, name: 'Admin' });
    await expect(authService.verifySessionToken(first)).rejects.toThrow('Session revoked');
    await expect(authService.verifySessionToken(second)).resolves.toMatchObject({ email });
  });

  it('logout deletes the stored session', async () => {
    const token = await authService.createSessionToken({ email, name: 'Admin' });
    await authService.revokeSessionToken(token);
    await expect(authService.verifySessionToken(token)).rejects.toThrow('Session revoked');
    expect(await getAdminSession(email)).toBeNull();
  });
});
