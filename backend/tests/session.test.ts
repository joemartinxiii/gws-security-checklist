import jwt from 'jsonwebtoken';
import {
  authService,
  SESSION_ROTATE_AFTER_SECONDS,
  SESSION_ROTATION_GRACE_MS,
} from '../src/services/auth.service';
import { deleteAdminSession, getAdminSession, saveAdminSession } from '../src/services/securityAuditStore';

const secret = process.env.JWT_SECRET as string;
const email = 'admin@example.com';

function tokenAt(authTime: number, sid = 'abc'): string {
  return jwt.sign({ email, name: 'Admin', sid, authTime }, secret, {
    algorithm: 'HS256',
    expiresIn: '1h',
  });
}

let clockOffsetMs = 0;
const realNow = Date.now.bind(Date);

function advance(seconds: number): void {
  clockOffsetMs += seconds * 1000;
}

beforeEach(() => {
  clockOffsetMs = 0;
  jest.spyOn(Date, 'now').mockImplementation(() => realNow() + clockOffsetMs);
});

afterEach(async () => {
  jest.restoreAllMocks();
  await deleteAdminSession(email);
});

describe('session verification', () => {
  it('accepts a new sign-in and keeps the token until the absolute limit', async () => {
    const token = await authService.createSessionToken({ email, name: 'Admin', sub: 'sub-1' });
    const session = await authService.verifySessionToken(token);
    expect(session.email).toBe(email);
    const decoded = jwt.decode(token) as jwt.JwtPayload;
    expect(decoded.exp! - decoded.iat!).toBeGreaterThan(59 * 60);
    expect((await getAdminSession(email))?.sub).toBe('sub-1');
  });

  it('rejects a session that has been idle for more than 15 minutes', async () => {
    const token = await authService.createSessionToken({ email, name: 'Admin' });
    advance(16 * 60);
    await expect(authService.verifySessionToken(token)).rejects.toThrow('Session idle timeout');
  });

  it('rejects a session older than 1 hour even when the last request was recent', async () => {
    const now = Math.floor(Date.now() / 1000);
    await expect(authService.verifySessionToken(tokenAt(now - 2 * 60 * 60))).rejects.toThrow(
      'Session ended'
    );
  });

  it('rejects a token signed with a different algorithm', async () => {
    const token = jwt.sign({ email, name: 'Admin', sid: 'abc', authTime: 1 }, secret, {
      algorithm: 'HS512',
      expiresIn: '15m',
    });
    await expect(authService.verifySessionToken(token)).rejects.toThrow('Invalid or expired token');
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

describe('session rotation and activity writes', () => {
  it('keeps the session id and skips the write for a young session with recent activity', async () => {
    const token = await authService.createSessionToken({ email, name: 'Admin' });
    const before = await getAdminSession(email);
    advance(30);
    const session = await authService.verifySessionToken(token);
    expect(await authService.refreshSessionToken(session)).toBeNull();
    expect(await getAdminSession(email)).toEqual(before);
  });

  it('writes lastActivity at most once a minute without changing the session id', async () => {
    const token = await authService.createSessionToken({ email, name: 'Admin' });
    const first = await getAdminSession(email);
    advance(61);
    const session = await authService.verifySessionToken(token);
    const refreshed = await authService.refreshSessionToken(session);
    expect(refreshed).not.toBeNull();
    const touched = await getAdminSession(email);
    expect(touched!.sid).toBe(first!.sid);
    expect(touched!.lastActivity).toBe(first!.lastActivity + 61);
    expect((jwt.decode(refreshed!.token) as jwt.JwtPayload).sid).toBe(first!.sid);

    advance(10);
    const again = await authService.verifySessionToken(refreshed!.token);
    expect(await authService.refreshSessionToken(again)).toBeNull();
    expect((await getAdminSession(email))!.lastActivity).toBe(touched!.lastActivity);
  });

  it('enforces the idle limit from the last written activity', async () => {
    const token = await authService.createSessionToken({ email, name: 'Admin' });
    advance(61);
    const session = await authService.verifySessionToken(token);
    const refreshed = await authService.refreshSessionToken(session);
    advance(14 * 60);
    await expect(authService.verifySessionToken(refreshed!.token)).resolves.toMatchObject({ email });
    advance(2 * 60);
    await expect(authService.verifySessionToken(refreshed!.token)).rejects.toThrow('Session idle timeout');
  });

  it('rotates only after the session id is 5 minutes old', async () => {
    const token = await authService.createSessionToken({ email, name: 'Admin' });
    const first = await getAdminSession(email);
    advance(SESSION_ROTATE_AFTER_SECONDS - 1);
    const young = await authService.verifySessionToken(token);
    const stillYoung = await authService.refreshSessionToken(young);
    expect((await getAdminSession(email))!.sid).toBe(first!.sid);
    expect(stillYoung).not.toBeNull();

    advance(2);
    const due = await authService.verifySessionToken(stillYoung!.token);
    const rotated = await authService.refreshSessionToken(due);
    const record = await getAdminSession(email);
    expect(record!.sid).not.toBe(first!.sid);
    expect(record!.previousSid).toBe(first!.sid);
    expect(record!.previousSidUntil).toBeGreaterThanOrEqual(Date.now() + SESSION_ROTATION_GRACE_MS - 1000);
    expect(rotated!.maxAgeMs).toBe(15 * 60 * 1000);
    expect((jwt.decode(rotated!.token) as jwt.JwtPayload).sid).toBe(record!.sid);
  });

  it('accepts the previous id after a long request, within the grace period', async () => {
    const original = await authService.createSessionToken({ email, name: 'Admin' });

    // A long audit starts with the original cookie and rotates the id.
    advance(6 * 60);
    const longRequest = await authService.verifySessionToken(original);
    const replacement = await authService.refreshSessionToken(longRequest);
    expect(replacement).not.toBeNull();

    // The audit runs for 5 minutes. The browser still holds the original cookie.
    advance(5 * 60);
    const next = await authService.verifySessionToken(original);
    expect(next.email).toBe(email);
    expect(next.sid).not.toBe(next.currentSid);

    // The follow-up response moves the browser to the current id without a new rotation.
    const moved = await authService.refreshSessionToken(next);
    expect((jwt.decode(moved!.token) as jwt.JwtPayload).sid).toBe(next.currentSid);
    await expect(authService.verifySessionToken(moved!.token)).resolves.toMatchObject({ email });
  });

  it('rejects the previous id once the grace period ends', async () => {
    const original = await authService.createSessionToken({ email, name: 'Admin' });
    advance(6 * 60);
    await authService.refreshSessionToken(await authService.verifySessionToken(original));
    const record = await getAdminSession(email);
    await saveAdminSession({ ...record!, previousSidUntil: Date.now() - 1 });
    await expect(authService.verifySessionToken(original)).rejects.toThrow('Session revoked');
  });

  it('does not rotate twice when two requests race on the same id', async () => {
    const token = await authService.createSessionToken({ email, name: 'Admin' });
    advance(6 * 60);
    const [a, b] = await Promise.all([
      authService.verifySessionToken(token),
      authService.verifySessionToken(token),
    ]);
    const [first, second] = await Promise.all([
      authService.refreshSessionToken(a),
      authService.refreshSessionToken(b),
    ]);
    const record = await getAdminSession(email);
    const sids = [first, second].map((r) => (jwt.decode(r!.token) as jwt.JwtPayload).sid);
    expect(sids[0]).toBe(record!.sid);
    expect(sids[1]).toBe(record!.sid);
  });

  it('keeps the request when storage fails during refresh', async () => {
    const token = await authService.createSessionToken({ email, name: 'Admin' });
    advance(6 * 60);
    const session = await authService.verifySessionToken(token);
    const store = jest.requireActual('../src/services/securityAuditStore');
    jest.spyOn(store, 'updateAdminSession').mockRejectedValue(Object.assign(new Error('boom'), { code: 503 }));
    jest.spyOn(console, 'error').mockImplementation(() => undefined);
    await expect(authService.refreshSessionToken(session)).resolves.toBeNull();
  });
});
