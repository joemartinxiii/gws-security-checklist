import { google } from 'googleapis';
import { getAuthUrl, getOAuth2Client } from '../src/config/google.config';
import { authService } from '../src/services/auth.service';

describe('getOAuth2Client', () => {
  test('returns a new client so concurrent logins do not share credentials', () => {
    const first = getOAuth2Client();
    const second = getOAuth2Client();
    expect(first).not.toBe(second);
    first.setCredentials({ access_token: 'user-a' });
    expect(second.credentials.access_token).toBeUndefined();
  });
});

describe('getAuthUrl', () => {
  test('adds an S256 code challenge when given one', () => {
    const url = new URL(getAuthUrl('state-1', 'challenge-1'));
    expect(url.searchParams.get('code_challenge')).toBe('challenge-1');
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('state')).toBe('state-1');
  });
});

describe('authService token handling', () => {
  beforeEach(() => {
    process.env.GOOGLE_CLIENT_ID = 'client-id.apps.googleusercontent.com';
  });

  afterEach(() => {
    jest.restoreAllMocks();
    delete process.env.GOOGLE_CLIENT_ID;
  });

  test('passes the PKCE verifier on the token exchange', async () => {
    const getToken = jest
      .spyOn(google.auth.OAuth2.prototype, 'getToken')
      .mockResolvedValue({ tokens: { access_token: 'at', id_token: 'idt' } } as never);
    const tokens = await authService.exchangeCodeForTokens('the-code', 'the-verifier');
    expect(getToken).toHaveBeenCalledWith({ code: 'the-code', codeVerifier: 'the-verifier' });
    expect(tokens.idToken).toBe('idt');
  });

  test('verifies the ID token against our client ID and returns the claims', async () => {
    const verify = jest.spyOn(google.auth.OAuth2.prototype, 'verifyIdToken').mockResolvedValue({
      getPayload: () => ({
        sub: 's1',
        email: 'a@example.com',
        email_verified: true,
        hd: 'example.com',
        name: 'A',
      }),
    } as never);
    await expect(authService.verifyIdToken('idt')).resolves.toMatchObject({
      sub: 's1',
      email: 'a@example.com',
      emailVerified: true,
      hd: 'example.com',
    });
    expect(verify).toHaveBeenCalledWith({ idToken: 'idt', audience: 'client-id.apps.googleusercontent.com' });
  });

  test('treats anything but email_verified === true as unverified', async () => {
    jest.spyOn(google.auth.OAuth2.prototype, 'verifyIdToken').mockResolvedValue({
      getPayload: () => ({ sub: 's1', email: 'a@example.com', email_verified: 'true' }),
    } as never);
    await expect(authService.verifyIdToken('idt')).resolves.toMatchObject({ emailVerified: false });
  });

  test('fails when the client ID is not configured', async () => {
    delete process.env.GOOGLE_CLIENT_ID;
    await expect(authService.verifyIdToken('idt')).rejects.toThrow(/GOOGLE_CLIENT_ID/);
  });

  test('propagates a verification failure', async () => {
    jest.spyOn(google.auth.OAuth2.prototype, 'verifyIdToken').mockRejectedValue(new Error('Wrong recipient') as never);
    await expect(authService.verifyIdToken('idt')).rejects.toThrow('Wrong recipient');
  });
});
