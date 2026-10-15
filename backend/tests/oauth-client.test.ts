import { getOAuth2Client } from '../src/config/google.config';

describe('getOAuth2Client', () => {
  test('returns a new client so concurrent logins do not share credentials', () => {
    const first = getOAuth2Client();
    const second = getOAuth2Client();
    expect(first).not.toBe(second);
    first.setCredentials({ access_token: 'user-a' });
    expect(second.credentials.access_token).toBeUndefined();
  });
});
