import { PermissionsService } from '../src/services/permissions.service';

function makeService(get: jest.Mock): PermissionsService {
  const service = new PermissionsService();
  jest.spyOn(service as any, 'adminFor').mockResolvedValue({ users: { get } });
  return service;
}

const superAdminUser = {
  data: { id: '1', primaryEmail: 'admin@example.com', isAdmin: true, isDelegatedAdmin: false },
};

afterEach(() => {
  jest.restoreAllMocks();
  jest.useRealTimers();
});

describe('getAdminRoles', () => {
  test('returns the Directory role with id and primary email', async () => {
    const get = jest.fn().mockResolvedValue(superAdminUser);
    const role = await makeService(get).getAdminRoles('admin@example.com');
    expect(role).toMatchObject({
      isSuperAdmin: true,
      isDelegatedAdmin: false,
      id: '1',
      primaryEmail: 'admin@example.com',
    });
  });

  test.each([
    ['response status', { response: { status: 403 }, message: 'Not Authorized to access this resource/api' }],
    ['numeric code', Object.assign(new Error('Not Authorized to access this resource/api'), { code: 403 })],
  ])('maps a 403 from users.get (%s) to a non-admin', async (_label, error) => {
    const get = jest.fn().mockRejectedValue(error);
    const role = await makeService(get).getAdminRoles('user@example.com');
    expect(role).toEqual({ isSuperAdmin: false, isDelegatedAdmin: false });
    expect(get).toHaveBeenCalledTimes(1);
  });

  test('keeps other Directory errors as errors', async () => {
    jest.spyOn(console, 'error').mockImplementation(() => undefined);
    const get = jest.fn().mockRejectedValue(Object.assign(new Error('bad request'), { code: 400 }));
    await expect(makeService(get).getAdminRoles('user@example.com')).rejects.toThrow(/Failed to fetch admin roles/);
  });

  test('a 403 while minting the delegated token is still a configuration error', async () => {
    const service = new PermissionsService();
    jest
      .spyOn(service as any, 'adminFor')
      .mockRejectedValue(new Error('Delegated token exchange failed (403): insufficient permission'));
    await expect(service.getAdminRoles('user@example.com')).rejects.toThrow(/Domain-wide delegation/);
  });

  test('caches roles for 2 minutes by lowercase email', async () => {
    jest.useFakeTimers({ now: new Date('2026-01-01T00:00:00Z') });
    const get = jest.fn().mockResolvedValue(superAdminUser);
    const service = makeService(get);
    await service.getAdminRoles('Admin@Example.com');
    await service.getAdminRoles('admin@example.com');
    expect(get).toHaveBeenCalledTimes(1);
    jest.setSystemTime(new Date('2026-01-01T00:01:59Z'));
    await service.getAdminRoles('admin@example.com');
    expect(get).toHaveBeenCalledTimes(1);
    jest.setSystemTime(new Date('2026-01-01T00:02:01Z'));
    await service.getAdminRoles('admin@example.com');
    expect(get).toHaveBeenCalledTimes(2);
  });

  test('caches negative results', async () => {
    const get = jest.fn().mockRejectedValue({ response: { status: 403 }, message: 'Not Authorized' });
    const service = makeService(get);
    await service.getAdminRoles('user@example.com');
    await service.getAdminRoles('user@example.com');
    expect(get).toHaveBeenCalledTimes(1);
  });

  test('never caches errors', async () => {
    jest.spyOn(console, 'error').mockImplementation(() => undefined);
    const get = jest
      .fn()
      .mockRejectedValueOnce(Object.assign(new Error('bad request'), { code: 400 }))
      .mockResolvedValueOnce(superAdminUser);
    const service = makeService(get);
    await expect(service.getAdminRoles('admin@example.com')).rejects.toThrow();
    await expect(service.getAdminRoles('admin@example.com')).resolves.toMatchObject({ isSuperAdmin: true });
    expect(get).toHaveBeenCalledTimes(2);
  });

  test('fresh skips the cache and refreshes it', async () => {
    const get = jest
      .fn()
      .mockResolvedValueOnce({ data: { id: '1', primaryEmail: 'a@example.com', isAdmin: false } })
      .mockResolvedValueOnce(superAdminUser);
    const service = makeService(get);
    expect((await service.getAdminRoles('a@example.com')).isSuperAdmin).toBe(false);
    expect((await service.getAdminRoles('a@example.com', { fresh: true })).isSuperAdmin).toBe(true);
    expect((await service.getAdminRoles('a@example.com')).isSuperAdmin).toBe(true);
    expect(get).toHaveBeenCalledTimes(2);
  });
});
