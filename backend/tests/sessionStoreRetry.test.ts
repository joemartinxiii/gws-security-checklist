import { PassThrough } from 'stream';

let currentBucket: unknown;

jest.mock('@google-cloud/storage', () => ({
  Storage: class {
    bucket() {
      return currentBucket;
    }
  },
}));

type StoreModule = typeof import('../src/services/securityAuditStore');

const record = {
  sid: 'sid-1',
  sidIssuedAt: 100,
  email: 'admin@example.com',
  name: 'Admin',
  authTime: 100,
  lastActivity: 100,
};

function loadStoreWithBucket(failures: unknown[]): { store: StoreModule; save: jest.Mock } {
  const save = jest.fn(async () => {
    const failure = failures.shift();
    if (failure) throw failure;
  });
  currentBucket = {
    file: () => ({
      createReadStream: () => {
        const stream = new PassThrough();
        setImmediate(() => {
          stream.emit('response', { headers: { 'x-goog-generation': '7' } });
          stream.end(JSON.stringify(record));
        });
        return stream;
      },
      save,
    }),
  };
  let store!: StoreModule;
  jest.isolateModules(() => {
    process.env.CHECKLIST_BUCKET = 'fake-bucket';
    store = require('../src/services/securityAuditStore');
  });
  return { store, save };
}

const status = (code: number) => Object.assign(new Error(`HTTP ${code}`), { code });

let delays: number[];

beforeEach(() => {
  delays = [];
  const realSetTimeout = global.setTimeout;
  jest.spyOn(global, 'setTimeout').mockImplementation(((fn: () => void, ms?: number) => {
    if (typeof ms === 'number' && ms >= 25) {
      delays.push(ms);
      return realSetTimeout(fn, 0);
    }
    return realSetTimeout(fn, ms);
  }) as typeof setTimeout);
});

afterEach(() => {
  delete process.env.CHECKLIST_BUCKET;
  jest.restoreAllMocks();
});

const touch = (current: typeof record | null) => ({ ...(current as typeof record), lastActivity: 200 });

describe('updateAdminSession retry', () => {
  test('retries 412, 429, and 5xx with growing jittered delays', async () => {
    const { store, save } = loadStoreWithBucket([status(412), status(429), status(503)]);
    const result = await store.updateAdminSession(record.email, touch as never);
    expect(result.lastActivity).toBe(200);
    expect(save).toHaveBeenCalledTimes(4);
    expect(delays).toHaveLength(3);
    expect(delays[0]).toBeGreaterThanOrEqual(50);
    expect(delays[0]).toBeLessThanOrEqual(100);
    expect(delays[1]).toBeGreaterThanOrEqual(100);
    expect(delays[1]).toBeLessThanOrEqual(200);
    expect(delays[2]).toBeGreaterThanOrEqual(200);
    expect(delays[2]).toBeLessThanOrEqual(400);
  });

  test('gives up after 5 attempts', async () => {
    const { store, save } = loadStoreWithBucket([1, 2, 3, 4, 5, 6].map(() => status(412)));
    await expect(store.updateAdminSession(record.email, touch as never)).rejects.toMatchObject({ code: 412 });
    expect(save).toHaveBeenCalledTimes(5);
  });

  test('does not retry other client errors', async () => {
    const { store, save } = loadStoreWithBucket([status(403)]);
    await expect(store.updateAdminSession(record.email, touch as never)).rejects.toMatchObject({ code: 403 });
    expect(save).toHaveBeenCalledTimes(1);
    expect(delays).toHaveLength(0);
  });

  test('skips the write when the update returns the current record', async () => {
    const { store, save } = loadStoreWithBucket([]);
    await store.updateAdminSession(record.email, ((current: unknown) => current) as never);
    expect(save).not.toHaveBeenCalled();
  });
});
