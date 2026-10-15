import { validateEnvironment, findEnvironmentProblems } from '../src/utils/env.validation';
import { errorHandler } from '../src/middleware/error.middleware';

const ORIGINAL_ENV = { ...process.env };

const productionEnv = {
  NODE_ENV: 'production',
  JWT_SECRET: 'a'.repeat(40),
  GCP_PROJECT_ID: 'proj-1',
  WORKSPACE_DOMAIN: 'example.com',
  GOOGLE_CLIENT_ID: 'client-id',
  GOOGLE_CLIENT_SECRET: 'client-secret',
  GOOGLE_REDIRECT_URI: 'https://checklist.example.com/api/auth/callback',
  CHECKLIST_BUCKET: 'checklist-bucket',
};

function setEnv(env: Record<string, string | undefined>): void {
  process.env = { ...ORIGINAL_ENV };
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

afterEach(() => {
  process.env = { ...ORIGINAL_ENV };
  jest.restoreAllMocks();
});

describe('production environment validation', () => {
  function run(): number | undefined {
    jest.spyOn(console, 'error').mockImplementation(() => undefined);
    jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    jest.spyOn(console, 'log').mockImplementation(() => undefined);
    const exit = jest.spyOn(process, 'exit').mockImplementation((() => undefined) as never);
    validateEnvironment();
    return exit.mock.calls[0]?.[0] as number | undefined;
  }

  test('passes with a complete production configuration', () => {
    setEnv(productionEnv);
    expect(findEnvironmentProblems()).toEqual({ missing: [], invalid: [] });
    expect(run()).toBeUndefined();
  });

  test('fails startup when CHECKLIST_BUCKET is missing', () => {
    setEnv({ ...productionEnv, CHECKLIST_BUCKET: undefined });
    expect(findEnvironmentProblems().missing).toContain('CHECKLIST_BUCKET');
    expect(run()).toBe(1);
  });

  test('fails startup when CHECKLIST_BUCKET is blank', () => {
    setEnv({ ...productionEnv, CHECKLIST_BUCKET: '  ' });
    expect(run()).toBe(1);
  });

  test('fails startup when JWT_SECRET is shorter than 32 characters', () => {
    setEnv({ ...productionEnv, JWT_SECRET: 'a'.repeat(31) });
    expect(findEnvironmentProblems().invalid.join(' ')).toMatch(/JWT_SECRET/);
    expect(run()).toBe(1);
  });

  test('accepts a 32 character JWT_SECRET', () => {
    setEnv({ ...productionEnv, JWT_SECRET: 'a'.repeat(32) });
    expect(run()).toBeUndefined();
  });

  test.each(['WORKSPACE_DOMAIN', 'GCP_PROJECT_ID', 'GOOGLE_CLIENT_ID', 'CHECKLIST_BUCKET', 'JWT_SECRET'])(
    'fails startup when %s contains PLACEHOLDER in any case',
    (key) => {
      setEnv({ ...productionEnv, [key]: `${'a'.repeat(32)}-placeHolder` });
      expect(findEnvironmentProblems().invalid.join(' ')).toContain(key);
      expect(run()).toBe(1);
    }
  );

  test('does not apply the production rules outside production', () => {
    setEnv({
      NODE_ENV: 'development',
      JWT_SECRET: 'short',
      GCP_PROJECT_ID: 'PLACEHOLDER',
      WORKSPACE_DOMAIN: 'example.com',
    });
    expect(findEnvironmentProblems()).toEqual({ missing: [], invalid: [] });
    expect(run()).toBeUndefined();
  });
});

describe('error handler', () => {
  function respond(status: number, message: string, nodeEnv: string) {
    process.env.NODE_ENV = nodeEnv;
    jest.spyOn(console, 'error').mockImplementation(() => undefined);
    const err = Object.assign(new Error(message), { statusCode: status });
    const json = jest.fn();
    const res = { status: jest.fn().mockReturnThis(), json } as any;
    errorHandler(err, { path: '/x', method: 'GET' } as any, res, jest.fn());
    return { body: json.mock.calls[0][0], err };
  }

  test('production responses carry no stack trace, and server errors are generic', () => {
    const { body, err } = respond(500, 'database password leaked', 'production');
    expect(body.stack).toBeUndefined();
    expect(JSON.stringify(body)).not.toContain(err.stack!.split('\n')[1].trim());
    expect(body.error).toBe('An unexpected error occurred');
  });

  test('production logs omit the stack trace', () => {
    process.env.NODE_ENV = 'production';
    const spy = jest.spyOn(console, 'error').mockImplementation(() => undefined);
    errorHandler(new Error('boom'), { path: '/x', method: 'GET' } as any, { status: () => ({ json: () => undefined }) } as any, jest.fn());
    expect(JSON.stringify(spy.mock.calls)).not.toContain('stack');
  });

  test('development responses still include the stack', () => {
    const { body } = respond(500, 'boom', 'development');
    expect(typeof body.stack).toBe('string');
  });
});
