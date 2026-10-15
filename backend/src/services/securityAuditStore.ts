import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

/**
 * Durable storage for Security Audit last-run results and org-level waivers.
 *
 * JSON objects in GCS when `CHECKLIST_BUCKET` is set, local disk under
 * `backend/data/` otherwise.
 *
 * Layout:
 *   security-checklist/latest.json   — most recent completed snapshot
 *   security-checklist/waivers.json  — durable check waivers (outlive individual runs)
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface PolicyApiMeta {
  available: boolean;
  /** Short machine-friendly code when unavailable, e.g. "http_403". */
  code?: string;
  /** Human-readable explanation — never a raw Google JSON body. */
  message?: string;
  /** Plain-language notes shown in a banner, e.g. a cut-off policy list. */
  warnings?: string[];
  /** True when the policy list was cut off, so some policies may be missing. */
  partial?: boolean;
}

export interface HardeningStatistics {
  total: number;
  pass: number;
  warning: number;
  fail: number;
  manual: number;
  info: number;
  /**
   * Severity-weighted pass rate, 0-100, over graded checks. Null when nothing
   * was graded. Absent on snapshots saved before scoring existed.
   */
  score?: number | null;
}

/** Serialized check shape (matches hardening.service HardeningCheck). */
export interface StoredHardeningCheck {
  id: string;
  category: string;
  name: string;
  description: string;
  status: 'pass' | 'warning' | 'fail' | 'manual' | 'info';
  source: 'auto' | 'manual';
  severity: Severity;
  currentValue?: unknown;
  recommendedValue?: unknown;
  rationale: string;
  recommendation: string;
  adminConsoleUrl?: string;
  issues?: string[];
}

/** Full snapshot written after each successful Run. */
export interface SecurityAuditReport {
  ranAt: string;
  triggeredBy: string;
  durationMs: number;
  checks: StoredHardeningCheck[];
  statistics: HardeningStatistics;
  policyApi: PolicyApiMeta;
}

export interface WaiverEntry {
  reason: string;
  waivedBy: string;
  waivedAt: string;
}

/** Map of checkId → waiver. Unknown check IDs are retained (orphans). */
export type WaiversMap = Record<string, WaiverEntry>;

const BUCKET_NAME = process.env.CHECKLIST_BUCKET || '';
const PREFIX = process.env.SECURITY_CHECKLIST_PREFIX || 'security-checklist';
const LATEST_OBJECT = `${PREFIX}/latest.json`;
const WAIVERS_OBJECT = `${PREFIX}/waivers.json`;

const DATA_DIR = path.join(__dirname, '..', '..', 'data', 'security-checklist');

let storageBucket: any = null;
async function getBucket(): Promise<any | null> {
  if (!BUCKET_NAME) return null;
  if (!storageBucket) {
    const { Storage } = await import('@google-cloud/storage');
    storageBucket = new Storage().bucket(BUCKET_NAME);
  }
  return storageBucket;
}

function localPath(object: string): string {
  return path.join(DATA_DIR, object.replace(`${PREFIX}/`, ''));
}

/** Serialize local read-modify-write. GCS uses generation preconditions instead. */
const localWriteChains = new Map<string, Promise<void>>();

function withLocalLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const previous = localWriteChains.get(key) ?? Promise.resolve();
  const run = previous.then(fn, fn);
  localWriteChains.set(
    key,
    run.then(
      () => undefined,
      () => undefined
    )
  );
  return run;
}

function httpStatus(error: unknown): number | undefined {
  const err = error as { code?: number | string; status?: number };
  const candidate = err?.code ?? err?.status;
  const parsed = typeof candidate === 'string' ? parseInt(candidate, 10) : candidate;
  return typeof parsed === 'number' && Number.isFinite(parsed) ? parsed : undefined;
}

function isNotFound(error: unknown): boolean {
  return httpStatus(error) === 404;
}

function isPreconditionFailed(error: unknown): boolean {
  return httpStatus(error) === 412;
}

function writeLocalFile(object: string, payload: string): void {
  const filePath = localPath(object);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tmp = `${filePath}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, payload, 'utf-8');
  fs.renameSync(tmp, filePath);
}

async function deleteObject(object: string): Promise<void> {
  const bucket = await getBucket();
  if (bucket) {
    try {
      await bucket.file(object).delete();
    } catch (error) {
      if (isNotFound(error)) return;
      throw error;
    }
    return;
  }
  try {
    fs.unlinkSync(localPath(object));
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code !== 'ENOENT') throw error;
  }
}

async function writeObject(object: string, payload: string): Promise<void> {
  const bucket = await getBucket();
  if (bucket) {
    await bucket.file(object).save(payload, {
      contentType: 'application/json',
      resumable: false,
    });
    return;
  }
  writeLocalFile(object, payload);
}

async function readObject(object: string): Promise<string | null> {
  const loaded = await readObjectWithGeneration(object);
  return loaded.raw;
}

/**
 * Body plus the GCS generation that produced it. generation 0 means the
 * object is absent, which matches ifGenerationMatch: 0 (create-if-absent).
 */
async function readObjectWithGeneration(
  object: string
): Promise<{ raw: string | null; generation: number }> {
  const bucket = await getBucket();
  if (!bucket) {
    try {
      return { raw: fs.readFileSync(localPath(object), 'utf-8'), generation: 1 };
    } catch {
      return { raw: null, generation: 0 };
    }
  }

  const file = bucket.file(object);
  try {
    const downloaded = await new Promise<{ raw: string; generation: number }>((resolve, reject) => {
      const chunks: Buffer[] = [];
      let generation = 0;
      const stream = file.createReadStream();
      stream.on('response', (res: { headers?: Record<string, string | string[] | undefined> }) => {
        const header = res.headers?.['x-goog-generation'];
        const value = Array.isArray(header) ? header[0] : header;
        const parsed = Number(value);
        if (Number.isFinite(parsed) && parsed > 0) generation = parsed;
      });
      stream.on('error', reject);
      stream.on('data', (chunk: Buffer) => chunks.push(chunk));
      stream.on('end', () => {
        if (!generation) {
          reject(new Error(`GCS download for ${object} did not include an object generation`));
          return;
        }
        resolve({ raw: Buffer.concat(chunks).toString('utf-8'), generation });
      });
    });
    return downloaded;
  } catch (error) {
    if (isNotFound(error)) return { raw: null, generation: 0 };
    throw error;
  }
}

async function writeObjectConditional(
  object: string,
  payload: string,
  generation: number
): Promise<void> {
  const bucket = await getBucket();
  if (!bucket) {
    writeLocalFile(object, payload);
    return;
  }
  await bucket.file(object).save(payload, {
    contentType: 'application/json',
    resumable: false,
    preconditionOpts: { ifGenerationMatch: generation },
  });
}

function parse<T>(raw: string | null): T | null {
  if (raw == null) return null;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

export async function putLatest(report: SecurityAuditReport): Promise<void> {
  await writeObject(LATEST_OBJECT, JSON.stringify(report));
}

export async function getLatest(): Promise<SecurityAuditReport | null> {
  const parsed = parse<SecurityAuditReport>(await readObject(LATEST_OBJECT));
  if (!parsed || !Array.isArray(parsed.checks)) return null;
  return parsed;
}

function normalizeWaivers(parsed: WaiversMap | null): WaiversMap {
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
  const out: WaiversMap = {};
  for (const [id, entry] of Object.entries(parsed)) {
    if (!id || typeof id !== 'string') continue;
    if (!entry || typeof entry !== 'object') continue;
    const reason = typeof entry.reason === 'string' ? entry.reason : '';
    const waivedBy = typeof entry.waivedBy === 'string' ? entry.waivedBy : '';
    const waivedAt =
      typeof entry.waivedAt === 'string' ? entry.waivedAt : new Date(0).toISOString();
    out[id] = { reason, waivedBy, waivedAt };
  }
  return out;
}

export async function getWaivers(): Promise<WaiversMap> {
  return normalizeWaivers(parse<WaiversMap>(await readObject(WAIVERS_OBJECT)));
}

export async function putWaivers(waivers: WaiversMap): Promise<void> {
  const write = () => writeObject(WAIVERS_OBJECT, JSON.stringify(waivers));
  if (!BUCKET_NAME) return withLocalLock(WAIVERS_OBJECT, write);
  await write();
}

/**
 * Read-modify-write waivers. Local disk is serialized in-process. GCS uses
 * ifGenerationMatch and retries when another writer won the race.
 */
async function mutateWaivers(mutate: (current: WaiversMap) => WaiversMap): Promise<WaiversMap> {
  const once = async (): Promise<WaiversMap> => {
    const { raw, generation } = await readObjectWithGeneration(WAIVERS_OBJECT);
    const next = mutate(normalizeWaivers(parse<WaiversMap>(raw)));
    await writeObjectConditional(WAIVERS_OBJECT, JSON.stringify(next), generation);
    return next;
  };

  const run = async (): Promise<WaiversMap> => {
    const bucket = await getBucket();
    const maxAttempts = bucket ? 5 : 1;
    let lastError: unknown;
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        return await once();
      } catch (error) {
        lastError = error;
        if (!bucket || !isPreconditionFailed(error) || attempt === maxAttempts - 1) throw error;
      }
    }
    throw lastError instanceof Error ? lastError : new Error('Waiver update conflicted');
  };

  if (!BUCKET_NAME) return withLocalLock(WAIVERS_OBJECT, run);
  return run();
}

export async function setWaiver(
  checkId: string,
  reason: string,
  waivedBy: string
): Promise<WaiversMap> {
  return mutateWaivers((current) => ({
    ...current,
    [checkId]: {
      reason: reason.trim(),
      waivedBy,
      waivedAt: new Date().toISOString(),
    },
  }));
}

export async function removeWaiver(checkId: string): Promise<WaiversMap> {
  return mutateWaivers((current) => {
    if (!(checkId in current)) return current;
    const next = { ...current };
    delete next[checkId];
    return next;
  });
}

/** Merge a full map (used for browser→cloud one-time import). */
export async function mergeWaivers(
  incoming: Record<string, string>,
  waivedBy: string
): Promise<WaiversMap> {
  const now = new Date().toISOString();
  return mutateWaivers((current) => {
    const next = { ...current };
    for (const [id, reason] of Object.entries(incoming)) {
      if (!id || typeof id !== 'string') continue;
      if (id in next) continue; // never overwrite an existing org waiver
      next[id] = {
        reason: typeof reason === 'string' ? reason.trim() : '',
        waivedBy,
        waivedAt: now,
      };
    }
    return next;
  });
}

/**
 * One active sign-in per admin. A replaced session id stays valid for a grace
 * period. Times in seconds except previousSidUntil (milliseconds).
 * lastActivity moves at most once a minute, so idle checks have that resolution.
 */
export interface AdminSessionRecord {
  sid: string;
  /** When `sid` was issued. Drives timed rotation. */
  sidIssuedAt: number;
  previousSid?: string;
  previousSidUntil?: number;
  email: string;
  name: string;
  picture?: string;
  /** OpenID Connect subject from the ID token used to sign in. */
  sub?: string;
  authTime: number;
  lastActivity: number;
}

function sessionObject(email: string): string {
  const hash = crypto.createHash('sha256').update(email.trim().toLowerCase()).digest('hex');
  return `${PREFIX}/sessions/${hash}.json`;
}

function normalizeSession(parsed: AdminSessionRecord | null): AdminSessionRecord | null {
  if (!parsed || typeof parsed !== 'object') return null;
  if (typeof parsed.sid !== 'string' || !parsed.sid) return null;
  if (typeof parsed.email !== 'string' || !parsed.email) return null;
  if (typeof parsed.name !== 'string') return null;
  if (typeof parsed.authTime !== 'number' || typeof parsed.lastActivity !== 'number') return null;
  return {
    sid: parsed.sid,
    sidIssuedAt: typeof parsed.sidIssuedAt === 'number' ? parsed.sidIssuedAt : parsed.authTime,
    previousSid: typeof parsed.previousSid === 'string' ? parsed.previousSid : undefined,
    previousSidUntil: typeof parsed.previousSidUntil === 'number' ? parsed.previousSidUntil : undefined,
    email: parsed.email,
    name: parsed.name,
    picture: typeof parsed.picture === 'string' ? parsed.picture : undefined,
    sub: typeof parsed.sub === 'string' ? parsed.sub : undefined,
    authTime: parsed.authTime,
    lastActivity: parsed.lastActivity,
  };
}

export async function getAdminSession(email: string): Promise<AdminSessionRecord | null> {
  return normalizeSession(parse<AdminSessionRecord>(await readObject(sessionObject(email))));
}

/** New sign-in. Replaces whatever session that admin had. */
export async function saveAdminSession(record: AdminSessionRecord): Promise<void> {
  const object = sessionObject(record.email);
  const write = () => writeObject(object, JSON.stringify(record));
  if (!BUCKET_NAME) return withLocalLock(object, write);
  await write();
}

export async function deleteAdminSession(email: string): Promise<void> {
  const object = sessionObject(email);
  const remove = () => deleteObject(object);
  if (!BUCKET_NAME) return withLocalLock(object, remove);
  await remove();
}

function isRetryableSessionWrite(error: unknown): boolean {
  const status = httpStatus(error);
  return status === 412 || status === 429 || (status !== undefined && status >= 500);
}

/** Jittered exponential delay: 50-100 ms, then 100-200 ms, up to 2 s. */
function sessionRetryDelayMs(attempt: number): number {
  const ceiling = Math.min(2000, 100 * 2 ** attempt);
  return ceiling / 2 + Math.random() * (ceiling / 2);
}

/**
 * Read-modify-write one admin session. Local disk is serialized in-process.
 * GCS retries with backoff on a lost race (412), throttling (429), and 5xx.
 * Returning the `current` object from `mutate` skips the write.
 */
export async function updateAdminSession(
  email: string,
  mutate: (current: AdminSessionRecord | null) => AdminSessionRecord
): Promise<AdminSessionRecord> {
  const object = sessionObject(email);
  const once = async (): Promise<AdminSessionRecord> => {
    const { raw, generation } = await readObjectWithGeneration(object);
    const current = normalizeSession(parse<AdminSessionRecord>(raw));
    const next = mutate(current);
    if (next === current) return next;
    await writeObjectConditional(object, JSON.stringify(next), generation);
    return next;
  };

  const run = async (): Promise<AdminSessionRecord> => {
    const bucket = await getBucket();
    const maxAttempts = bucket ? 5 : 1;
    let lastError: unknown;
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        return await once();
      } catch (error) {
        lastError = error;
        if (!bucket || !isRetryableSessionWrite(error) || attempt === maxAttempts - 1) throw error;
        await new Promise((resolve) => setTimeout(resolve, sessionRetryDelayMs(attempt)));
      }
    }
    throw lastError instanceof Error ? lastError : new Error('Session update conflicted');
  };

  if (!BUCKET_NAME) return withLocalLock(object, run);
  return run();
}
