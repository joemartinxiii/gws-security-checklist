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
}

export interface HardeningStatistics {
  total: number;
  pass: number;
  warning: number;
  fail: number;
  manual: number;
  info: number;
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
