export type ScoreCheck = {
  id: string;
  status: 'pass' | 'warning' | 'fail' | 'manual' | 'info';
  severity?: 'critical' | 'high' | 'medium' | 'low';
};

export type ScoreStatistics = { score?: number | null };

export type ChecklistScore = {
  /** 0-100 */
  value: number;
  /** True when the value is weighted by severity, false for the plain pass rate. */
  weighted: boolean;
};

const SEVERITY_WEIGHT = { critical: 4, high: 3, medium: 2, low: 1 } as const;

export function weightedScore(checks: ScoreCheck[]): number | null {
  let earned = 0;
  let possible = 0;
  for (const check of checks) {
    if (check.status !== 'pass' && check.status !== 'warning' && check.status !== 'fail') continue;
    const weight = SEVERITY_WEIGHT[check.severity ?? 'medium'] ?? SEVERITY_WEIGHT.medium;
    possible += weight;
    if (check.status === 'pass') earned += weight;
    else if (check.status === 'warning') earned += weight / 2;
  }
  return possible === 0 ? null : Math.round((earned / possible) * 100);
}

function passRate(checks: ScoreCheck[]): number {
  const pass = checks.filter((c) => c.status === 'pass').length;
  const graded = pass + checks.filter((c) => c.status === 'warning' || c.status === 'fail').length;
  return graded === 0 ? 0 : Math.round((pass / graded) * 100);
}

/**
 * Headline score for the checks that are not waived. Uses the backend's severity-weighted
 * `statistics.score` when it is present. Waived checks change the inputs, so that case is
 * recomputed here with the same weights. Without a backend score it falls back to the plain
 * pass rate.
 */
export function computeChecklistScore(
  activeChecks: ScoreCheck[],
  statistics: ScoreStatistics | undefined,
  waivedCount: number
): ChecklistScore {
  const serverScore = statistics?.score;
  if (typeof serverScore !== 'number' || !Number.isFinite(serverScore)) {
    return { value: passRate(activeChecks), weighted: false };
  }
  if (waivedCount === 0) {
    return { value: Math.round(serverScore), weighted: true };
  }
  return { value: weightedScore(activeChecks) ?? 0, weighted: true };
}

export const WEIGHTED_SCORE_LABEL = 'Score (weighted by severity)';
export const WEIGHTED_SCORE_NOTE =
  'Weighted by severity (critical 4, high 3, medium 2, low 1). Warnings count half. Info and manual checks are excluded.';
export const PLAIN_SCORE_NOTE = 'Graded checks only. Info and manual checks are excluded from the score.';
