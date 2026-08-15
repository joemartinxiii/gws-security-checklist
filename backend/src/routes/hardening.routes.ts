import { Router, Response } from 'express';
import { authenticateSession, AuthRequest } from '../middleware/auth.middleware';
import { requireAnyAdmin, requireSuperAdmin } from '../middleware/permissions.middleware';
import {
  hardeningService,
  isTransientPolicyFailure,
} from '../services/hardening.service';
import {
  getLatest as getSecurityAuditLatest,
  getWaivers as getSecurityAuditWaivers,
  putLatest as putSecurityAuditLatest,
  setWaiver as setSecurityAuditWaiver,
  removeWaiver as removeSecurityAuditWaiver,
  mergeWaivers as mergeSecurityAuditWaivers,
  SecurityAuditReport,
  WaiversMap,
} from '../services/securityAuditStore';
import { driveExportService } from '../services/driveExport.service';
import { convertToCSV } from '../utils/csv';
import { sendApiError } from '../utils/apiError';

const router = Router();

router.use(authenticateSession);

// ---------------------------------------------------------------------------
// Security Audit (hardening) — cloud last-run + durable waivers
// ---------------------------------------------------------------------------

function buildHardeningPayload(report: SecurityAuditReport | null, waivers: WaiversMap) {
  if (!report) {
    return {
      status: 'never-run' as const,
      ranAt: null,
      triggeredBy: null,
      durationMs: null,
      checks: [] as SecurityAuditReport['checks'],
      statistics: { total: 0, pass: 0, warning: 0, fail: 0, manual: 0, info: 0 },
      policyApi: { available: true },
      waivers,
    };
  }
  return {
    status: 'ready' as const,
    ranAt: report.ranAt,
    triggeredBy: report.triggeredBy,
    durationMs: report.durationMs,
    checks: report.checks,
    statistics: report.statistics,
    policyApi: report.policyApi,
    waivers,
  };
}

function hardeningRowsForExport(report: SecurityAuditReport, waivers: WaiversMap) {
  return report.checks.map((check) => {
    const waiver = waivers[check.id];
    return {
      Category: check.category,
      Name: check.name,
      Description: check.description,
      Severity: (check.severity || 'medium').toUpperCase(),
      Status: check.status.toUpperCase(),
      Waived: waiver ? 'Yes' : 'No',
      'Waive Reason': waiver?.reason || '',
      'Current Value': check.currentValue != null ? String(check.currentValue) : '',
      'Recommended Value': check.recommendedValue != null ? String(check.recommendedValue) : '',
      Rationale: check.rationale || '',
      Recommendation: check.recommendation || '',
      'Admin Console URL': check.adminConsoleUrl || '',
    };
  });
}

/**
 * GET /api/audit/hardening
 * Cached last-run + durable waivers (does not re-evaluate policies).
 * Alias of /hardening/latest for backwards compatibility with live tests / clients.
 */
router.get('/hardening', requireAnyAdmin, async (_req: AuthRequest, res: Response) => {
  try {
    const [report, waivers] = await Promise.all([getSecurityAuditLatest(), getSecurityAuditWaivers()]);
    res.json(buildHardeningPayload(report, waivers));
  } catch (error: any) {
    sendApiError(res, error, 'Failed to load security audit', 'audit.hardening');
  }
});

/**
 * GET /api/audit/hardening/latest
 * Explicit latest snapshot endpoint (same payload as GET /hardening).
 */
router.get('/hardening/latest', requireAnyAdmin, async (_req: AuthRequest, res: Response) => {
  try {
    const [report, waivers] = await Promise.all([getSecurityAuditLatest(), getSecurityAuditWaivers()]);
    res.json(buildHardeningPayload(report, waivers));
  } catch (error: any) {
    sendApiError(res, error, 'Failed to load security audit', 'audit.hardening.latest');
  }
});

/**
 * POST /api/audit/hardening/run
 * Sync re-evaluate all checks, persist latest.json, return snapshot + waivers.
 * Super admin only (Policy API requires super-admin subject).
 *
 * Preflight: load Cloud Identity Policy API first. On transient failure (429/503
 * after retries), abort without writing a degraded mostly-manual snapshot so the
 * org keeps its last good run and the admin does not see a "failed" score.
 * Permanent config issues (403/401) still proceed with manual fallbacks.
 */
router.post('/hardening/run', requireSuperAdmin, async (req: AuthRequest, res: Response) => {
  try {
    const domain = process.env.WORKSPACE_DOMAIN || req.user!.email.split('@')[1];
    const started = Date.now();

    const { snapshot, policyApi } = await hardeningService.preflightPolicyApi(req.user!.email);

    if (isTransientPolicyFailure(policyApi)) {
      const [previous, waivers] = await Promise.all([
        getSecurityAuditLatest(),
        getSecurityAuditWaivers(),
      ]);
      const message =
        policyApi.message ||
        'Google Policy API is temporarily unavailable. Previous audit results were left unchanged.';
      return res.status(503).json({
        error: previous
          ? `${message} Your last saved audit is still on file — try Run again in a minute.`
          : `${message} No prior audit was saved; try Run again in a minute.`,
        code: 'policy_api_rate_limited',
        retryable: true,
        policyApi,
        // Preserve last good snapshot for clients that want to re-bind state.
        previous: previous ? buildHardeningPayload(previous, waivers) : null,
      });
    }

    const result = await hardeningService.runAllChecks(req.user!.email, domain, snapshot);
    const report: SecurityAuditReport = {
      ranAt: new Date().toISOString(),
      triggeredBy: req.user!.email,
      durationMs: Date.now() - started,
      checks: result.checks,
      statistics: result.statistics,
      policyApi: result.policyApi,
    };
    await putSecurityAuditLatest(report);
    const waivers = await getSecurityAuditWaivers();
    res.json(buildHardeningPayload(report, waivers));
  } catch (error: any) {
    sendApiError(res, error, 'Failed to run security audit', 'audit.hardening.run');
  }
});

/**
 * GET /api/audit/hardening/waivers
 */
router.get('/hardening/waivers', requireAnyAdmin, async (_req: AuthRequest, res: Response) => {
  try {
    const waivers = await getSecurityAuditWaivers();
    res.json({ waivers });
  } catch (error: any) {
    sendApiError(res, error, 'Failed to load waivers', 'audit.hardening.waivers');
  }
});

/**
 * PUT /api/audit/hardening/waivers/:checkId
 * Body: { reason?: string }. Super admin — set/update a durable waiver.
 */
router.put('/hardening/waivers/:checkId', requireSuperAdmin, async (req: AuthRequest, res: Response) => {
  try {
    const checkId = String(req.params.checkId || '').trim();
    if (!checkId) {
      return res.status(400).json({ error: 'checkId is required' });
    }
    const reason = typeof req.body?.reason === 'string' ? req.body.reason : '';
    const waivers = await setSecurityAuditWaiver(checkId, reason, req.user!.email);
    res.json({ waivers });
  } catch (error: any) {
    sendApiError(res, error, 'Failed to save waiver', 'audit.hardening.waivers.put');
  }
});

/**
 * DELETE /api/audit/hardening/waivers/:checkId
 * Super admin — remove a durable waiver.
 */
router.delete('/hardening/waivers/:checkId', requireSuperAdmin, async (req: AuthRequest, res: Response) => {
  try {
    const checkId = String(req.params.checkId || '').trim();
    if (!checkId) {
      return res.status(400).json({ error: 'checkId is required' });
    }
    const waivers = await removeSecurityAuditWaiver(checkId);
    res.json({ waivers });
  } catch (error: any) {
    sendApiError(res, error, 'Failed to remove waiver', 'audit.hardening.waivers.delete');
  }
});

/**
 * POST /api/audit/hardening/waivers/import
 * Body: { waivers: { [checkId]: reason } }. Super admin — merge browser-local
 * waivers into org storage without overwriting existing entries.
 */
router.post('/hardening/waivers/import', requireSuperAdmin, async (req: AuthRequest, res: Response) => {
  try {
    const incoming = req.body?.waivers;
    if (!incoming || typeof incoming !== 'object' || Array.isArray(incoming)) {
      return res.status(400).json({ error: 'waivers object is required' });
    }
    const normalized: Record<string, string> = {};
    for (const [id, reason] of Object.entries(incoming as Record<string, unknown>)) {
      if (typeof id === 'string' && id) {
        normalized[id] = typeof reason === 'string' ? reason : '';
      }
    }
    const waivers = await mergeSecurityAuditWaivers(normalized, req.user!.email);
    res.json({ waivers, imported: Object.keys(normalized).length });
  } catch (error: any) {
    sendApiError(res, error, 'Failed to import waivers', 'audit.hardening.waivers.import');
  }
});

/**
 * GET /api/audit/hardening/export
 * Export last-run checks to CSV (does not re-run the audit).
 */
router.get('/hardening/export', requireAnyAdmin, async (_req: AuthRequest, res: Response) => {
  try {
    const [report, waivers] = await Promise.all([getSecurityAuditLatest(), getSecurityAuditWaivers()]);
    if (!report) {
      return res.status(404).json({
        error: 'No security audit has been run yet. Click Run audit first.',
      });
    }
    const csv = convertToCSV(hardeningRowsForExport(report, waivers));
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader(
      'Content-Disposition',
      `attachment; filename="gws-hardening-${report.ranAt.split('T')[0]}.csv"`
    );
    res.send(csv);
  } catch (error: any) {
    sendApiError(res, error, 'Failed to export security audit', 'audit.hardening.export');
  }
});

/**
 * POST /api/audit/hardening/export/drive
 * Export last-run checks to Google Drive (does not re-run the audit).
 */
router.post('/hardening/export/drive', requireSuperAdmin, async (req: AuthRequest, res: Response) => {
  try {
    const [report, waivers] = await Promise.all([getSecurityAuditLatest(), getSecurityAuditWaivers()]);
    if (!report) {
      return res.status(404).json({
        error: 'No security audit has been run yet. Click Run audit first.',
      });
    }
    const csv = convertToCSV(hardeningRowsForExport(report, waivers));
    const fileName = `gws-hardening-${report.ranAt.split('T')[0]}.csv`;
    const uploadResult = await driveExportService.uploadFile(
      req.user!.email,
      fileName,
      csv,
      'text/csv',
      req.body?.folderId
    );
    res.json({
      fileId: uploadResult.id,
      webViewLink: uploadResult.webViewLink,
      message: 'Security audit exported to Google Drive successfully',
    });
  } catch (error: any) {
    sendApiError(res, error, 'Failed to export security audit to Drive', 'audit.hardening.export');
  }
});

export default router;
