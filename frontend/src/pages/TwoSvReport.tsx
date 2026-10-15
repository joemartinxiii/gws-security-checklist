import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  IconButton,
  Menu,
  Snackbar,
  Typography,
  useMediaQuery,
  useTheme,
} from '@mui/material';
import { ChevronDown, CloudUpload, Download } from 'lucide-react';
import { apiClient } from '../services/api.client';
import { ActionTooltip } from '../components/ActionTooltip';
import { ExportMenuRow } from '../components/ExportButton';
import { DotLabel } from '../components/StatusDot';
import { ColumnHeader } from '../components/ui/ColumnHeader';
import { ListDataRow, ListHeaderRow, ListShell, listGrowSx } from '../components/ui/ListShell';
import { PageHeader } from '../components/ui/PageHeader';
import { ScoreRing } from '../components/ui/ScoreRing';
import {
  T,
  exportToolbarButtonSx,
  menuPaperProps,
  pick,
  textSecondary,
  textTertiary,
} from '../theme/designTokens';
import { getApiErrorMessage } from '../utils/apiError';
import { twoSvUsersToCsv, type TwoSvCsvUser } from '../utils/twoSvCsv';

const LU = 1.75;

type SortKey = 'name' | 'email' | 'enrolled' | 'enforced';

type TwoSvPayload = {
  generatedAt: string;
  truncated: boolean;
  users: TwoSvCsvUser[];
};

function yesNo(value: boolean): string {
  return value ? 'Yes' : 'No';
}

function downloadBlob(filename: string, blob: Blob) {
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
}

export function TwoSvReport() {
  const theme = useTheme();
  const isMdUp = useMediaQuery(theme.breakpoints.up('md'));
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [report, setReport] = useState<TwoSvPayload | null>(null);
  const [exportAnchorEl, setExportAnchorEl] = useState<null | HTMLElement>(null);
  const [sort, setSort] = useState<{ key: SortKey; direction: 'asc' | 'desc' }>({
    key: 'name',
    direction: 'asc',
  });
  const [snackbar, setSnackbar] = useState<{
    open: boolean;
    message: string;
    severity: 'success' | 'error' | 'info';
  }>({ open: false, message: '', severity: 'success' });

  const showSnackbar = (message: string, severity: 'success' | 'error' | 'info' = 'success') =>
    setSnackbar({ open: true, message, severity });

  const loadReport = async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const response = await apiClient.get<TwoSvPayload>('/audit/2sv');
      setReport(response.data);
    } catch (error: unknown) {
      setReport(null);
      setLoadError(getApiErrorMessage(error, 'Failed to load the 2FA report.'));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadReport();
  }, []);

  const users = report?.users ?? [];

  const sortedUsers = useMemo(() => {
    const dir = sort.direction === 'asc' ? 1 : -1;
    return [...users].sort((a, b) => {
      if (sort.key === 'enrolled' || sort.key === 'enforced') {
        return (Number(a[sort.key]) - Number(b[sort.key])) * dir;
      }
      return a[sort.key].localeCompare(b[sort.key]) * dir;
    });
  }, [users, sort]);

  const generatedLabel = useMemo(() => {
    if (!report?.generatedAt) return null;
    try {
      return new Date(report.generatedAt).toLocaleString();
    } catch {
      return null;
    }
  }, [report?.generatedAt]);

  const onSort = (columnId: string) => {
    const key = columnId as SortKey;
    setSort((prev) =>
      prev.key === key
        ? { key, direction: prev.direction === 'asc' ? 'desc' : 'asc' }
        : { key, direction: 'asc' }
    );
  };

  const handleExportCSV = () => {
    setExportAnchorEl(null);
    if (!report || users.length === 0) {
      showSnackbar('No users to export.', 'info');
      return;
    }
    try {
      const csv = twoSvUsersToCsv(sortedUsers);
      const date = (report.generatedAt || new Date().toISOString()).split('T')[0];
      downloadBlob(`2fa-report-${date}.csv`, new Blob([csv], { type: 'text/csv;charset=utf-8' }));
      showSnackbar('CSV downloading now.');
    } catch (error: unknown) {
      showSnackbar(getApiErrorMessage(error, 'Failed to export CSV.'), 'error');
    }
  };

  const handleExportDrive = async () => {
    setExportAnchorEl(null);
    try {
      const response = await apiClient.post('/audit/2sv/export/drive');
      if (response.data?.webViewLink) window.open(response.data.webViewLink, '_blank');
      showSnackbar('Saved to Google Drive.');
    } catch (error: unknown) {
      showSnackbar(getApiErrorMessage(error, 'Drive export failed.'), 'error');
    }
  };

  const stats = useMemo(() => {
    const total = users.length;
    const enrolled = users.filter((user) => user.enrolled).length;
    const enforced = users.filter((user) => user.enforced).length;
    return {
      total,
      enrolled,
      notEnrolled: total - enrolled,
      enforced,
      notEnforced: total - enforced,
      pct: total === 0 ? 0 : Math.round((enrolled / total) * 100),
    };
  }, [users]);

  const headlineColor = stats.pct >= 80 ? T.success : stats.pct >= 50 ? T.accent : T.warning;
  const share = (n: number) => (stats.total === 0 ? 0 : Math.round((n / stats.total) * 100));

  return (
    <>
      <Box sx={{ fontFamily: T.font }}>
        <PageHeader
          title="2FA Report"
          lede="Directory users and their 2-step verification status. Enrollment means a second factor is set up. Enforcement means the admin policy requires it."
          status={
            loading ? (
              <Box component="span" className="page-status-live">
                Loading directory
              </Box>
            ) : generatedLabel ? (
              <>
                Generated: {generatedLabel}
                {report?.truncated ? (
                  <Box component="span" className="page-status-faint">
                    {' '}
                    · First 50,000 users
                  </Box>
                ) : null}
              </>
            ) : (
              <Box component="span" className="page-status-faint">
                Directory list could not be loaded
              </Box>
            )
          }
          statusActions={
            !loading && report ? (
              <ActionTooltip title="Export this report (CSV or Drive)">
                <span>
                  {isMdUp ? (
                    <Button
                      variant="outlined"
                      endIcon={<ChevronDown size={20} strokeWidth={LU} />}
                      onClick={(e) => setExportAnchorEl(e.currentTarget)}
                      sx={exportToolbarButtonSx()}
                    >
                      Export
                    </Button>
                  ) : (
                    <IconButton
                      onClick={(e) => setExportAnchorEl(e.currentTarget)}
                      aria-label="Export"
                      sx={exportToolbarButtonSx()}
                    >
                      <ChevronDown size={20} strokeWidth={LU} />
                    </IconButton>
                  )}
                </span>
              </ActionTooltip>
            ) : undefined
          }
          actions={
            !loading && report ? (
              <Box
                sx={(th) => ({
                  display: 'inline-flex',
                  flexDirection: 'column',
                  gap: 2,
                  border: `1px solid ${pick(th, T.border, '#3f3f46')}`,
                  borderRadius: T.radiusLg,
                  p: 2.25,
                  bgcolor: pick(th, T.surface, '#18181b'),
                  maxWidth: '100%',
                })}
              >
                <Box
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    flexWrap: 'wrap',
                    gap: { xs: 2.5, sm: 3.5 },
                  }}
                >
                  <ScoreRing value={stats.pct} color={headlineColor} caption="Enrolled" sizeVariant="lg" />
                  <Box sx={{ display: 'flex', alignItems: 'flex-start', flexWrap: 'wrap', gap: { xs: 2, sm: 2.5 } }}>
                    <ScoreRing
                      value={share(stats.enrolled)}
                      centerLabel={String(stats.enrolled)}
                      color={T.success}
                      caption="Enrolled"
                      sizeVariant="sm"
                    />
                    <ScoreRing
                      value={share(stats.notEnrolled)}
                      centerLabel={String(stats.notEnrolled)}
                      color={T.danger}
                      caption="Not enrolled"
                      sizeVariant="sm"
                    />
                  </Box>
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, pl: { sm: 0.5 }, minWidth: 120 }}>
                    {(
                      [
                        ['Enforced', stats.enforced, T.success],
                        ['Not enforced', stats.notEnforced, T.warning],
                      ] as const
                    ).map(([label, n, color]) => (
                      <Box key={label} sx={{ display: 'flex', alignItems: 'baseline', gap: 1 }}>
                        <Typography
                          sx={{ fontFamily: T.font, fontSize: '1.125rem', fontWeight: 600, color, minWidth: 28 }}
                        >
                          {n}
                        </Typography>
                        <Typography
                          sx={{
                            fontFamily: T.font,
                            fontSize: '0.6875rem',
                            color: (t) => textTertiary(t),
                            textTransform: 'uppercase',
                            letterSpacing: '0.06em',
                          }}
                        >
                          {label}
                        </Typography>
                      </Box>
                    ))}
                  </Box>
                </Box>
                <Typography sx={{ fontFamily: T.font, fontSize: '0.8125rem', color: (t) => textSecondary(t) }}>
                  {stats.total} users. Enrolled is who has a second factor. Enforced can be on during a grace period,
                  before setup finishes.
                </Typography>
              </Box>
            ) : undefined
          }
        />

        {!loading && report && (
          <Menu
            anchorEl={exportAnchorEl}
            open={Boolean(exportAnchorEl)}
            onClose={() => setExportAnchorEl(null)}
            anchorOrigin={{ vertical: 'bottom', horizontal: 'left' }}
            transformOrigin={{ vertical: 'top', horizontal: 'left' }}
            PaperProps={{
              sx: (th) => ({
                ...(typeof menuPaperProps.PaperProps.sx === 'function' ? menuPaperProps.PaperProps.sx(th) : {}),
                ...(exportAnchorEl ? { minWidth: exportAnchorEl.offsetWidth } : {}),
              }),
            }}
            MenuListProps={{ dense: true, sx: { py: 0.5 } }}
          >
            <ExportMenuRow label="Export to CSV" icon={<Download size={16} strokeWidth={LU} />} onClick={handleExportCSV} />
            <ExportMenuRow
              label="Export to Drive"
              icon={<CloudUpload size={16} strokeWidth={LU} />}
              onClick={handleExportDrive}
            />
          </Menu>
        )}

        {loadError && !loading && (
          <Alert
            severity="error"
            sx={{ mb: 2 }}
            action={
              <Button color="inherit" size="small" onClick={() => void loadReport()}>
                Retry
              </Button>
            }
          >
            {loadError}
          </Alert>
        )}

        {loading ? (
          <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
            <CircularProgress />
          </Box>
        ) : report ? (
          <ListShell>
            <ListHeaderRow>
              <ColumnHeader label="Name" columnId="name" sortConfig={sort} onSort={onSort} grow={1.2} minWidth={140} />
              <ColumnHeader label="Email" columnId="email" sortConfig={sort} onSort={onSort} grow={1.6} minWidth={180} />
              <ColumnHeader
                label="2FA enrolled"
                columnId="enrolled"
                sortConfig={sort}
                onSort={onSort}
                grow={0.8}
                minWidth={120}
              />
              <ColumnHeader
                label="2FA enforced"
                columnId="enforced"
                sortConfig={sort}
                onSort={onSort}
                grow={0.8}
                minWidth={120}
              />
            </ListHeaderRow>
            {sortedUsers.length === 0 ? (
              <Box sx={{ py: 6, textAlign: 'center' }}>
                <Typography sx={{ fontFamily: T.font, fontSize: '0.9375rem', color: (t) => textSecondary(t) }}>
                  No users returned.
                </Typography>
              </Box>
            ) : (
              sortedUsers.map((user, idx) => (
                <ListDataRow key={user.email} last={idx === sortedUsers.length - 1}>
                  <Box sx={listGrowSx(1.2, 140)}>
                    <Typography
                      noWrap
                      sx={{
                        fontFamily: T.font,
                        fontSize: '0.8125rem',
                        fontWeight: 500,
                        color: (th) => pick(th, T.text, '#fafafa'),
                      }}
                    >
                      {user.name}
                    </Typography>
                  </Box>
                  <Box sx={listGrowSx(1.6, 180)}>
                    <Typography
                      noWrap
                      sx={{ fontFamily: T.font, fontSize: '0.8125rem', color: (t) => textSecondary(t) }}
                    >
                      {user.email}
                    </Typography>
                  </Box>
                  <Box sx={listGrowSx(0.8, 120)}>
                    <DotLabel dotColor={user.enrolled ? T.success : T.danger}>{yesNo(user.enrolled)}</DotLabel>
                  </Box>
                  <Box sx={listGrowSx(0.8, 120)}>
                    <DotLabel dotColor={user.enforced ? T.success : T.warning}>{yesNo(user.enforced)}</DotLabel>
                  </Box>
                </ListDataRow>
              ))
            )}
          </ListShell>
        ) : null}
      </Box>
      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar((s) => ({ ...s, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert
          onClose={() => setSnackbar((s) => ({ ...s, open: false }))}
          severity={snackbar.severity}
          sx={{ width: '100%' }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </>
  );
}
