/** Columns match backend `hardeningRowsForExport` in hardening.routes.ts. */

import { escapeCsvCell } from './csvCell';

export type CsvCheck = {
  id: string;
  category: string;
  name: string;
  description: string;
  severity?: string;
  status: string;
  currentValue?: unknown;
  recommendedValue?: unknown;
  rationale?: string;
  recommendation?: string;
  adminConsoleUrl?: string;
};

export type CsvWaiver = { reason?: string };

const HEADERS = [
  'Category',
  'Name',
  'Description',
  'Severity',
  'Status',
  'Waived',
  'Waive Reason',
  'Current Value',
  'Recommended Value',
  'Rationale',
  'Recommendation',
  'Admin Console URL',
] as const;

export function hardeningChecksToCsv(
  checks: CsvCheck[],
  waivers: Record<string, CsvWaiver> = {}
): string {
  const lines = [HEADERS.join(',')];
  for (const check of checks) {
    const waiver = waivers[check.id];
    lines.push(
      [
        check.category,
        check.name,
        check.description,
        (check.severity || 'medium').toUpperCase(),
        check.status.toUpperCase(),
        waiver ? 'Yes' : 'No',
        waiver?.reason || '',
        check.currentValue != null ? String(check.currentValue) : '',
        check.recommendedValue != null ? String(check.recommendedValue) : '',
        check.rationale || '',
        check.recommendation || '',
        check.adminConsoleUrl || '',
      ]
        .map(escapeCsvCell)
        .join(',')
    );
  }
  return lines.join('\n');
}
