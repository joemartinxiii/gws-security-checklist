/**
 * Converts an array of objects to a CSV string with proper escaping.
 * Used for the audit checklist export and the 2-Step Verification report.
 * Supports basic transformation and header mapping.
 */
export interface CSVOptions {
  headers?: Record<string, string>;
  transform?: (row: any) => Record<string, any>;
}

export function convertToCSV(data: any[], options: CSVOptions = {}): string {
  if (!data || data.length === 0) return '';

  const { headers = {}, transform } = options;

  // Use first row to determine headers if not provided
  let headersToUse = Object.keys(data[0] || {});
  if (Object.keys(headers).length > 0) {
    headersToUse = Object.keys(headers);
  }

  const csvRows: string[] = [headersToUse.map(h => headers[h] || h).join(',')];

  for (const row of data) {
    const processedRow = transform ? transform(row) : row;
    const values = headersToUse.map(header => csvCell(processedRow[header]));
    csvRows.push(values.join(','));
  }

  return csvRows.join('\n');
}

/**
 * Escape one CSV field. A value that starts with =, +, -, or @ (after any
 * leading whitespace or control characters, which spreadsheet apps skip), or
 * with a tab or CR, gets a leading quote so spreadsheets treat it as text.
 */
function csvCell(value: unknown): string {
  if (value === null || value === undefined) return '';
  const raw = Array.isArray(value) ? value.join('; ') : String(value);
  const flattened = raw.replace(/\r\n|\n|\r/g, ' ');
  const startsLikeFormula = /^[\s\p{Cc}]*[=+\-@]/u.test(raw) || /^[\t\r]/.test(raw);
  const neutralized = startsLikeFormula ? `'${flattened}` : flattened;
  const stringValue = neutralized.replace(/"/g, '""');
  return /[",]/.test(stringValue) ? `"${stringValue}"` : stringValue;
}

/**
 * Helper to send CSV response with proper headers.
 * Use in export routes to ensure consistency and security (no sensitive headers leaked).
 */
export function sendCSVResponse(
  res: any, 
  csvData: string, 
  filename: string = 'export.csv',
  auditLogFn?: () => void
): void {
  if (auditLogFn) auditLogFn();
  
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  // Security: prevent caching of sensitive exports
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.send(csvData);
}
