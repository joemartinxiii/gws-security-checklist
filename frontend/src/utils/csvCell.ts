// Spreadsheets run a cell as a formula when it starts with one of these after
// leading whitespace and control characters are ignored. A leading tab is
// prefixed too, because some programs treat it as a command separator.
const FORMULA_START = /^[=+\-@]/;

function isBlankOrControl(char: string): boolean {
  const code = char.charCodeAt(0);
  return code <= 0x20 || code === 0x7f || /\s/.test(char);
}

function stripLeadingBlanks(value: string): string {
  let start = 0;
  while (start < value.length && isBlankOrControl(value[start])) start += 1;
  return value.slice(start);
}

export function escapeCsvCell(value: unknown): string {
  if (value == null) return '';
  const flattened = String(value).replace(/\r\n|\n|\r/g, ' ');
  const startsLikeFormula =
    flattened.startsWith('\t') || FORMULA_START.test(stripLeadingBlanks(flattened));
  const neutralized = startsLikeFormula ? `'${flattened}` : flattened;
  const stringValue = neutralized.replace(/"/g, '""');
  if (stringValue.includes(',') || stringValue.includes('"')) {
    return `"${stringValue}"`;
  }
  return stringValue;
}
