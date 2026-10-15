import { convertToCSV } from '../src/utils/csv';

describe('convertToCSV', () => {
  test('prefixes formula-looking cells', () => {
    const csv = convertToCSV([
      { Name: '=cmd|"/c calc"!A1', Note: 'ok', Plus: '+1', At: '@sum' },
    ]);
    expect(csv).toContain("'=cmd|\"\"/c calc\"\"!A1");
    expect(csv).toContain("'+1");
    expect(csv).toContain("'@sum");
    expect(csv).toContain('ok');
  });

  test.each([
    ['leading space', ' =1+1'],
    ['leading newline', '\n=1+1'],
    ['leading CRLF', '\r\n=1+1'],
    ['leading newline then space', '\n  @SUM(A1)'],
    ['leading control character', '\u0001-2+3'],
  ])('prefixes a formula after %s', (_label, value) => {
    const csv = convertToCSV([{ Value: value }]);
    const cell = csv.split('\n').slice(1).join('\n');
    expect(cell.startsWith("'") || cell.startsWith('"\'')).toBe(true);
    expect(cell).not.toMatch(/\n/);
  });

  test.each([
    ['tab', '\tdata'],
    ['CR', '\rdata'],
  ])('prefixes a leading %s on its own', (_label, value) => {
    expect(convertToCSV([{ Value: value }]).split('\n')[1]).toBe("'" + value.replace('\r', ' '));
  });

  test('keeps the rest of the output identical', () => {
    expect(convertToCSV([{ A: 'plain', B: 'a,b', C: 'say "hi"', D: ['x', 'y'], E: null, F: 'line1\nline2' }])).toBe(
      'A,B,C,D,E,F\nplain,"a,b","say ""hi""",x; y,,line1 line2'
    );
    expect(convertToCSV([{ A: ' text', B: 'a-b', C: 'x=1' }])).toBe('A,B,C\n text,a-b,x=1');
  });
});
