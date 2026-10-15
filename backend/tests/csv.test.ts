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
});
