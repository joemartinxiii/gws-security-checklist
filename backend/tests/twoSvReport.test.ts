import { collectTwoSvUsers, twoSvUsersToCsv, type TwoSvDirectoryPage } from '../src/services/twoSvReport';

describe('collectTwoSvUsers', () => {
  test('keeps name, email, enrollment, and enforcement', async () => {
    const report = await collectTwoSvUsers(async () => ({
      users: [
        {
          primaryEmail: 'bob@example.com',
          name: { fullName: 'Bob Johnson' },
          isEnrolledIn2Sv: false,
          isEnforcedIn2Sv: true,
        },
        {
          primaryEmail: 'jane@example.com',
          name: { givenName: 'Jane', familyName: 'Smith' },
          isEnrolledIn2Sv: true,
          isEnforcedIn2Sv: false,
        },
      ],
    }));

    expect(report.truncated).toBe(false);
    expect(report.users).toEqual([
      { name: 'Bob Johnson', email: 'bob@example.com', enrolled: false, enforced: true },
      { name: 'Jane Smith', email: 'jane@example.com', enrolled: true, enforced: false },
    ]);
  });

  test('pages until the directory is exhausted and skips blank emails', async () => {
    const pages: TwoSvDirectoryPage[] = [
      {
        users: [{ primaryEmail: 'b@example.com', name: { fullName: 'B' }, isEnrolledIn2Sv: true }],
        nextPageToken: 'p2',
      },
      {
        users: [{ primaryEmail: '  ', name: { fullName: 'Skip' } }, { primaryEmail: 'a@example.com', name: { fullName: 'A' } }],
      },
    ];
    const report = await collectTwoSvUsers(async (token) => (token === 'p2' ? pages[1] : pages[0]));
    expect(report.users.map((user) => user.email)).toEqual(['a@example.com', 'b@example.com']);
    expect(report.truncated).toBe(false);
  });

  test('marks the report truncated at the cap when another page remains', async () => {
    const report = await collectTwoSvUsers(
      async (token) =>
        token
          ? { users: [{ primaryEmail: 'c@example.com', name: { fullName: 'C' }, isEnrolledIn2Sv: true }] }
          : {
              users: [
                { primaryEmail: 'a@example.com', name: { fullName: 'A' } },
                { primaryEmail: 'b@example.com', name: { fullName: 'B' } },
              ],
              nextPageToken: 'more',
            },
      2
    );
    expect(report.users).toHaveLength(2);
    expect(report.truncated).toBe(true);
  });
});

describe('twoSvUsersToCsv', () => {
  test('writes the four report columns', () => {
    const csv = twoSvUsersToCsv([
      { name: 'Ada, Lovelace', email: 'ada@example.com', enrolled: true, enforced: false },
    ]);
    expect(csv).toBe('Name,Email,2FA Enrolled,2FA Enforced\n"Ada, Lovelace",ada@example.com,Yes,No');
  });

  test('prefixes formula-looking names so a spreadsheet treats them as text', () => {
    const csv = twoSvUsersToCsv([
      { name: '=cmd', email: 'ada@example.com', enrolled: true, enforced: true },
    ]);
    expect(csv).toContain("'=cmd");
  });
});
