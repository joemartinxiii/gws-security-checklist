export type TwoSvCsvUser = {
  name: string;
  email: string;
  enrolled: boolean;
  enforced: boolean;
};

function escapeCsv(value: string): string {
  const flattened = value.replace(/\r\n|\n|\r/g, ' ');
  const neutralized = /^[=+\-@\t]/.test(flattened) ? `'${flattened}` : flattened;
  const stringValue = neutralized.replace(/"/g, '""');
  if (stringValue.includes(',') || stringValue.includes('"')) {
    return `"${stringValue}"`;
  }
  return stringValue;
}

export function twoSvUsersToCsv(users: TwoSvCsvUser[]): string {
  const header = 'Name,Email,2FA Enrolled,2FA Enforced';
  const lines = users.map((user) =>
    [user.name, user.email, user.enrolled ? 'Yes' : 'No', user.enforced ? 'Yes' : 'No']
      .map(escapeCsv)
      .join(',')
  );
  return [header, ...lines].join('\n');
}
