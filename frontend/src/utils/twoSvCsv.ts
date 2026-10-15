import { escapeCsvCell } from './csvCell';

export type TwoSvCsvUser = {
  name: string;
  email: string;
  enrolled: boolean;
  enforced: boolean;
};

export function twoSvUsersToCsv(users: TwoSvCsvUser[]): string {
  const header = 'Name,Email,2FA Enrolled,2FA Enforced';
  const lines = users.map((user) =>
    [user.name, user.email, user.enrolled ? 'Yes' : 'No', user.enforced ? 'Yes' : 'No']
      .map(escapeCsvCell)
      .join(',')
  );
  return [header, ...lines].join('\n');
}
