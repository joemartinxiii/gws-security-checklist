import { WorkspaceService } from './workspace.service';

interface DirectoryUser {
  isAdmin?: boolean;
  isDelegatedAdmin?: boolean;
  delegatedAdminPrivileges?: string[];
  orgUnitPath?: string;
  primaryEmail?: string;
  name?: { fullName?: string };
}

export type Permission = 'audit.view' | 'audit.export';

export interface AdminRole {
  isSuperAdmin: boolean;
  isDelegatedAdmin: boolean;
  delegatedAdminPrivileges?: string[];
  orgUnitPath?: string;
}

export class PermissionsService extends WorkspaceService {
  async getAdminRoles(userEmail: string): Promise<AdminRole> {
    try {
      const admin = await this.adminFor(userEmail);

      const response = await this.withRetry(() =>
        admin.users.get({
          userKey: userEmail,
          projection: 'full',
        })
      );

      const user = response.data as DirectoryUser;

      return {
        isSuperAdmin: user.isAdmin === true,
        isDelegatedAdmin: user.isDelegatedAdmin === true,
        delegatedAdminPrivileges: user.delegatedAdminPrivileges || [],
        orgUnitPath: user.orgUnitPath,
      };
    } catch (error: unknown) {
      const err = error instanceof Error ? error : new Error(String(error));
      const message = err.message;
      if (message.includes('secret') || message.includes('SecretManager') || (message.includes('403') && message.includes('access'))) {
        throw new Error(`Secret Manager or IAM configuration error. See SECURITY.md. Details: ${message}`);
      }
      if (message.includes('delegation') || message.includes('Forbidden') || message.includes('403') || message.includes('insufficient')) {
        throw new Error(`Domain-wide delegation or admin privileges issue for ${userEmail}. Verify SA scopes in Admin Console match SECURITY.md. Details: ${message}`);
      }
      console.error('getAdminRoles failed:', error);
      throw new Error(`Failed to fetch admin roles for ${userEmail}: ${message}`);
    }
  }

  getPermissions(adminRole: AdminRole): Permission[] {
    if (adminRole.isSuperAdmin) {
      return ['audit.view', 'audit.export'];
    }
    if (adminRole.isDelegatedAdmin) {
      return ['audit.view'];
    }
    return [];
  }

  async hasPermission(userEmail: string, permission: Permission): Promise<boolean> {
    const adminRole = await this.getAdminRoles(userEmail);
    return this.getPermissions(adminRole).includes(permission);
  }

  async getUserPermissions(userEmail: string): Promise<Permission[]> {
    const adminRole = await this.getAdminRoles(userEmail);
    return this.getPermissions(adminRole);
  }
}

export const permissionsService = new PermissionsService();
