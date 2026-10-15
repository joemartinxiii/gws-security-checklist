import { WorkspaceService } from './workspace.service';

interface DirectoryUser {
  id?: string;
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
  /** Directory user id and primary email, absent when Google refused the lookup. */
  id?: string;
  primaryEmail?: string;
}

const ROLE_CACHE_TTL_MS = 2 * 60 * 1000;
const ROLE_CACHE_MAX_ENTRIES = 500;

const NOT_ADMIN: AdminRole = { isSuperAdmin: false, isDelegatedAdmin: false };

function httpStatusOf(error: unknown): number | undefined {
  const err = error as { response?: { status?: number }; code?: number | string; status?: number };
  const candidate = err?.response?.status ?? err?.code ?? err?.status;
  const parsed = typeof candidate === 'string' ? parseInt(candidate, 10) : candidate;
  return typeof parsed === 'number' && Number.isFinite(parsed) ? parsed : undefined;
}

export class PermissionsService extends WorkspaceService {
  private readonly roleCache = new Map<string, { role: AdminRole; expiresAt: number }>();

  /**
   * Directory lookup as the user. Non-admins and delegated admins without the
   * Users read privilege get 403 from Google, which maps to "not an admin".
   * Results, including "not an admin", are cached for 2 minutes. Errors are not.
   * Pass `fresh` to skip the cache, as sign-in does.
   */
  async getAdminRoles(userEmail: string, options: { fresh?: boolean } = {}): Promise<AdminRole> {
    const key = userEmail.trim().toLowerCase();
    if (!options.fresh) {
      const cached = this.roleCache.get(key);
      if (cached && cached.expiresAt > Date.now()) return cached.role;
    }

    const role = await this.lookupAdminRole(userEmail);
    if (this.roleCache.size >= ROLE_CACHE_MAX_ENTRIES) this.pruneRoleCache();
    this.roleCache.set(key, { role, expiresAt: Date.now() + ROLE_CACHE_TTL_MS });
    return role;
  }

  clearRoleCache(): void {
    this.roleCache.clear();
  }

  private pruneRoleCache(): void {
    const now = Date.now();
    for (const [key, entry] of this.roleCache) {
      if (entry.expiresAt <= now) this.roleCache.delete(key);
    }
    if (this.roleCache.size >= ROLE_CACHE_MAX_ENTRIES) this.roleCache.clear();
  }

  private async lookupAdminRole(userEmail: string): Promise<AdminRole> {
    try {
      const admin = await this.adminFor(userEmail);

      let response;
      try {
        response = await this.withRetry(() =>
          admin.users.get({
            userKey: userEmail,
            projection: 'full',
          })
        );
      } catch (error: unknown) {
        if (httpStatusOf(error) === 403) return NOT_ADMIN;
        throw error;
      }

      const user = response.data as DirectoryUser;

      return {
        isSuperAdmin: user.isAdmin === true,
        isDelegatedAdmin: user.isDelegatedAdmin === true,
        delegatedAdminPrivileges: user.delegatedAdminPrivileges || [],
        orgUnitPath: user.orgUnitPath,
        id: user.id,
        primaryEmail: user.primaryEmail,
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
