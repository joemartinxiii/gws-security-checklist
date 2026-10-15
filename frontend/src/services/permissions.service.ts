import { isAxiosError } from 'axios';
import { apiClient } from './api.client';

export type Permission = 'audit.view' | 'audit.export';

export interface UserPermissions {
  permissions: Permission[];
  isSuperAdmin: boolean;
  isDelegatedAdmin: boolean;
  /** Super admin, or a delegated admin listed in GWS_AUDIT_READERS. */
  canReadStoredAudit?: boolean;
  error?: string | null;
}

class PermissionsService {
  private permissions: Permission[] | null = null;
  private isSuperAdmin: boolean = false;
  private isDelegatedAdmin: boolean = false;
  private canReadStoredAudit: boolean = false;
  private cacheExpiry: number = 0;
  private loadError: string | null = null;
  private readonly CACHE_TTL = 5 * 60 * 1000;

  async fetchPermissions(): Promise<UserPermissions> {
    if (this.permissions && Date.now() < this.cacheExpiry) {
      return {
        permissions: this.permissions,
        isSuperAdmin: this.isSuperAdmin,
        isDelegatedAdmin: this.isDelegatedAdmin,
        canReadStoredAudit: this.canReadStoredAudit,
        error: this.loadError,
      };
    }

    try {
      const response = await apiClient.get<UserPermissions>('/auth/permissions');
      this.permissions = response.data.permissions;
      this.isSuperAdmin = response.data.isSuperAdmin;
      this.isDelegatedAdmin = response.data.isDelegatedAdmin;
      this.canReadStoredAudit = response.data.canReadStoredAudit ?? response.data.isSuperAdmin;
      this.cacheExpiry = Date.now() + this.CACHE_TTL;
      this.loadError = null;

      return { ...response.data, canReadStoredAudit: this.canReadStoredAudit, error: null };
    } catch (error: unknown) {
      const body = isAxiosError<{ error?: string; hint?: string }>(error) ? error.response?.data : undefined;
      const errorMsg =
        body?.error || (error instanceof Error ? error.message : undefined) || 'Unknown error';
      const hint = body?.hint;
      console.error('Error fetching permissions:', errorMsg);
      this.permissions = [];
      this.isSuperAdmin = false;
      this.isDelegatedAdmin = false;
      this.canReadStoredAudit = false;
      this.cacheExpiry = 0;
      this.loadError = hint ? `${errorMsg} ${hint}` : errorMsg;

      return {
        permissions: [],
        isSuperAdmin: false,
        isDelegatedAdmin: false,
        canReadStoredAudit: false,
        error: this.loadError,
      };
    }
  }

  hasPermission(permission: Permission): boolean {
    if (!this.permissions) return false;
    return this.permissions.includes(permission);
  }

  hasAnyPermission(...permissions: Permission[]): boolean {
    if (!this.permissions) return false;
    return permissions.some((p) => this.permissions!.includes(p));
  }

  clearCache(): void {
    this.permissions = null;
    this.canReadStoredAudit = false;
    this.cacheExpiry = 0;
  }

  canViewAudit(): boolean {
    return this.hasPermission('audit.view');
  }
}

export const permissionsService = new PermissionsService();
