import { Response, NextFunction } from 'express';
import { AuthRequest } from './auth.middleware';
import { permissionsService } from '../services/permissions.service';
import { getAuditReaders } from '../utils/validation';

/**
 * Middleware to require any admin role (super or delegated)
 * Usage: router.get('/', requireAnyAdmin, handler)
 */
export async function requireAnyAdmin(
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    if (!req.user?.email) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    const adminRole = await permissionsService.getAdminRoles(req.user.email);
    
    if (!adminRole.isSuperAdmin && !adminRole.isDelegatedAdmin) {
      res.status(403).json({ 
        error: 'Admin privileges required. You must be a Google Workspace admin to use this application.' 
      });
      return;
    }

    next();
  } catch (error: unknown) {
    console.error('Error verifying admin status:', error);
    res.status(500).json({
      error: 'Failed to verify admin privileges. Check server logs and SECURITY.md.',
    });
  }
}

/**
 * Google Workspace super admin only (isAdmin in Admin SDK).
 * Use for mutations and side effects; delegated admins get 403.
 */
export async function requireSuperAdmin(
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    if (!req.user?.email) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    const adminRole = await permissionsService.getAdminRoles(req.user.email);

    if (!adminRole.isSuperAdmin) {
      res.status(403).json({
        error: 'Super admin privileges required for this action.',
      });
      return;
    }

    next();
  } catch (error: unknown) {
    console.error('Error verifying super admin status:', error);
    res.status(500).json({
      error: 'Failed to verify super admin privileges. Check server logs and SECURITY.md.',
    });
  }
}

/**
 * Stored results (latest snapshot, waivers, CSV) come from the bucket through
 * the runtime service account, so Google never checks the caller's privileges.
 * Super admins may read them. Admins listed in GWS_AUDIT_READERS may too.
 */
export async function requireAuditReader(
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    if (!req.user?.email) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    const adminRole = await permissionsService.getAdminRoles(req.user.email);
    const isListedReader = getAuditReaders().has(req.user.email.trim().toLowerCase());
    const isAdmin = adminRole.isSuperAdmin || adminRole.isDelegatedAdmin;

    if (!adminRole.isSuperAdmin && !(isListedReader && isAdmin)) {
      res.status(403).json({
        error: 'Super admin privileges required to view stored audit results.',
      });
      return;
    }

    next();
  } catch (error: unknown) {
    console.error('Error verifying audit reader status:', error);
    res.status(500).json({
      error: 'Failed to verify admin privileges. Check server logs and SECURITY.md.',
    });
  }
}
