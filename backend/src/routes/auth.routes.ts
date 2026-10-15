import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import { createPkcePair, getAuthUrl, getGoogleConfig } from '../config/google.config';
import { authService } from '../services/auth.service';
import { authenticateSession, AuthRequest } from '../middleware/auth.middleware';
import { permissionsService } from '../services/permissions.service';
import { isEmailInAllowedDomain, getAllowedDomains, emailsEqual, getAuditReaders } from '../utils/validation';
import { sendApiError } from '../utils/apiError';
import {
  SESSION_COOKIE_NAME,
  OAUTH_STATE_COOKIE_NAME,
  OAUTH_VERIFIER_COOKIE_NAME,
  sessionCookieOptions,
  clearCookieOptions,
  oauthStateCookieOptions,
} from '../utils/sessionCookie';

const router = Router();

function frontendBase(): string {
  const raw = process.env.CORS_ORIGIN?.split(',')[0].trim() || 'http://localhost:3000';
  return raw.replace(/\/+$/, '');
}

/**
 * GET /api/auth/login
 * Start Google OAuth (identity only). Sets short-lived oauth_state and
 * oauth_verifier cookies: state guards the callback against CSRF, and the
 * PKCE verifier binds the code exchange to this browser.
 */
router.get('/login', async (_req: Request, res: Response) => {
  if (!getGoogleConfig().redirectUri) {
    console.error('Sign-in refused: GOOGLE_REDIRECT_URI is not set.');
    return res.status(503).json({ error: 'Sign-in is not set up yet. Try again in a minute.' });
  }
  try {
    const state = crypto.randomBytes(24).toString('hex');
    const { codeVerifier, codeChallenge } = await createPkcePair();
    res.cookie(OAUTH_STATE_COOKIE_NAME, state, oauthStateCookieOptions());
    res.cookie(OAUTH_VERIFIER_COOKIE_NAME, codeVerifier, oauthStateCookieOptions());
    const authUrl = getAuthUrl(state, codeChallenge);
    res.json({ authUrl });
  } catch (error) {
    console.error('Error generating auth URL:', error);
    res.status(500).json({ error: 'Failed to generate auth URL' });
  }
});

/**
 * GET /api/auth/callback
 * OAuth2 callback: exchange code (with the PKCE verifier), verify the ID token,
 * gate domain + admin, set HttpOnly session cookie.
 * Google tokens are used only for this request and never sent to the browser.
 */
router.get('/callback', async (req: Request, res: Response) => {
  const base = frontendBase();
  try {
    const { code, error, state } = req.query;

    if (error) {
      return res.redirect(`${base}/auth/error?error=${encodeURIComponent(String(error))}`);
    }

    const expectedState = req.cookies?.[OAUTH_STATE_COOKIE_NAME];
    const codeVerifier = req.cookies?.[OAUTH_VERIFIER_COOKIE_NAME];
    res.clearCookie(OAUTH_STATE_COOKIE_NAME, clearCookieOptions());
    res.clearCookie(OAUTH_VERIFIER_COOKIE_NAME, clearCookieOptions());
    if (
      !state ||
      !expectedState ||
      String(state) !== String(expectedState) ||
      typeof codeVerifier !== 'string' ||
      !codeVerifier
    ) {
      console.warn('OAuth callback rejected: missing or mismatched state or PKCE verifier');
      return res.redirect(`${base}/auth/error?error=invalid_state`);
    }

    if (!code || typeof code !== 'string') {
      return res.redirect(`${base}/auth/error?error=no_code`);
    }

    // Exchange code for tokens (server-side only; discarded after identity check)
    const tokens = await authService.exchangeCodeForTokens(code, codeVerifier);
    if (!tokens.idToken) {
      console.warn('OAuth callback rejected: token response had no ID token');
      return res.redirect(`${base}/auth/error?error=callback_failed`);
    }
    const identity = await authService.verifyIdToken(tokens.idToken);

    // --- Login gate -------------------------------------------------------
    // Only allow verified accounts whose hosted domain (hd) is a permitted
    // Workspace domain and that are actually Workspace admins. The hd claim is
    // required: an email suffix alone does not prove Workspace membership.
    const hd = String(identity.hd || '').toLowerCase();
    if (!identity.emailVerified) {
      console.warn(`Denied login for unverified email: ${identity.email}`);
      return res.redirect(`${base}/auth/error?error=domain_not_allowed`);
    }
    if (!hd || !getAllowedDomains().includes(hd) || !isEmailInAllowedDomain(identity.email)) {
      console.warn(`Denied login for out-of-domain account: ${identity.email}`);
      return res.redirect(`${base}/auth/error?error=domain_not_allowed`);
    }

    try {
      const adminRole = await permissionsService.getAdminRoles(identity.email, { fresh: true });
      if (!adminRole.isSuperAdmin && !adminRole.isDelegatedAdmin) {
        console.warn(`Denied login for non-admin account: ${identity.email}`);
        return res.redirect(`${base}/auth/error?error=not_admin`);
      }
      if (!adminRole.id || !adminRole.primaryEmail || !emailsEqual(adminRole.primaryEmail, identity.email)) {
        console.warn(`Denied login: Directory user does not match token email for ${identity.email}`);
        return res.redirect(`${base}/auth/error?error=admin_check_failed`);
      }
    } catch (adminErr) {
      console.error('Login gate admin check failed:', adminErr);
      return res.redirect(`${base}/auth/error?error=admin_check_failed`);
    }
    // ---------------------------------------------------------------------

    const sessionToken = await authService.createSessionToken({
      email: identity.email,
      name: identity.name || identity.email,
      picture: identity.picture,
      sub: identity.sub,
    });
    res.cookie(SESSION_COOKIE_NAME, sessionToken, sessionCookieOptions());

    // Clean redirect — no tokens in query or fragment
    res.redirect(`${base}/`);
  } catch (error) {
    console.error('Error in OAuth callback:', error);
    res.redirect(`${base}/auth/error?error=callback_failed`);
  }
});

/**
 * GET /api/auth/me
 * Current user from session cookie (or Bearer for automation outside production).
 */
router.get('/me', authenticateSession, async (req: AuthRequest, res: Response) => {
  try {
    const allowedDomains = getAllowedDomains();
    res.json({
      email: req.user?.email,
      name: req.user?.name,
      picture: req.user?.picture,
      allowedDomains,
    });
  } catch (error) {
    console.error('Error getting user info:', error);
    res.status(500).json({ error: 'Failed to get user info' });
  }
});

/**
 * POST /api/auth/logout
 * Clear session cookie. Does not require a valid session (always clear client state).
 */
router.post('/logout', async (req: Request, res: Response) => {
  const token = req.cookies?.[SESSION_COOKIE_NAME];
  if (typeof token === 'string' && token) {
    try {
      await authService.revokeSessionToken(token);
    } catch (error) {
      console.error('Error revoking session:', error);
    }
  }
  res.clearCookie(SESSION_COOKIE_NAME, clearCookieOptions());
  res.clearCookie(OAUTH_STATE_COOKIE_NAME, clearCookieOptions());
  res.clearCookie(OAUTH_VERIFIER_COOKIE_NAME, clearCookieOptions());
  res.json({ message: 'Logged out successfully' });
});

/**
 * GET /api/auth/permissions
 * Permissions from Workspace admin roles (DWD). Requires session.
 */
router.get('/permissions', authenticateSession, async (req: AuthRequest, res: Response) => {
  try {
    const permissions = await permissionsService.getUserPermissions(req.user!.email);
    const adminRole = await permissionsService.getAdminRoles(req.user!.email);

    const isListedReader =
      adminRole.isDelegatedAdmin && getAuditReaders().has(req.user!.email.trim().toLowerCase());

    res.json({
      permissions,
      isSuperAdmin: adminRole.isSuperAdmin,
      isDelegatedAdmin: adminRole.isDelegatedAdmin,
      canReadStoredAudit: adminRole.isSuperAdmin || isListedReader,
    });
  } catch (error: any) {
    sendApiError(res, error, 'Failed to get permissions', 'auth.permissions');
  }
});

export default router;
