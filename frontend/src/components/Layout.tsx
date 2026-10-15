import { useState, useContext, useEffect, useMemo } from 'react';
import { Link as RouterLink, useNavigate } from 'react-router-dom';
import {
  Box,
  AppBar,
  Toolbar,
  Typography,
  IconButton,
  ListItemIcon,
  Avatar,
  Menu,
  MenuItem,
  Alert,
  Button as MuiButton,
  useTheme,
  Chip,
} from '@mui/material';
import { ThemeProvider as MuiThemeProviderNested } from '@mui/material/styles';
import { Shield, LogOut, Sun, Moon } from 'lucide-react';
import { authService } from '../services/auth.service';
import { usePermissions } from '../hooks/usePermissions';
import { ThemeContext } from '../App';
import { T, pick, textSecondary, PAGE_MAX_WIDTH } from '../theme/designTokens';
import { FontLinks } from './FontLinks';

const LU = 1.75;

interface LayoutProps {
  children: React.ReactNode;
}

function AppMark() {
  return (
    <Box
      sx={{
        width: 32,
        height: 32,
        borderRadius: '9px',
        background: 'linear-gradient(145deg, #2b8aef, #1557b0)',
        display: 'grid',
        placeItems: 'center',
        flexShrink: 0,
        boxShadow: '0 0 0 1px rgba(255,255,255,0.08), 0 4px 12px rgba(26,115,232,0.35)',
        color: '#fff',
      }}
      aria-hidden
    >
      <Shield size={16} strokeWidth={2} />
    </Box>
  );
}

export function Layout({ children }: LayoutProps) {
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [currentUser, setCurrentUser] = useState<{ email: string; name: string; picture?: string } | null>(null);
  const navigate = useNavigate();
  const permissions = usePermissions();
  const { isSuperAdmin, isDelegatedAdmin } = permissions;
  const { mode, toggleColorMode } = useContext(ThemeContext);

  const muiTheme = useTheme();
  const nestedMuiTheme = useMemo(() => muiTheme, [muiTheme]);

  const handleMenuClick = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handleLogout = async () => {
    handleMenuClose();
    await authService.logout();
    navigate('/login');
  };

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'b') {
        e.preventDefault();
        toggleColorMode();
      }
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [toggleColorMode]);

  useEffect(() => {
    let mounted = true;
    const loadCurrentUser = async () => {
      try {
        const cached = authService.getCachedUser();
        if (cached) {
          if (mounted) setCurrentUser(cached);
          return;
        }
        const user = await authService.getCurrentUser();
        if (mounted) setCurrentUser(user);
      } catch {
        if (mounted) setCurrentUser(null);
      }
    };
    void loadCurrentUser();
    return () => {
      mounted = false;
    };
  }, []);

  const avatarLabel = useMemo(() => {
    const source = (currentUser?.name || currentUser?.email || '').trim();
    if (!source) return isSuperAdmin ? 'S' : 'A';
    const words = source.split(/\s+/).filter(Boolean);
    if (words.length === 1) return words[0].slice(0, 2).toUpperCase();
    return words
      .slice(0, 2)
      .map((w) => w[0])
      .join('')
      .toUpperCase();
  }, [currentUser?.name, currentUser?.email, isSuperAdmin]);

  const userMenu = (
    <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleMenuClose}>
      <MenuItem disabled sx={{ opacity: 1, cursor: 'default' }}>
        <Chip
          label={
            isSuperAdmin
              ? 'Super Admin (Full Access)'
              : isDelegatedAdmin
                ? 'Delegated Admin (View Only)'
                : 'No Admin Privileges'
          }
          color={isSuperAdmin ? 'success' : isDelegatedAdmin ? 'warning' : 'default'}
          size="small"
          sx={{ fontFamily: T.font }}
        />
      </MenuItem>
      <MenuItem onClick={handleLogout}>
        <ListItemIcon>
          <LogOut size={18} strokeWidth={LU} />
        </ListItemIcon>
        Logout
      </MenuItem>
    </Menu>
  );

  const layoutTree = (
    <Box sx={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
      <FontLinks />
      <AppBar
        position="fixed"
        elevation={0}
        sx={{
          width: '100%',
          borderBottom: (th) => `1px solid ${pick(th, 'rgba(0,0,0,0.08)', 'rgba(255,255,255,0.10)')}`,
          backdropFilter: 'blur(8px)',
        }}
      >
        <Toolbar sx={{ minHeight: { xs: 48, sm: 52 }, gap: 1.25 }}>
          <Box
            component={RouterLink}
            to="/"
            aria-label="GWS Security home"
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 1.25,
              minWidth: 0,
              color: 'inherit',
              textDecoration: 'none',
            }}
          >
            <AppMark />
            <Typography
              component="span"
              sx={{
                fontFamily: T.font,
                fontWeight: 700,
                fontSize: '0.875rem',
                letterSpacing: '-0.02em',
                color: 'inherit',
                lineHeight: 1.2,
              }}
            >
              GWS Security
            </Typography>
          </Box>
          <Box sx={{ flexGrow: 1 }} />
          <Box
            onClick={toggleColorMode}
            role="switch"
            aria-checked={mode === 'dark'}
            aria-label="Toggle color mode"
            sx={{
              display: 'inline-flex',
              borderRadius: '8px',
              bgcolor: 'rgba(255,255,255,0.1)',
              p: '3px',
              gap: '2px',
              cursor: 'pointer',
              flexShrink: 0,
            }}
          >
            {(
              [
                { label: 'light', icon: <Sun size={15} strokeWidth={1.75} /> },
                { label: 'dark', icon: <Moon size={15} strokeWidth={1.75} /> },
              ] as const
            ).map(({ label, icon }) => {
              const active = mode === label;
              return (
                <Box
                  key={label}
                  sx={{
                    px: 1.25,
                    py: 0.5,
                    borderRadius: '6px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: active ? (mode === 'dark' ? '#1a1a2e' : '#1a1a1a') : 'rgba(255,255,255,0.6)',
                    bgcolor: active ? '#ffffff' : 'transparent',
                    boxShadow: active ? '0 1px 3px rgba(0,0,0,0.18)' : 'none',
                    transition: 'all 0.18s ease',
                    userSelect: 'none',
                  }}
                >
                  {icon}
                </Box>
              );
            })}
          </Box>
          <IconButton
            onClick={handleMenuClick}
            aria-label="Account menu"
            aria-haspopup="true"
            aria-expanded={Boolean(anchorEl)}
            sx={{ p: 0.25 }}
          >
            <Avatar
              src={currentUser?.picture}
              alt={currentUser?.name || currentUser?.email || 'User'}
              sx={{
                width: 28,
                height: 28,
                fontSize: '0.6875rem',
                fontWeight: 600,
                bgcolor: (th) => pick(th, '#e4e4e7', '#3f3f46'),
                color: (t) => textSecondary(t),
              }}
            >
              {avatarLabel}
            </Avatar>
          </IconButton>
        </Toolbar>
      </AppBar>
      {userMenu}
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          height: '100vh',
          overflowY: 'auto',
          overflowX: 'hidden',
          width: '100%',
        }}
      >
        <Toolbar sx={{ minHeight: { xs: 48, sm: 52 } }} />
        <Box
          sx={{
            width: '100%',
            maxWidth: PAGE_MAX_WIDTH,
            mx: 'auto',
            boxSizing: 'border-box',
            px: { xs: 3, sm: 4, md: 5, lg: 6 },
            pt: { xs: 4, sm: 5, md: 6, lg: 8 },
            pb: { xs: 5, sm: 6, md: 8, lg: 10 },
          }}
        >
          {permissions.error && (
            <Alert
              severity="warning"
              sx={{ mb: 3 }}
              action={
                <MuiButton color="inherit" size="small" onClick={() => permissions.refresh()}>
                  Retry
                </MuiButton>
              }
            >
              Some permissions couldn&apos;t be loaded, so parts of the app may be hidden or disabled.{' '}
              {permissions.error}
            </Alert>
          )}
          {children}
        </Box>
      </Box>
    </Box>
  );

  return <MuiThemeProviderNested theme={nestedMuiTheme}>{layoutTree}</MuiThemeProviderNested>;
}
