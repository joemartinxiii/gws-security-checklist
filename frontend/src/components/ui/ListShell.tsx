import { Box } from '@mui/material';
import type { Theme } from '@mui/material/styles';
import { T, pick } from '../../theme/designTokens';
import { listShellSx } from './listShellStyles';

export function ListShell({ children }: { children: React.ReactNode }) {
  return (
    <Box sx={(theme: Theme) => listShellSx(theme)}>{children}</Box>
  );
}

const rowBase = {
  display: 'flex',
  alignItems: 'center',
  gap: 1.5,
  px: 2,
  width: '100%',
  boxSizing: 'border-box' as const,
  minWidth: 0,
};

/** Header strip under the top border */
export function ListHeaderRow({ children }: { children: React.ReactNode }) {
  return (
    <Box
      sx={(theme: Theme) => ({
        ...rowBase,
        py: 1.125,
        borderBottom: `1px solid ${pick(theme, T.borderSubtle, '#27272a')}`,
        bgcolor: pick(theme, T.surfaceHover, '#1f1f23'),
      })}
    >
      {children}
    </Box>
  );
}

/** One data row with bottom divider */
export function ListDataRow({
  children,
  last,
  selected,
  onClick,
}: {
  children: React.ReactNode;
  last?: boolean;
  selected?: boolean;
  onClick?: () => void;
}) {
  const onKeyDown = onClick
    ? (event: React.KeyboardEvent) => {
        if (event.target !== event.currentTarget) return;
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          onClick();
        }
      }
    : undefined;

  return (
    <Box
      onClick={onClick}
      onKeyDown={onKeyDown}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      sx={(theme: Theme) => ({
        ...rowBase,
        py: 1.125,
        borderBottom: last ? 'none' : `1px solid ${pick(theme, T.borderSubtle, '#27272a')}`,
        cursor: onClick ? 'pointer' : 'default',
        bgcolor: selected ? pick(theme, T.accentSoft, 'rgba(26, 115, 232, 0.16)') : 'transparent',
        transition: 'background-color 0.12s ease',
        '&:hover': {
          bgcolor: selected
            ? pick(theme, T.accentSoft, 'rgba(26, 115, 232, 0.16)')
            : pick(theme, T.surfaceHover, '#27272a'),
        },
        '&:focus-visible': {
          outline: `2px solid ${theme.palette.primary.main}`,
          outlineOffset: -2,
        },
      })}
    >
      {children}
    </Box>
  );
}
