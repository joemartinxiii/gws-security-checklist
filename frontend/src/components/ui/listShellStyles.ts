import type { Theme } from '@mui/material/styles';
import { T, pick } from '../../theme/designTokens';

/** Outer bordered container for flex-based data lists */
export function listShellSx(theme: Theme) {
  return {
    border: `1px solid ${pick(theme, T.border, '#3f3f46')}`,
    borderRadius: T.radiusLg,
    overflowX: 'hidden' as const,
    overflowY: 'hidden' as const,
    bgcolor: pick(theme, T.surface, '#18181b'),
  };
}

/** Flexible text column. Use grow weights so columns share width evenly. */
export function listGrowSx(grow = 1, minWidth = 120): {
  flex: string;
  minWidth: number;
  overflow: 'hidden';
} {
  return {
    flex: `${grow} 1 0px`,
    minWidth,
    overflow: 'hidden',
  };
}
