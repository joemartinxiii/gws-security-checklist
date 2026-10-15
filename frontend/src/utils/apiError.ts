import { AxiosError } from 'axios';

interface ApiErrorBody {
  error?: string;
  hint?: string;
  code?: string;
}

/**
 * Produce a user-facing message from an API or network error.
 *
 * Prefers the backend's `error` message and appends its `hint` when present.
 * Falls back to defaults for 401, 403, 404, 429, and network failures.
 */
export function getApiErrorMessage(e: unknown, fallback = 'Something went wrong. Please try again.'): string {
  const err = e as AxiosError<ApiErrorBody>;

  // No response => network/timeout/CORS failure.
  if (err && err.isAxiosError && !err.response) {
    return 'Could not reach the server. Check your connection and try again.';
  }

  const status = err?.response?.status;
  const data = err?.response?.data;
  const base = data?.error;
  const hint = data?.hint;

  let message: string;
  if (status === 403) {
    message = base || "You don't have permission to perform this action.";
  } else if (status === 401) {
    message = base || 'Your session expired. Please sign in again.';
  } else if (status === 404) {
    message = base || 'The requested resource was not found.';
  } else if (status === 429) {
    message = base || 'Too many requests. Please wait a moment and try again.';
  } else {
    message = base || (err && err.message) || fallback;
  }

  return hint ? `${message} ${hint}` : message;
}
