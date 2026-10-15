import { defineConfig } from '@playwright/test';

// By default the tests run against the mock UI (MSW), which needs no Google
// credentials. Set E2E_BASE_URL to test a running server instead.
const externalBaseUrl = process.env.E2E_BASE_URL;
const baseURL = externalBaseUrl || 'http://localhost:3000';

export default defineConfig({
  testDir: 'tests/e2e',
  use: { baseURL },
  webServer: externalBaseUrl
    ? undefined
    : {
        command: 'npm run dev:frontend:msw',
        url: baseURL,
        reuseExistingServer: !process.env.CI,
        timeout: 120_000,
      },
});
