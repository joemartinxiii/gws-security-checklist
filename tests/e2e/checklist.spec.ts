import { test, expect } from '@playwright/test';

test('loads checklist overview or empty state', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByText(/Security Checklist|No checklist snapshot yet/i).first()).toBeVisible({
    timeout: 15_000,
  });
});
