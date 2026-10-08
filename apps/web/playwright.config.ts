import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: './e2e',
  testMatch: '**/*.spec.ts',
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  forbidOnly: !!process.env.CI,
  timeout: 45_000,
  expect: { timeout: 10_000 },
  reporter: [['list'], ['html', { open: 'never', outputFolder: 'playwright-report' }]],
  use: {
    ...devices['Desktop Chrome'],
    baseURL: 'http://127.0.0.1:14173',
    channel: process.env.PLAYWRIGHT_CHANNEL || undefined,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  webServer: [
    {
      command: `'${(process.env.EGRESSDECK_E2E_GO || 'go').replaceAll("'", "'\\''")}' run ./apps/web/e2e/controller`,
      env: { GOCACHE: process.env.EGRESSDECK_E2E_GOCACHE || '/tmp/egressdeck-go-cache' },
      cwd: '../..',
      url: 'http://127.0.0.1:18080/healthz',
      timeout: 120_000,
      gracefulShutdown: { signal: 'SIGTERM', timeout: 5_000 },
      reuseExistingServer: false,
    },
    {
      command: 'npm run dev -- --config e2e/vite.config.ts',
      url: 'http://127.0.0.1:14173',
      timeout: 60_000,
      reuseExistingServer: false,
    },
  ],
})
