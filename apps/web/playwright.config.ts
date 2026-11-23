import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests', workers: 1, timeout: 60000,
  outputDir: '../../artifacts/d3-browser/results',
  use: { headless: true, viewport: { width: 1440, height: 1000 }, trace: 'retain-on-failure' },
});
