import { expect, test } from '@playwright/test';

const base = process.env.IMPORT_SENSOR_E2E_URL;
const dataset = {
  dataset_id: '10000000-0000-0000-0000-000000000001',
  default_session_id: '10000000-0000-0000-0000-000000000002',
  name: '测试工作区',
  provenance_type: 'synthetic',
};

test.skip(!base, 'IMPORT_SENSOR_E2E_URL is required');
test.use({ channel: process.env.IMPORT_SENSOR_E2E_CHANNEL });

for (const ambiguous of [false, true]) {
  test(ambiguous ? 'choose a sensor after an ambiguous upload' : 'upload with the sensor blank', async ({ page }) => {
    let attempts = 0;
    await page.route('**/api/v1/health/live', route => route.fulfill({ json: { status: 'ok' } }));
    await page.route('**/api/v1/datasets', route => route.fulfill({
      json: { items: [dataset], next_cursor: null, request_id: 'datasets' },
    }));
    await page.route('**/api/v1/imports', async route => {
      attempts++;
      const request = route.request().postData() ?? '';
      if (attempts === 1) {
        expect(request).not.toContain('name="sensor_id"');
        if (ambiguous) {
          await route.fulfill({
            status: 422,
            json: { error: {
              code: 'SENSOR_SELECTION_REQUIRED',
              details: { sensor_ids: ['capture-a', 'capture-b'] },
            } },
          });
          return;
        }
      } else {
        expect(request).toContain('name="sensor_id"');
        expect(request).toContain('capture-b');
      }
      await route.fulfill({ status: 202, json: { batch_id: 'batch-1', job_id: 'job-1' } });
    });
    await page.route('**/api/v1/imports/batch-1', route => route.fulfill({
      json: { status: 'succeeded', accepted: 1, duplicate: 0, quarantined: 0, raw_records: 1 },
    }));
    await page.goto(base!);
    await page.getByLabel('访问令牌', { exact: true }).fill('browser-test-token');
    await page.getByRole('button', { name: '连接', exact: true }).click();
    await page.getByLabel('日志文件', { exact: true }).setInputFiles({
      name: 'neutral.pcap',
      mimeType: 'application/octet-stream',
      buffer: Buffer.from('d4c3b2a1020004000000000000000000ffff000001000000', 'hex'),
    });
    await expect(page.getByRole('combobox', { name: '日志类型', exact: true })).toHaveValue('pcap_packet');
    const sensor = page.getByRole('combobox', { name: '传感器', exact: true });
    await expect(sensor).toHaveValue('');
    await page.getByRole('button', { name: '上传日志', exact: true }).click();
    if (ambiguous) {
      await expect(page.getByRole('alert')).toContainText('有多个匹配的采集点');
      await expect(page.locator('datalist option[value="capture-b"]')).toHaveCount(1);
      await expect(sensor).toBeEnabled();
      await sensor.fill('capture-b');
      await page.getByRole('button', { name: '上传日志', exact: true }).click();
    }
    await expect(page.getByTestId('import-status')).toContainText('导入完成');
    expect(attempts).toBe(ambiguous ? 2 : 1);
  });
}
