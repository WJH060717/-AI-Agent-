import { test, expect } from '@playwright/test';
import { identifySource } from '../src/importHints';
import { env } from 'node:process';

test('isolated real HTTP upload, evidence and report', async ({ page }) => {
  test.skip(!env.HTTP_E2E_URL, 'Independent real environment only');
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(env.HTTP_E2E_URL!);
  await page.getByLabel('访问令牌', { exact: true }).fill(env.HTTP_E2E_TOKEN!);
  await page.getByRole('button', { name: '连接', exact: true }).click();
  await expect(page.getByTestId('active-session')).toContainText('CTU-13');
  await page.getByText('切换或新建数据集', { exact: true }).click();
  await page.getByRole('combobox', { name: '数据集', exact: true }).selectOption(env.HTTP_E2E_DATASET!);
  await page.getByLabel('日志文件', { exact: true }).setInputFiles(`${env.HTTP_E2E_SAMPLE}/zeek_http.jsonl`);
  await expect(page.getByRole('combobox', { name: '日志类型', exact: true })).toHaveValue('zeek_http');
  await page.getByLabel('传感器', { exact: true }).fill('ctu13-s07-bro');
  await page.getByRole('button', { name: '上传日志', exact: true }).click();
  await expect(page.getByTestId('import-status')).toContainText('导入完成', { timeout: 30000 });
  await expect(page.getByTestId('import-status')).toContainText('新增 0');
  await page.getByRole('button', { name: '查看异常', exact: true }).first().click();
  if (Number(env.HTTP_E2E_REPORTS) > 0) {
    await page.getByRole('button', { name: '查看历史报告' }).first().click();
    await page.getByRole('region', { name: '已有报告版本' }).getByRole('button', { name: '载入报告' }).first().click();
    const report = page.getByRole('region', { name: '报告与人工复核' });
    await expect(report).toContainText('deterministic_fallback');
    await report.getByText('适用限制', { exact: true }).first().click();
    await expect(report).toContainText('恶意性未知');
    await report.locator('summary').filter({ hasText: /^查看证据/ }).first().click();
    const buttons = report.getByRole('button', { name: /^证据 \d/ });
    let sawHttp = false;
    for (let i = 0; i < await buttons.count(); i++) {
      await buttons.nth(i).click();
      const dialog = page.getByRole('dialog');
      await expect(dialog).toContainText('SHA-256');
      if ((await dialog.textContent())?.includes('uri_suffix')) sawHttp = true;
      await page.keyboard.press('Escape');
    }
    expect(sawHttp).toBe(true);
    const download = page.waitForEvent('download');
    await report.getByRole('button', { name: '导出 HTML' }).click();
    expect((await download).suggestedFilename()).toContain('.html');
  } else {
    await expect(page.getByText('当前没有规则命中；这不证明没有攻击。', { exact: true })).toBeVisible();
  }
  await page.screenshot({ path: `${env.HTTP_E2E_ARTIFACTS}/browser-result.png`, fullPage: true });
  expect(errors).toEqual([]);
});

test('HTTP and DNS are distinct Zeek formats; mixed files stay unknown', () => {
  const base = { ts: 1, uid: 'C', 'id.orig_h': '192.0.2.1', 'id.resp_h': '192.0.2.2' };
  const http = JSON.stringify({ ...base, method: 'GET', trans_depth: 1 });
  const dns = JSON.stringify({ ...base, query: 'example.com', qtype: 1 });
  expect(identifySource(http)).toBe('zeek_http');
  expect(identifySource(dns)).toBe('zeek_dns');
  expect(identifySource(`${http}\n${dns}`)).toBeNull();
  expect(identifySource(JSON.stringify({ ...base, trans_depth: 1, query: 'x' }))).toBeNull();
});
