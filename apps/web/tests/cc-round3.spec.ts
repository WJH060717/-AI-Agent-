import { test, expect } from '@playwright/test';
import { env } from 'node:process';

test('C&C candidate, normal control, evidence and report in isolated environment', async ({ page }) => {
  test.skip(!env.CC3_E2E_URL, 'Requires independent round3 environment');
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.goto(env.CC3_E2E_URL!);
  await page.getByLabel('访问令牌', { exact: true }).fill(env.CC3_E2E_TOKEN!);
  await page.getByRole('button', { name: '连接', exact: true }).click();
  await expect(page.getByTestId('active-session')).toContainText('CTU-13');
  await page.getByText('切换或新建数据集', { exact: true }).click();
  await page.getByRole('combobox', { name: '数据集', exact: true }).selectOption(env.CC3_E2E_DATASET!);
  await page.getByLabel('日志文件', { exact: true }).setInputFiles(`${env.CC3_E2E_SAMPLE}/zeek_http.jsonl`);
  await expect(page.getByRole('combobox', { name: '日志类型', exact: true })).toHaveValue('zeek_http');
  await page.getByLabel('传感器', { exact: true }).fill('ctu13-s07-bro');
  await page.getByRole('button', { name: '上传日志', exact: true }).click();
  await expect(page.getByTestId('import-status')).toContainText('导入完成', { timeout: 30000 });
  await expect(page.getByTestId('import-status')).toContainText('新增 0');
  await page.getByRole('button', { name: '查看异常', exact: true }).first().click();
  const cc = page.locator('.incident-list > li').filter({ hasText: /R0[89]|R10/ });
  await expect(cc).toHaveCount(Number(env.CC3_E2E_COUNT));
  if (Number(env.CC3_E2E_REPORTS) > 0) {
    const item = Number(env.CC3_E2E_COUNT) ? cc.first() : page.locator('.incident-list > li').first();
    await item.getByRole('button', { name: '查看历史报告' }).click();
    await page.getByRole('region', { name: '已有报告版本' }).getByRole('button', { name: '载入报告' }).first().click();
    const report = page.getByRole('region', { name: '报告与人工复核' });
    await expect(report).toContainText('deterministic_fallback');
    await report.getByText('适用限制', { exact: true }).first().click();
    if (Number(env.CC3_E2E_COUNT)) await expect(report).toContainText('失败');
    await report.locator('summary').filter({ hasText: /^查看证据/ }).first().click();
    const buttons = report.getByRole('button', { name: /^证据 \d/ });
    let sawShape = false;
    for (let index = 0; index < await buttons.count(); index++) {
      await buttons.nth(index).click();
      const dialog = page.getByRole('dialog');
      await expect(dialog).toContainText('SHA-256');
      const content = await dialog.textContent();
      if (content?.includes('query_shape')) sawShape = true;
      expect(content).not.toContain('user_agent":');
      expect(content).not.toContain('"uri":');
      expect(content).not.toContain('uri_b64');
      expect(content).not.toContain('user_agent_b64');
      await page.keyboard.press('Escape');
    }
    if (Number(env.CC3_E2E_COUNT)) expect(sawShape).toBe(true);
    const downloaded = page.waitForEvent('download');
    await report.getByRole('button', { name: '导出 HTML' }).click();
    expect((await downloaded).suggestedFilename()).toContain('.html');
  }
  await page.screenshot({ path: `${env.CC3_E2E_ARTIFACTS}/browser-result.png`, fullPage: true });
  expect(errors).toEqual([]);
});
