import { test, expect, type Page } from '@playwright/test';
import { env } from 'node:process';

async function connect(page: Page) {
  await page.goto(env.CTU_E2E_URL!);
  await page.getByLabel('访问令牌', { exact: true }).fill(env.CTU_E2E_TOKEN!);
  await page.getByRole('button', { name: '连接', exact: true }).click();
  await expect(page.getByTestId('active-session')).toContainText('CTU-13');
}

test('CTU-13 real sample: events and actual detection results', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await connect(page);
  await page.getByText('切换或新建数据集', { exact: true }).click();
  await expect(page.getByRole('combobox', { name: '数据集', exact: true })).toHaveValue(env.CTU_E2E_DATASET!);
  await expect(page.getByRole('combobox', { name: '数据集', exact: true })).toContainText('derived');
  await page.getByText('原始事件查询', { exact: true }).click();
  await expect(page.locator('tbody tr:visible')).toHaveCount(Math.min(20, Number(env.CTU_E2E_COUNT)));
  await page.getByText('查看事件与引用', { exact: true }).first().click();
  await expect(page.locator('pre:visible').first()).toContainText('2011-08-16');
  if (Number(env.CTU_E2E_COUNT) > 20) {
    await page.getByRole('button', { name: '下一页', exact: true }).click();
    await expect(page.locator('tbody tr:visible')).toHaveCount(Math.min(20, Number(env.CTU_E2E_COUNT) - 20));
  }
  await page.getByRole('button', { name: '查看异常', exact: true }).first().click();
  if (Number(env.CTU_E2E_INCIDENTS) === 0) {
    await expect(page.getByText('当前没有规则命中；这不证明没有攻击。', { exact: true })).toBeVisible();
  } else {
    await expect(page.getByRole('button', { name: '开始调查', exact: true }).first()).toBeVisible();
  }
  expect(errors).toEqual([]);
});

test('CTU-13 real sample: original evidence and deterministic report', async ({ page }) => {
    test.skip(Number(env.CTU_E2E_REPORTS) === 0, 'This sample did not produce a report; not verified here');
    const writes: string[] = [];
    const errors: string[] = [];
    page.on('request', request => { if (request.method() === 'POST') writes.push(request.url()); });
    page.on('pageerror', error => errors.push(error.message));
    await connect(page);
    await page.getByRole('button', { name: '查看异常', exact: true }).first().click();
    await page.getByRole('button', { name: '查看历史报告' }).first().click();
    await page.getByRole('region', { name: '已有报告版本' }).getByRole('button', { name: '载入报告' }).first().click();
    const report = page.getByRole('region', { name: '报告与人工复核' });
    await expect(report).toBeVisible();
    await expect(report).toContainText('deterministic_fallback');
    await report.locator('summary').filter({ hasText: /^查看证据/ }).first().click();
    await report.getByRole('button', { name: /^证据 \d/ }).first().click();
    await expect(page.getByRole('dialog')).toContainText('131349');
    await expect(page.getByRole('dialog')).toContainText('SHA-256');
    await page.keyboard.press('Escape');
    await page.getByRole('button', { name: '关系与时间线', exact: true }).click();
    await expect(page.getByRole('heading', { name: '冻结快照时间线' })).toBeVisible();
    await expect(page.getByRole('heading', { name: '证据关系图' })).toBeVisible();
    await page.getByRole('button', { name: '运行记录', exact: true }).click();
    await page.getByRole('button', { name: '刷新 Agent 记录' }).click();
    await expect(page.getByText(/模型预算 0\//)).toBeVisible();
    await page.getByRole('button', { name: '结论', exact: true }).click();
    const download = page.waitForEvent('download');
    await report.getByRole('button', { name: '导出 HTML' }).click();
    expect((await download).suggestedFilename()).toContain('.html');
    await page.screenshot({ path: `${env.TRACE_E2E_ARTIFACTS}/report-browser.png`, fullPage: true });
  expect(writes).toEqual([]);
  expect(errors).toEqual([]);
});

test('CTU-13 real sample: oversized investigation is explicitly refused', async ({ page }) => {
  test.skip(Number(env.CTU_E2E_BLOCKED) === 0, 'No oversized investigation in this sample');
  await connect(page);
  await page.getByRole('button', { name: '查看异常', exact: true }).first().click();
  await page.getByText('调查设置', { exact: true }).click();
  await page.getByRole('combobox', { name: '调查模式', exact: true }).selectOption('deterministic');
  await page.getByRole('button', { name: '开始调查', exact: true }).first().click();
  await expect(page.getByRole('alert')).toContainText('SNAPSHOT_EMPTY_OR_TOO_LARGE');
  await expect(page.getByTestId('active-session')).toContainText('CTU-13');
});
