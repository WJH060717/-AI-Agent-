import { test, expect } from '@playwright/test';
import { env } from 'node:process';

test('D4 context + network/auth/audit -> R02 -> graph/report/evidence', async ({ page }) => {
  await page.goto(env.D3_E2E_URL!);
  await page.getByLabel('角色令牌').fill(env.D3_E2E_TOKEN!);
  await page.getByRole('button', { name: '连接 / 刷新' }).click();
  await page.getByLabel('新数据集名称').fill('D4 browser synthetic');
  await page.getByRole('button', { name: '创建合成数据集' }).click();
  await expect(page.getByRole('combobox', { name: '数据集', exact: true })).not.toHaveValue('');
  await page.getByLabel('上下文 JSON').setInputFiles(`${env.D4_E2E_DIR}/context.json`);
  await page.getByRole('button', { name: '配置上下文', exact: true }).click();
  await expect(page.getByText(/上下文已封存/)).toBeVisible();
  for (const [source, sensor, file, count] of [
    ['zeek', 'net-a', 'network', 6], ['linux_auth', 'auth-a', 'auth_positive', 6],
    ['linux_audit', 'audit-a', 'audit', 1],
  ] as const) {
    await page.getByRole('combobox', { name: '来源', exact: true }).selectOption(source);
    await page.getByLabel('传感器', { exact: true }).fill(sensor);
    await page.getByLabel('JSONL 文件').setInputFiles(`${env.D4_E2E_DIR}/${file}.jsonl`);
    await page.getByRole('button', { name: '上传日志', exact: true }).click();
    await expect(page.getByText(new RegExp(`succeeded · 新增 ${count}`))).toBeVisible({ timeout: 30000 });
  }
  await expect(page.getByText(/物理记录 3 · 已聚合记录 3/)).toBeVisible();
  await page.getByRole('button', { name: '安全事件' }).click();
  await page.getByRole('button', { name: '刷新检测事件' }).click();
  await expect(page.getByRole('listitem').filter({ hasText: 'R02 认证失败后成功候选' })).toBeVisible();
  await page.getByRole('button', { name: '开始调查' }).click();
  await expect(page.getByRole('heading', { name: '确定性模板报告', exact: true })).toBeVisible({ timeout: 30000 });
  await expect(page.getByRole('heading', { name: '证据关系图', exact: true })).toBeVisible();
  await page.getByText('展开全部边及证据', { exact: true }).click();
  await expect(page.getByText(/associated_process/).first()).toBeVisible();
  await page.getByRole('button', { name: '证据 1', exact: true }).click();
  await expect(page.getByText(/行 1:/)).toBeVisible();
  await expect(page.getByText(/user_redacted/)).toBeVisible();
  await expect(page.locator('main')).not.toContainText('demo-user');
  await page.screenshot({ path: '../../artifacts/d4-browser/closed-loop.png', fullPage: true });
});
