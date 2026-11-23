import { test, expect } from '@playwright/test';
import { env } from 'node:process';

test('upload -> continuous worker -> R01 -> snapshot graph -> template -> evidence', async ({ page }) => {
  await page.goto(env.D3_E2E_URL!);
  await page.getByLabel('角色令牌').fill(env.D3_E2E_TOKEN!);
  await page.getByRole('button', { name: '连接 / 刷新' }).click();
  await page.getByLabel('新数据集名称').fill('D3 browser synthetic');
  await page.getByRole('button', { name: '创建合成数据集' }).click();
  await expect(page.getByRole('combobox', { name: '数据集', exact: true })).not.toHaveValue('');
  await page.getByLabel('JSONL 文件').setInputFiles(env.D3_E2E_FILE!);
  await page.getByRole('button', { name: '上传日志', exact: true }).click();
  await expect(page.getByText(/succeeded · 新增 24/)).toBeVisible({ timeout: 30000 });
  await page.getByRole('button', { name: '刷新事件', exact: true }).click();
  await expect(page.getByRole('cell', { name: 'network.connection', exact: true }).first()).toBeVisible();
  await page.getByRole('button', { name: '安全事件' }).click();
  await page.getByRole('button', { name: '刷新检测事件' }).click();
  await page.getByRole('button', { name: '开始调查' }).click();
  await expect(page.getByRole('heading', { name: '确定性模板报告', exact: true })).toBeVisible({ timeout: 30000 });
  await expect(page.getByRole('heading', { name: '证据关系图', exact: true })).toBeVisible();
  await expect(page.getByText(/证据不足，未生成路径/)).toBeVisible();
  await page.getByRole('button', { name: '证据 1', exact: true }).click();
  await expect(page.getByRole('heading', { name: '证据抽屉 · 已核验哈希的脱敏投影' })).toBeVisible();
  await expect(page.getByText(/行 1:/)).toBeVisible();
  await page.screenshot({ path: '../../artifacts/d3-browser/closed-loop.png', fullPage: true });
});
