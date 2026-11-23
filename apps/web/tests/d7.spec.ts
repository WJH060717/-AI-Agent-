import { test, expect } from '@playwright/test';
import { env } from 'node:process';

test('D7 R05/R06 -> two controlled tools -> cited before/after countercontext -> bounded stop', async ({ page }) => {
  await page.goto(env.D3_E2E_URL!);
  await page.getByLabel('角色令牌').fill(env.D3_E2E_TOKEN!);
  await page.getByRole('button', { name: '连接 / 刷新' }).click();
  await page.getByLabel('新数据集名称').fill('D7 evidence changes');
  await page.getByRole('button', { name: '创建合成数据集' }).click();
  await expect(page.getByRole('combobox', { name: '数据集', exact: true })).not.toHaveValue('');
  await page.getByLabel('上下文 JSON').setInputFiles(`${env.D7_E2E_DIR}/context.json`);
  await page.getByRole('button', { name: '配置上下文', exact: true }).click();
  await expect(page.getByText(/上下文已封存/)).toBeVisible();
  for (const [source, sensor, file, count] of [['zeek', 'net-a', 'network', 9], ['linux_audit', 'audit-a', 'audit', 2]] as const) {
    await page.getByRole('combobox', { name: '来源', exact: true }).selectOption(source);
    await page.getByLabel('传感器', { exact: true }).fill(sensor);
    await page.getByLabel('JSONL 文件').setInputFiles(`${env.D7_E2E_DIR}/${file}.jsonl`);
    const uploaded = page.waitForResponse(r => r.url().endsWith('/api/v1/imports') && r.request().method() === 'POST');
    await page.getByRole('button', { name: '上传日志', exact: true }).click();
    expect((await uploaded).status()).toBe(202);
    await expect(page.getByText(new RegExp(`succeeded · 新增 ${count}`))).toBeVisible({ timeout: 30000 });
  }
  await page.getByRole('button', { name: '安全事件' }).click();
  await page.getByRole('button', { name: '刷新检测事件' }).click();
  await expect(page.getByRole('listitem').filter({ hasText: 'R05 / R06 聚合调查候选' })).toBeVisible();
  await page.getByRole('combobox', { name: '调查模式', exact: true }).selectOption('live');
  await page.getByRole('button', { name: '开始调查', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Agent 调查报告', exact: true })).toBeVisible({ timeout: 30000 });
  await expect(page.getByRole('heading', { name: '缺口补证与分析变化', exact: true })).toBeVisible();
  const comparison = page.getByRole('region', { name: '补证前后对比' });
  await expect(comparison).toContainText('种子证据 9 条 → 已核查证据 11 条');
  await expect(comparison).toContainText('ACTIONABLE_GAPS_RESOLVED');
  await expect(comparison.getByRole('cell', { name: '待补证', exact: true })).toHaveCount(2);
  await expect(comparison.getByRole('cell', { name: '恶意解释被削弱', exact: true })).toHaveCount(2);
  await expect(comparison).toContainText('不证明流量归属或没有攻击');
  await comparison.getByRole('button', { name: '查看补证依据' }).first().click();
  await expect(page.getByRole('heading', { name: '证据抽屉 · 已核验哈希的脱敏投影' })).toBeVisible();
  await expect(page.locator('main')).toContainText(/\/usr\/bin\/(node_exporter|rsync)/);
  await page.getByRole('button', { name: '刷新 Agent 记录', exact: true }).click();
  await expect(page.getByRole('cell', { name: 'get_asset_timeline', exact: true })).toBeVisible();
  await expect(page.getByRole('cell', { name: 'get_event_evidence', exact: true })).toBeVisible();
  await expect(page.getByText('本地协议测试桩（非真实LLM）', { exact: true })).toBeVisible();
  await expect(page.locator('main')).not.toContainText('local-browser-dummy');
  await expect(page.locator('main')).not.toContainText('demo-user');
  await page.screenshot({ path: '../../artifacts/d7-browser/closed-loop.png', fullPage: true });
});
