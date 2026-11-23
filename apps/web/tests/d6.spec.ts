import { test, expect } from '@playwright/test';
import { env } from 'node:process';

test('D6 four rules -> labelled HTTP stub -> controlled tools -> new evidence -> report', async ({ page }) => {
  await page.goto(env.D3_E2E_URL!);
  await page.getByLabel('角色令牌').fill(env.D3_E2E_TOKEN!);
  await page.getByRole('button', { name: '连接 / 刷新' }).click();
  await page.getByLabel('新数据集名称').fill('D6 browser protocol test');
  await page.getByRole('button', { name: '创建合成数据集' }).click();
  await expect(page.getByRole('combobox', { name: '数据集', exact: true })).not.toHaveValue('');
  await page.getByLabel('上下文 JSON').setInputFiles(`${env.D6_E2E_DIR}/context.json`);
  await page.getByRole('button', { name: '配置上下文', exact: true }).click();
  await expect(page.getByText(/上下文已封存/)).toBeVisible();
  for (const [source, sensor, file, count] of [
    ['zeek', 'net-a', 'network', 25], ['linux_auth', 'auth-a', 'auth_a', 6],
    ['linux_audit', 'audit-a', 'audit', 3], ['linux_auth', 'auth-b', 'auth_b', 1],
  ] as const) {
    await page.getByRole('combobox', { name: '来源', exact: true }).selectOption(source);
    await page.getByLabel('传感器', { exact: true }).fill(sensor);
    await page.getByLabel('JSONL 文件').setInputFiles(`${env.D6_E2E_DIR}/${file}.jsonl`);
    const uploaded = page.waitForResponse(r => r.url().endsWith('/api/v1/imports') && r.request().method() === 'POST');
    await page.getByRole('button', { name: '上传日志', exact: true }).click();
    expect((await uploaded).status()).toBe(202);
    await expect(page.getByText(new RegExp(`succeeded · 新增 ${count}`))).toBeVisible({ timeout: 30000 });
  }
  await page.getByRole('button', { name: '安全事件' }).click();
  await page.getByRole('button', { name: '刷新检测事件' }).click();
  await expect(page.getByRole('listitem').filter({ hasText: 'R01 / R02 / R03 / R04 聚合调查候选' })).toBeVisible();
  await page.getByRole('combobox', { name: '调查模式', exact: true }).selectOption('live');
  await page.getByRole('button', { name: '开始调查', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Agent 调查报告', exact: true })).toBeVisible({ timeout: 30000 });
  await expect(page.getByText('本地协议测试桩（非真实LLM）', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: '刷新 Agent 记录', exact: true }).click();
  await expect(page.getByRole('cell', { name: 'search_events', exact: true })).toBeVisible();
  await expect(page.getByRole('cell', { name: 'get_event_evidence', exact: true })).toBeVisible();
  await expect(page.getByText('补充证据 1 条', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: '查看工具证据' }).first().click();
  await expect(page.getByRole('heading', { name: '证据抽屉 · 已核验哈希的脱敏投影' })).toBeVisible();
  await expect(page.locator('main')).not.toContainText('demo-user');
  await expect(page.locator('main')).not.toContainText('local-browser-dummy');
  await page.screenshot({ path: '../../artifacts/d6-browser/closed-loop.png', fullPage: true });
});
