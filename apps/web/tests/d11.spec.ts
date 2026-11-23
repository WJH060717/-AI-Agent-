import { expect, test } from '@playwright/test';
import { env } from 'node:process';

test('D11 empty, no-hit and detection-limited states are distinct on the real API', async ({ page }) => {
  await page.goto(env.D3_E2E_URL!);
  await page.getByLabel('角色令牌').fill(env.D3_E2E_TOKEN!);
  await page.getByRole('button', { name: '连接 / 刷新' }).click();
  await page.getByLabel('新数据集名称').fill('<img src=x onerror="window.d11Xss=1"> D11 empty');
  await page.getByRole('button', { name: '创建合成数据集' }).click();
  await expect(page.getByRole('combobox', { name: '数据集', exact: true }).locator('option:checked')).toContainText('D11 empty');
  await page.getByRole('button', { name: '刷新事件', exact: true }).click();
  await expect(page.getByText('当前数据集暂无规范事件。')).toBeVisible();
  await page.getByRole('button', { name: '安全事件' }).click();
  await expect(page.getByText('尚未查询检测结果。')).toBeVisible();
  await page.getByRole('button', { name: '刷新检测事件' }).click();
  await expect(page.getByText('当前数据集暂无规范事件，尚不能进行检测。')).toBeVisible();
  await expect(page.getByRole('button', { name: '开始调查', exact: true })).toHaveCount(0);
  await page.screenshot({ path: `${env.TRACE_E2E_ARTIFACTS}/empty.png`, fullPage: true });

  for (const [index, count] of [[0, 1], [1, 2]]) {
    await page.getByRole('button', { name: '概览与导入' }).click();
    const rows = Array.from({ length: count }, (_, i) => JSON.stringify({
      ts: 1794618000 + index * 10 + i, uid: `d11-${index}-${i}`, 'id.orig_h': '192.0.2.10',
      'id.orig_p': 42000 + i, 'id.resp_h': '10.10.0.20', 'id.resp_p': 443, proto: 'tcp', synthetic: true,
    })).join('\n') + '\n';
    await page.getByLabel('JSONL 文件').setInputFiles({ name: 'synthetic.jsonl', mimeType: 'application/x-ndjson', buffer: Buffer.from(rows) });
    await page.getByRole('button', { name: '上传日志', exact: true }).click();
    await expect(page.getByText(new RegExp(`${index ? 'partial' : 'succeeded'} · 新增 ${count}`))).toBeVisible({ timeout: 30000 });
    await page.getByRole('button', { name: '安全事件' }).click();
    await page.getByRole('button', { name: '刷新检测事件' }).click();
    if (index === 0) {
      await expect(page.getByText('已查询，当前没有规则命中；这不证明没有攻击。')).toBeVisible();
      await page.screenshot({ path: `${env.TRACE_E2E_ARTIFACTS}/no-hit.png`, fullPage: true });
    } else {
      await expect(page.getByRole('alert')).toContainText('检测范围超限');
      await expect(page.getByText('检测覆盖不足，不能据此判断是否存在规则命中。')).toBeVisible();
      await page.screenshot({ path: `${env.TRACE_E2E_ARTIFACTS}/partial.png`, fullPage: true });
    }
  }
  expect(await page.evaluate(() => Reflect.get(window, 'd11Xss'))).toBeUndefined();
  await expect(page.getByRole('button', { name: '开始调查', exact: true })).toHaveCount(0);
});
