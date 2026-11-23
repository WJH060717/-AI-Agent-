import { test, expect } from '@playwright/test';
import { env } from 'node:process';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

for (const scenario of ['S1', 'S2', 'S3'] as const) {
  test(`D9 ${scenario}: synthetic evidence -> report -> review -> offline export -> exact cached view`, async ({ page, context }) => {
    await page.goto(env.D3_E2E_URL!);
    await page.getByLabel('角色令牌').fill(env.D3_E2E_TOKEN!);
    await page.getByRole('button', { name: '连接 / 刷新' }).click();
    await page.getByLabel('新数据集名称').fill(`D9 ${scenario} synthetic engineering check`);
    await page.getByRole('button', { name: '创建合成数据集' }).click();
    await expect(page.getByRole('combobox', { name: '数据集', exact: true }).locator('option:checked')).toContainText(`D9 ${scenario} synthetic engineering check`);
    const datasetId = await page.getByRole('combobox', { name: '数据集', exact: true }).inputValue();
    const folder = scenario === 'S1' ? env.D6_E2E_DIR : env.D7_E2E_DIR;
    await page.getByLabel('上下文 JSON').setInputFiles(`${folder}/context.json`);
    await page.getByRole('button', { name: '配置上下文', exact: true }).click();
    await expect(page.getByText(/上下文已封存/)).toBeVisible();
    const sources: [string, string, string, number][] = scenario === 'S1'
      ? [['zeek', 'net-a', 'network', 26], ['linux_auth', 'auth-a', 'auth_a', 6], ['linux_audit', 'audit-a', 'audit', 3], ['linux_auth', 'auth-b', 'auth_b', 1], ['suricata', 'alert-a', 'alerts', 1]]
      : scenario === 'S2' ? [['zeek', 'net-a', 'network', 9], ['linux_audit', 'audit-a', 'audit', 2]] : [['zeek', 'net-a', 'network', 9]];
    for (const [source, sensor, file, count] of sources) {
      await page.getByRole('combobox', { name: '来源', exact: true }).selectOption(source);
      await page.getByLabel('传感器', { exact: true }).fill(sensor);
      await page.getByLabel('JSONL 文件').setInputFiles(`${folder}/${file}.jsonl`);
      await page.getByRole('button', { name: '上传日志', exact: true }).click();
      await expect(page.getByText(new RegExp(`succeeded · 新增 ${count}`))).toBeVisible({ timeout: 30000 });
    }
    await page.getByRole('button', { name: '安全事件' }).click();
    await page.getByRole('button', { name: '刷新检测事件' }).click();
    await page.getByRole('combobox', { name: '调查模式', exact: true }).selectOption('live');
    if (scenario === 'S3') await page.getByLabel('模型调用上限').fill('0');
    await page.getByRole('button', { name: '开始调查', exact: true }).first().click();
    const report = page.getByRole('region', { name: '报告与人工复核' });
    await expect(report).toBeVisible({ timeout: 30000 });
    if (scenario === 'S3') await expect(page.getByRole('region', { name: '缺证与校验' })).toContainText('调查未完成');
    if (scenario === 'S2') await expect(page.getByRole('region', { name: '补证前后对比' })).toContainText('仅同窗正常进程上下文');
    await report.getByRole('button', { name: '复核本条' }).first().click();
    await report.getByLabel('复核决定').selectOption('needs_more_evidence');
    await report.getByLabel('复核说明').fill('<img src=x onerror="window.d9Xss=1">保留未知');
    await report.getByRole('button', { name: '保存复核意见' }).click();
    await expect(report.getByRole('list', { name: '人工复核记录' })).toContainText('保留未知');
    expect(await page.evaluate(() => Reflect.get(window, 'd9Xss'))).toBeUndefined();
    for (const format of ['JSON', 'HTML'] as const) {
      const downloaded = page.waitForEvent('download');
      await report.getByRole('button', { name: `导出 ${format}` }).click();
      const download = await downloaded;
      const target = `${env.TRACE_E2E_ARTIFACTS ?? '../../artifacts/d9-browser'}/${scenario}.${format.toLowerCase()}`;
      await download.saveAs(target);
      const text = await readFile(target, 'utf8');
      if (format === 'JSON') {
        const value = JSON.parse(text);
        expect(value.evidence.length).toBeGreaterThan(0);
        expect(value.reviews).toHaveLength(1);
        expect(value.run_state).toBe(scenario === 'S3' ? 'partial' : 'completed');
      } else {
        const offline = await context.newPage();
        await offline.goto(pathToFileURL(resolve(target)).href);
        await expect(offline.getByRole('heading', { name: '证据目录', exact: true })).toBeVisible();
        await offline.getByRole('link').first().click();
        expect(offline.url()).toContain('#e-');
        expect(await offline.evaluate(() => Reflect.get(window, 'd9Xss'))).toBeUndefined();
        await offline.close();
      }
      expect(text).not.toContain('local-browser-dummy');
      expect(text).not.toContain('demo-user');
    }
    await report.getByRole('button', { name: '读取匹配缓存' }).click();
    await expect(report).toContainText('模式：cached');
    await expect(report).toContainText('历史结果');
    await report.getByRole('button', { name: '刷新报告版本' }).click();
    await expect(report.getByRole('button', { name: '打开历史版本' })).toHaveCount(1);
    await page.screenshot({ path: `${env.TRACE_E2E_ARTIFACTS ?? '../../artifacts/d9-browser'}/${scenario}.png`, fullPage: true });
    if (scenario === 'S3') {
      await page.reload();
      let createdRuns = 0;
      page.on('request', request => { if (request.method() === 'POST' && request.url().endsWith('/investigations')) createdRuns++; });
      await page.getByLabel('角色令牌').fill(env.D9_E2E_VIEWER!);
      await page.getByRole('button', { name: '连接 / 刷新' }).click();
      await page.getByRole('combobox', { name: '数据集', exact: true }).selectOption(datasetId);
      await page.getByRole('button', { name: /报告与运行记录/ }).click();
      await page.getByRole('button', { name: '刷新检测事件' }).click();
      await expect(page.getByRole('button', { name: '查看历史报告', exact: true }).first()).toBeVisible({ timeout: 2000 });
      await page.getByRole('button', { name: '查看历史报告', exact: true }).first().click();
      await page.getByRole('region', { name: '已有报告版本' }).getByRole('button', { name: '载入报告', exact: true }).click();
      await expect(report).toContainText('确定性模板报告');
      await report.getByRole('button', { name: '读取匹配缓存' }).click();
      await expect(report).toContainText('模式：cached');
      expect(createdRuns).toBe(0);
    }
  });
}
