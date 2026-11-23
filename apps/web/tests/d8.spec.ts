import { test, expect } from '@playwright/test';
import { env } from 'node:process';
import type { Report } from '../../../packages/contracts/generated/api';

test('D8 missing host evidence and exhausted budget remain explicit, next run can supplement', async ({ page }) => {
  await page.goto(env.D3_E2E_URL!);
  await page.getByLabel('角色令牌').fill(env.D3_E2E_TOKEN!);
  await page.getByRole('button', { name: '连接 / 刷新' }).click();
  await page.getByLabel('新数据集名称').fill('D8 missing-source case');
  await page.getByRole('button', { name: '创建合成数据集' }).click();
  await expect(page.getByRole('combobox', { name: '数据集', exact: true })).not.toHaveValue('');
  await page.getByLabel('上下文 JSON').setInputFiles(`${env.D7_E2E_DIR}/context.json`);
  await page.getByRole('button', { name: '配置上下文', exact: true }).click();
  await expect(page.getByText(/上下文已封存/)).toBeVisible();
  async function upload(source: string, sensor: string, file: string, count: number) {
    await page.getByRole('combobox', { name: '来源', exact: true }).selectOption(source);
    await page.getByLabel('传感器', { exact: true }).fill(sensor);
    await page.getByLabel('JSONL 文件').setInputFiles(`${env.D7_E2E_DIR}/${file}.jsonl`);
    await page.getByRole('button', { name: '上传日志', exact: true }).click();
    await expect(page.getByText(new RegExp(`succeeded · 新增 ${count}`))).toBeVisible({ timeout: 30000 });
  }
  await upload('zeek', 'net-a', 'network', 9);
  await page.getByRole('button', { name: '安全事件' }).click();
  await page.getByRole('button', { name: '刷新检测事件' }).click();
  await page.getByRole('combobox', { name: '调查模式', exact: true }).selectOption('live');
  await page.getByLabel('模型调用上限').fill('0');
  await page.getByRole('button', { name: '开始调查', exact: true }).click();
  const panel = page.getByRole('region', { name: '缺证与校验' });
  await expect(panel).toBeVisible({ timeout: 30000 });
  await expect(panel).toContainText('调查未完成');
  await expect(panel).toContainText('MODEL_CALL_BUDGET_EXHAUSTED');
  await expect(panel).toContainText('不代表完整攻击链已获证实');
  await expect(panel).toContainText('normal_process_context');
  await expect(page.getByRole('region', { name: '补证前后对比' })).toContainText('种子证据 9 条 → 已核查证据 9 条');
  await page.screenshot({ path: `${env.TRACE_E2E_ARTIFACTS ?? '../../artifacts/d8-browser'}/missing-evidence.png`, fullPage: true });
  await page.getByRole('button', { name: '概览与导入' }).click();
  await upload('linux_audit', 'audit-a', 'audit', 2);
  await page.getByRole('button', { name: '安全事件' }).click();
  await page.getByRole('button', { name: '刷新检测事件' }).click();
  await page.getByLabel('模型调用上限').fill('4');
  await page.getByRole('button', { name: '开始调查', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Agent 调查报告', exact: true })).toBeVisible({ timeout: 30000 });
  await expect(panel).toContainText('有限事实校验');
  await expect(panel).toContainText('仍有未知项');
  await expect(panel).not.toContainText('MODEL_CALL_BUDGET_EXHAUSTED');
  await expect(page.getByRole('region', { name: '补证前后对比' })).toContainText('种子证据 9 条 → 已核查证据 11 条');
  await expect(page.getByText('本地协议测试桩（非真实LLM）', { exact: true })).toBeVisible();
  await page.screenshot({ path: `${env.TRACE_E2E_ARTIFACTS ?? '../../artifacts/d8-browser'}/closed-loop.png`, fullPage: true });
});


test('D8 current integrity failure is distinct from successful historical validation', async ({ page }) => {
  const { createElement } = await import('react');
  const { renderToStaticMarkup } = await import('react-dom/server');
  const { MissingEvidence } = await import('../src/MissingEvidence');
  const report: Report = {
    report_id: 'historical-report', run_id: 'completed-run', snapshot_id: 'frozen-snapshot',
    mode: 'deterministic_fallback' as const, generated_at: '2026-11-15T00:00:00Z',
    summary: 'historical result', claims: [], provenance: {}, validation: 'partial' as const,
    gaps: ['当前原始证据不可验证；历史报告内容未改写'],
    claim_validation: { method_version: 'finite_predicates@2.0.0' as const,
      integrity: 'verified' as const, validated_observed: 2, unknown_claims: 1,
      rejected_codes: [], repair_attempts: 0, stop_reason: null },
  };
  const html = renderToStaticMarkup(createElement(MissingEvidence, {
    report, status: null, busy: false, onEvidence: () => {},
  }));
  await page.setContent(html);
  const panel = page.getByRole('region', { name: '缺证与校验' });
  await expect(panel.getByRole('alert')).toContainText('当前原始证据不可验证');
  await expect(panel).toContainText('生成时的校验记录');
  await expect(panel).not.toContainText('有限事实校验完成');
  await expect(panel).not.toContainText('哈希验证说明归档未变');
  await expect(panel).not.toContainText('调查未完成');
});
