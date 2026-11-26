import { expect, test, type Page } from '@playwright/test';
import { env } from 'node:process';
import type { EvidenceResponse } from '../../../packages/contracts/generated/api';
import { identifySource } from '../src/importHints';

test.use({ actionTimeout: 10000 });

async function connect(page: Page, token = env.D3_E2E_TOKEN!) {
  await page.goto(env.D3_E2E_URL!);
  await page.getByLabel('访问令牌', { exact: true }).fill(token);
  await page.getByRole('button', { name: '连接', exact: true }).click();
  await expect(page.getByTestId('active-session')).toBeVisible();
}

test('auto-load: connection leads to anomalies without a refresh or automatic investigation', async ({ page }) => {
  let created = 0;
  page.on('request', r => { if (r.method() === 'POST' && r.url().endsWith('/investigations')) created++; });
  await connect(page);
  await page.getByRole('button', { name: '查看异常', exact: true }).first().click();
  await expect(page.getByRole('button', { name: '开始调查', exact: true }).first()).toBeVisible();
  await expect(page.getByRole('heading', { name: '导入日志', exact: true })).toBeHidden();
  expect(created).toBe(0);
  await page.getByRole('button', { name: '阅读报告', exact: true }).click();
  await expect(page.getByRole('button', { name: '选择异常', exact: true })).toBeVisible();
  expect(created).toBe(0);
});

test('retry: lost create response retains the same investigation and report read retry never creates another', async ({ page }) => {
  await connect(page);
  await page.getByRole('button', { name: '查看异常', exact: true }).first().click();
  await page.getByText('调查设置', { exact: true }).click();
  await page.getByRole('combobox', { name: '调查模式', exact: true }).selectOption('deterministic');
  const keys: string[] = [], runs: string[] = [];
  await page.route('**/incidents/*/investigations', async route => {
    keys.push(route.request().headers()['idempotency-key']);
    const response = await route.fetch(); runs.push((await response.json()).run_id);
    if (keys.length === 1) await route.abort('failed');
    else await route.fulfill({ response });
  });
  let failedRead = false;
  await page.route('**/reports/*', async route => {
    if (!failedRead && !route.request().url().includes('export')) {
      failedRead = true; await route.abort('failed');
    } else await route.continue();
  });
  await page.getByRole('button', { name: '开始调查', exact: true }).first().click();
  await page.getByRole('button', { name: '重试调查请求', exact: true }).click();
  await page.getByRole('button', { name: '重试读取结果', exact: true }).click();
  await expect(page.getByRole('region', { name: '报告与人工复核' })).toBeVisible();
  expect(keys).toHaveLength(2); expect(keys[0]).toBe(keys[1]); expect(runs[0]).toBe(runs[1]);
});

test('scope: replay pending and cancellation stay explicit; old session responses are discarded', async ({ page }) => {
  await connect(page);
  await page.getByText('切换或新建数据集', { exact: true }).click();
  await page.getByRole('combobox', { name: '数据集', exact: true }).selectOption(env.UI_DATASET!);
  await page.locator('summary').filter({ hasText: /^已有事件回放$/ }).click();
  await page.getByLabel('回放速率（EPS）').fill('1');
  await page.getByRole('button', { name: '创建回放', exact: true }).click();
  await expect(page.getByTestId('active-session')).toContainText('回放');
  await page.getByRole('button', { name: '查看异常', exact: true }).first().click();
  await expect(page.getByRole('alert')).toContainText('REPLAY_DETECTION_PENDING');
  await expect(page.getByText(/检测覆盖不足/)).toBeVisible();
  await page.getByRole('button', { name: '导入数据', exact: true }).click();
  let release!: () => void, arrived!: () => void;
  const waiting = new Promise<void>(resolve => { arrived = resolve; });
  const hold = new Promise<void>(resolve => { release = resolve; });
  await page.route('**/events?*', async route => {
    if (new URL(route.request().url()).searchParams.get('session_id') === env.UI_SESSION) return route.continue();
    const response = await route.fetch(); arrived(); await hold;
    await route.fulfill({ response }).catch(() => {});
  });
  await page.getByText('原始事件查询', { exact: true }).click();
  await waiting;
  await page.getByRole('button', { name: '返回导入会话', exact: true }).click();
  await expect(page.getByTestId('active-session')).toContainText('文件导入');
  release();
  await expect(page.locator('tbody tr:visible')).toHaveCount(20);
  await page.getByRole('button', { name: '取消回放', exact: true }).click();
  await expect(page.getByTestId('replay-status')).toContainText('cancelled');
  await expect(page.getByTestId('replay-status')).toContainText('partial');
  await page.getByRole('button', { name: '断开连接', exact: true }).click();
  await page.getByLabel('访问令牌', { exact: true }).fill(env.D9_E2E_VIEWER!);
  await page.getByRole('button', { name: '连接', exact: true }).click();
  await page.locator('summary').filter({ hasText: /^已有事件回放$/ }).click();
  await page.getByRole('button', { name: '创建回放', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('403');
  await expect(page.getByTestId('replay-status')).toHaveCount(0);
});

test('report: investigation, evidence, export, review and historical read retain functionality', async ({ page }) => {
  await connect(page);
  await page.getByRole('button', { name: '查看异常', exact: true }).first().click();
  await page.getByText('调查设置', { exact: true }).click();
  await page.getByRole('combobox', { name: '调查模式', exact: true }).selectOption('deterministic');
  const created = page.waitForResponse(r => r.request().method() === 'POST' && r.url().endsWith('/investigations'));
  await page.getByRole('button', { name: '开始调查', exact: true }).first().click();
  expect((await created).ok()).toBeTruthy();
  const report = page.getByRole('region', { name: '报告与人工复核' });
  await expect(report).toBeVisible({ timeout: 30000 });
  await expect(page.getByRole('button', { name: '阅读报告', exact: true })).toHaveAttribute('aria-current', 'step');
  await expect(report).toContainText('deterministic_fallback');
  await page.getByRole('button', { name: '补证对比', exact: true }).click();
  const comparison = page.getByRole('region', { name: '补证前后对比' });
  await expect(comparison).toContainText('新增非种子证据 0 条');
  await expect(comparison).toContainText('本次工具返回未扩大已知事件集合。');
  await page.getByRole('button', { name: '结论', exact: true }).click();
  await expect(report.getByText('本次未记录第 13.9 节的行为命中。')).toBeVisible();
  await report.locator('summary').filter({ hasText: /^查看证据/ }).first().click();
  await page.route(/\/evidence\/[^?]+\?snapshot_id=/, async route => {
    const response = await route.fetch();
    const evidence = await response.json() as EvidenceResponse;
    const fragment = evidence.fragments[0];
    const record = {
      record_number: 1, capture_time: '2026-11-22T00:00:00Z', capture_truncated: false,
      byte_range: { byte_start: 24, byte_end: 82 },
    };
    await route.fulfill({ response, json: { ...evidence, fragments: [...evidence.fragments,
      { ...fragment, lines: [], pcap_record: { ...record, packet: {
        arp_operation: 2, sender_mac: '020000000001', captured_length: 42, wire_length: 42,
      } } },
      { ...fragment, lines: [], pcap_record: { ...record, packet: {
        protocol_number: 17, ip_id: 1, fragment_offset_bytes: 0, more_fragments: false,
        captured_length: 72, wire_length: 72, dns_message: { message_type: 'response',
          transaction_id: 42, qtype: 28, question_sha256: 'a'.repeat(64),
          answer_set_sha256: 'b'.repeat(64), },
      } } },
    ] } });
  }, { times: 1 });
  await report.getByRole('button', { name: /^证据 \d/ }).first().click();
  await expect(page.getByRole('dialog')).toContainText('SHA-256');
  await expect(page.getByRole('dialog')).toContainText('ARP 应答');
  await expect(page.getByRole('dialog')).toContainText('DNS 应答 · AAAA');
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog')).toBeHidden();
  await report.getByRole('button', { name: '复核本条' }).first().click();
  await report.getByLabel('复核说明').fill('<img src=x onerror="window.uiXss=1"> 保留未知');
  await report.getByRole('button', { name: '保存复核意见' }).click();
  await expect(report.getByRole('list', { name: '人工复核记录' })).toContainText('保留未知');
  expect(await page.evaluate(() => Reflect.get(window, 'uiXss'))).toBeUndefined();
  for (const format of ['HTML', 'JSON']) {
    const download = page.waitForEvent('download');
    await report.getByRole('button', { name: `导出 ${format}` }).click();
    expect((await download).suggestedFilename()).toContain(`.${format.toLowerCase()}`);
  }
  await page.getByRole('button', { name: '关系与时间线', exact: true }).click();
  await expect(page.getByRole('heading', { name: '证据关系图' })).toBeVisible();
  await page.getByRole('button', { name: '运行记录', exact: true }).click();
  await page.getByRole('button', { name: '刷新 Agent 记录' }).click();
  await expect(page.getByRole('heading', { name: 'Agent 阶段与受控调用' })).toBeVisible();
  await page.getByRole('button', { name: '结论', exact: true }).click();
  await report.getByText('版本与费用', { exact: true }).click();
  await report.getByRole('button', { name: '读取匹配缓存' }).click();
  await expect(report).toContainText('cached');
  await report.getByText('版本与费用', { exact: true }).click();
  await report.getByRole('button', { name: '收起复核', exact: true }).click();
  await report.locator('summary').filter({ hasText: /^查看证据/ }).first().click();
  await page.screenshot({ path: `${env.TRACE_E2E_ARTIFACTS}/report.png`, fullPage: true });
  await page.reload();
  await page.getByLabel('访问令牌', { exact: true }).fill(env.D9_E2E_VIEWER!);
  await page.getByRole('button', { name: '连接', exact: true }).click();
  await page.getByRole('button', { name: '查看异常', exact: true }).first().click();
  await page.getByRole('button', { name: '查看历史报告' }).first().click();
  await page.getByRole('button', { name: '载入报告' }).first().click();
  await expect(report).toBeVisible();
  await report.getByRole('button', { name: '导出 JSON' }).click();
  await expect(report.getByRole('alert')).toContainText('403');
});

test('import: setup, context and upload lead to the correct anomaly session', async ({ page }) => {
  await connect(page);
  await page.getByText('切换或新建数据集', { exact: true }).click();
  await page.getByLabel('新数据集名称').fill('新手导入');
  await page.getByRole('button', { name: '创建合成数据集' }).click();
  await page.getByText('资产配置', { exact: true }).click();
  await page.getByLabel('上下文 JSON').setInputFiles(`${env.UI_FIXTURES}/context.json`);
  await page.getByRole('button', { name: '配置上下文' }).click();
  await expect(page.getByText('配置已保存', { exact: true })).toBeVisible();
  for (const [source, sensor, file, count] of [
    ['zeek', 'net-a', 'network', 26], ['linux_auth', 'auth-a', 'auth_a', 6],
    ['linux_audit', 'audit-a', 'audit', 3], ['linux_auth', 'auth-b', 'auth_b', 1],
    ['suricata', 'alert-a', 'alerts', 1],
  ] as const) {
    await page.getByLabel('日志文件', { exact: true }).setInputFiles(`${env.UI_FIXTURES}/${file}.jsonl`);
    await expect(page.getByRole('combobox', { name: '日志类型', exact: true })).toHaveValue(source);
    if (source === 'linux_auth') await page.getByLabel('传感器', { exact: true }).fill(sensor);
    else await expect(page.getByLabel('传感器', { exact: true })).toHaveValue(sensor);
    await page.getByRole('button', { name: '上传日志', exact: true }).click();
    await expect(page.getByTestId('import-status')).toContainText(`导入完成 · 新增 ${count}`, { timeout: 30000 });
  }
  await page.getByRole('button', { name: '查看导入结果', exact: true }).click();
  await expect(page.getByRole('button', { name: '开始调查', exact: true }).first()).toBeVisible();
  await expect(page.getByTestId('active-session')).toContainText('新手导入');
  await page.screenshot({ path: `${env.TRACE_E2E_ARTIFACTS}/anomalies.png`, fullPage: true });
  await page.getByRole('button', { name: '导入数据', exact: true }).click();
  await page.screenshot({ path: `${env.TRACE_E2E_ARTIFACTS}/import.png`, fullPage: true });
});

test('behavior report presents detected host discovery with unsuccessful trace', async ({ page }) => {
  await connect(page);
  await page.getByText('切换或新建数据集', { exact: true }).click();
  await page.getByLabel('新数据集名称').fill('行为检测回归');
  await page.getByRole('button', { name: '创建合成数据集' }).click();
  await page.getByLabel('日志文件', { exact: true }).setInputFiles(
    '../../artifacts/ciciot2023-recon-host-discovery-real-01/capture-01.pcap',
  );
  await expect(page.getByRole('combobox', { name: '日志类型', exact: true })).toHaveValue('pcap_packet');
  await page.getByRole('button', { name: '上传日志', exact: true }).click();
  await expect(page.getByTestId('import-status')).toContainText('导入完成', { timeout: 30000 });
  await page.getByRole('button', { name: '查看导入结果', exact: true }).click();
  await page.getByRole('button', { name: '开始调查', exact: true }).first().click();
  const report = page.getByRole('region', { name: '报告与人工复核' });
  await expect(report.getByRole('heading', { name: '检测到 疑似主机发现 · 溯源未成功' })).toBeVisible();
  await report.getByText('查看检测与溯源证据', { exact: true }).click();
  await report.getByRole('button', { name: '检测证据 1', exact: true }).click();
  await expect(page.getByRole('dialog')).toContainText('SHA-256');
});

test('format hints refuse conflicting and unknown source records', () => {
  expect(identifySource('')).toBeNull();
  expect(identifySource('{"hello":"world"}')).toBeNull();
  expect(identifySource('{"ts":1,"id.orig_h":"192.0.2.1","id.resp_h":"192.0.2.2"}')).toBe('zeek');
  expect(identifySource('{"event_type":"alert","alert":{}}')).toBe('suricata');
  expect(identifySource('{"timestamp":"2026-01-01","host":"host-a","auth":{}}')).toBe('linux_auth');
  expect(identifySource('{"host":"host-a","audit_serial":"1","record_type":"SYSCALL"}')).toBe('linux_audit');
  expect(identifySource('{"event_type":"alert","alert":{},"ts":1,"id.orig_h":"a","id.resp_h":"b"}')).toBeNull();
  expect(identifySource('{"event_type":"alert","alert":{}}\n{"host":"a","audit_serial":"1","record_type":"X"}')).toBeNull();
  expect(identifySource('<script>alert(1)</script>')).toBeNull();
});

test('unknown file asks for a format and never silently submits it', async ({ page }) => {
  await connect(page);
  await page.getByLabel('日志文件', { exact: true }).setInputFiles({ name: 'unknown.jsonl', mimeType: 'application/json', buffer: Buffer.from('{"unknown":true}') });
  await expect(page.getByRole('combobox', { name: '日志类型', exact: true })).toHaveValue('');
  await expect(page.getByRole('button', { name: '上传日志', exact: true })).toBeDisabled();
  await page.getByRole('combobox', { name: '日志类型', exact: true }).selectOption('zeek');
  await expect(page.getByRole('button', { name: '上传日志', exact: true })).toBeEnabled();
});

test('partial: unavailable evidence is warned before claims and graph failures do not hide the report', async ({ page }) => {
  await connect(page);
  await page.getByRole('button', { name: '查看异常', exact: true }).first().click();
  await page.getByText('调查设置', { exact: true }).click();
  await page.getByRole('combobox', { name: '调查模式', exact: true }).selectOption('deterministic');
  await page.route('**/investigations/*/graph', route => route.fulfill({ status: 503,
    json: { error: { message: '本地测试：图暂不可用' } } }));
  await page.route('**/reports/*', async route => {
    const response = await route.fetch();
    await route.fulfill({ response, json: { ...await response.json(), validation: 'partial' } });
  });
  await page.getByRole('button', { name: '开始调查', exact: true }).first().click();
  await expect(page.getByRole('region', { name: '报告与人工复核' })).toBeVisible();
  const warning = page.getByRole('alert').filter({ hasText: '当前证据不可验证，历史结论仅供参考。' });
  await expect(warning).toBeVisible();
  const warningBox = await warning.boundingBox();
  const reportBox = await page.getByRole('region', { name: '报告与人工复核' }).boundingBox();
  expect(warningBox!.y).toBeLessThan(reportBox!.y);
});

test('queued import: waiting for worker does not trap the user in the dataset', async ({ page }) => {
  await connect(page);
  await page.route('**/imports/*', async route => {
    const response = await route.fetch();
    await route.fulfill({ response, json: { ...await response.json(), status: 'queued' } });
  });
  await page.getByLabel('日志文件', { exact: true }).setInputFiles(`${env.UI_FIXTURES}/network.jsonl`);
  await page.getByRole('button', { name: '上传日志', exact: true }).click();
  await expect(page.getByTestId('import-status')).toContainText('等待处理');
  await expect(page.getByRole('button', { name: '断开连接', exact: true })).toBeEnabled();
  await page.getByRole('button', { name: '断开连接', exact: true }).click();
  await expect(page.getByLabel('访问令牌', { exact: true })).toBeVisible();
  await expect(page.getByTestId('import-status')).toHaveCount(0);
});
