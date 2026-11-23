import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { env } from 'node:process';
import { readFile, writeFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import type { DatasetResponse, IncidentSummary, Report, RunStatus } from '../../../packages/contracts/generated/api';

test.use({ actionTimeout: 10000 });
let api: APIRequestContext;
let multi: DatasetResponse;
const histories: { title: string; report: Report; run: RunStatus }[] = [];

async function get<T>(path: string): Promise<T> {
  const response = await api.get(`/api/v1${path}`);
  expect(response.ok(), path).toBeTruthy();
  return response.json();
}

test.beforeAll(async ({ playwright }) => {
  api = await playwright.request.newContext({ baseURL: env.D3_E2E_URL,
    extraHTTPHeaders: { Authorization: `Bearer ${env.D3_E2E_TOKEN}` } });
  const created = await api.post('/api/v1/datasets', { data: { name: '完整功能隔离检查', provenance_type: 'synthetic' },
    headers: { 'Idempotency-Key': crypto.randomUUID() } });
  expect(created.status()).toBe(201); multi = await created.json();
  const context = JSON.parse(await readFile(`${env.UI_FIXTURES}/context.json`, 'utf8'));
  expect((await api.post(`/api/v1/datasets/${multi.dataset_id}/context`, { data: context,
    headers: { 'Idempotency-Key': crypto.randomUUID() } })).ok()).toBeTruthy();
  for (const [source, sensor, file] of [['zeek', 'net-a', 'network'], ['linux_auth', 'auth-a', 'auth_a'],
    ['linux_audit', 'audit-a', 'audit'], ['linux_auth', 'auth-b', 'auth_b'], ['suricata', 'alert-a', 'alerts']]) {
    const response = await api.post('/api/v1/imports', { headers: { 'Idempotency-Key': crypto.randomUUID() },
      multipart: { dataset_id: multi.dataset_id, source_type: source, sensor_id: sensor, timezone: 'UTC',
        file: { name: `${file}.jsonl`, mimeType: 'application/json', buffer: await readFile(`${env.UI_FIXTURES}/${file}.jsonl`) } } });
    expect(response.status()).toBe(202);
    const batch = await response.json();
    await expect.poll(async () => (await get<{ status: string }>(`/imports/${batch.batch_id}`)).status).toBe('succeeded');
  }
  const incidents = await get<{ items: IncidentSummary[] }>(`/incidents?dataset_id=${multi.dataset_id}&session_id=${multi.default_session_id}`);
  expect(incidents.items.length).toBeGreaterThan(1);
  for (const incident of incidents.items) {
    const response = await api.post(`/api/v1/incidents/${incident.id}/investigations`, {
      data: { mode: 'deterministic', budget: { max_tool_calls: 6, max_model_calls: 4 } },
      headers: { 'Idempotency-Key': crypto.randomUUID() } });
    expect(response.status()).toBe(202);
    const value = await response.json();
    let run!: RunStatus;
    await expect.poll(async () => { run = await get<RunStatus>(`/investigations/${value.run_id}`); return run.state; },
      { timeout: 30000 }).toBe('completed');
    const report = await get<Report>(`/reports/${run.report_id}`);
    histories.push({ title: incident.title, report, run });
  }
});
test.afterAll(async () => { await api?.dispose(); });

async function connect(page: Page, token = env.D3_E2E_TOKEN!, dataset = multi.dataset_id) {
  await page.goto(env.D3_E2E_URL!);
  await page.getByLabel('访问令牌', { exact: true }).fill(token);
  await page.getByRole('button', { name: '连接', exact: true }).click();
  await expect(page.getByTestId('active-session')).toBeVisible();
  await page.getByText('切换或新建数据集', { exact: true }).click();
  while (!(await page.getByRole('combobox', { name: '数据集', exact: true }).locator(`option[value="${dataset}"]`).count())) {
    const options = page.getByRole('combobox', { name: '数据集', exact: true }).locator('option');
    const count = await options.count();
    await page.getByRole('button', { name: '载入更多数据集' }).click();
    await expect.poll(() => options.count()).toBeGreaterThan(count);
  }
  await page.getByRole('combobox', { name: '数据集', exact: true }).selectOption(dataset);
}

async function openHistory(page: Page, index = 0, token = env.D3_E2E_TOKEN!) {
  await connect(page, token);
  await page.getByRole('button', { name: '查看异常', exact: true }).first().click();
  const row = page.locator('.incident-list > li').filter({ hasText: histories[index].title });
  const button = await row.count() ? row.getByRole('button', { name: '查看历史报告' })
    : page.getByRole('listitem').filter({ hasText: histories[index].title }).getByRole('button', { name: '查看历史报告' });
  await button.click();
  await page.getByRole('region', { name: '已有报告版本' }).getByRole('button', { name: '载入报告' }).first().click();
  await expect(page.getByRole('region', { name: '报告与人工复核' })).toBeVisible();
}

test('installed: 8080 landing, login boundary and mobile entry are read-only', async ({ page }) => {
  const mutations: string[] = [];
  await page.route('**/*', route => {
    if (!['GET', 'HEAD'].includes(route.request().method())) {
      mutations.push(route.request().url()); return route.abort();
    }
    return route.continue();
  });
  await page.goto('http://127.0.0.1:8080');
  await expect(page.getByLabel('访问令牌', { exact: true })).toBeVisible();
  await expect(page.getByRole('navigation', { name: '操作步骤' }).getByRole('button')).toHaveCount(3);
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 900 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
    await expect(page.getByRole('button', { name: '连接', exact: true })).toBeVisible();
  }
  expect(mutations).toEqual([]);
  const health = await page.request.get('http://127.0.0.1:8080/api/v1/health/live');
  expect((await health.json()).status).toBe('ok');
  expect((await page.request.get('http://127.0.0.1:8080/api/v1/datasets')).status()).toBe(401);
});

test('installed: real dataset, event and incident pagination retain current scope', async ({ page }) => {
  await page.route('**/api/v1/datasets*', async route => {
    if (route.request().method() !== 'GET' || !new URL(route.request().url()).pathname.endsWith('/datasets')) return route.continue();
    const url = new URL(route.request().url()); url.searchParams.set('limit', '1');
    await route.fulfill({ response: await route.fetch({ url: url.toString() }) });
  });
  await connect(page);
  await page.getByText('原始事件查询', { exact: true }).click();
  await expect(page.locator('tbody tr:visible')).toHaveCount(20);
  await page.getByText('查看事件与引用', { exact: true }).first().click();
  await expect(page.locator('pre:visible').first()).toContainText('source_locators');
  await page.getByRole('button', { name: '下一页', exact: true }).click();
  await expect(page.locator('tbody tr:visible')).toHaveCount(17);
  await page.getByRole('button', { name: '刷新事件', exact: true }).click();
  await expect(page.locator('tbody tr:visible')).toHaveCount(20);
  await page.route('**/api/v1/incidents?*', async route => {
    const url = new URL(route.request().url()); url.searchParams.set('limit', '1');
    await route.fulfill({ response: await route.fetch({ url: url.toString() }) });
  });
  await page.getByRole('button', { name: '查看异常', exact: true }).first().click();
  await expect(page.getByRole('button', { name: '开始调查', exact: true })).toHaveCount(1);
  const queue = page.locator('section').filter({ has: page.getByRole('heading', { name: /^待核查异常/ }) });
  const initial = await queue.innerText();
  await page.getByRole('button', { name: '下一页候选', exact: true }).click();
  await expect(queue).not.toHaveText(initial);
  await expect(page.getByTestId('active-session')).toContainText('完整功能隔离检查');
});

test('installed: replay response loss retries same job, completes, and reopens by ID', async ({ page }) => {
  await connect(page, env.D3_E2E_TOKEN!, env.UI_DATASET!);
  await page.locator('summary').filter({ hasText: /^已有事件回放$/ }).click();
  await page.getByLabel('回放速率（EPS）').fill('0');
  await expect(page.getByRole('button', { name: '创建回放', exact: true })).toBeDisabled();
  await page.getByLabel('回放速率（EPS）').fill('1000');
  const jobs: string[] = [], keys: string[] = [];
  await page.route('**/datasets/*/replays', async route => {
    const response = await route.fetch(); jobs.push((await response.json()).job_id);
    keys.push(route.request().headers()['idempotency-key']);
    if (jobs.length === 1) await route.abort('failed'); else await route.fulfill({ response });
  });
  await page.getByRole('button', { name: '创建回放', exact: true }).click();
  await page.getByRole('button', { name: '重试创建（同一请求）', exact: true }).click();
  await expect(page.getByTestId('replay-status')).toContainText('completed', { timeout: 30000 });
  await expect(page.getByTestId('replay-status')).toContainText('24 / 24');
  await expect(page.getByTestId('replay-status')).toContainText('complete');
  expect(jobs).toHaveLength(2); expect(jobs[0]).toBe(jobs[1]); expect(keys[0]).toBe(keys[1]);
  await page.reload(); await connect(page, env.D3_E2E_TOKEN!, env.UI_DATASET!);
  await page.locator('summary').filter({ hasText: /^已有事件回放$/ }).click();
  await page.getByLabel('回放作业 ID').fill(jobs[0]);
  await page.getByRole('button', { name: '打开回放', exact: true }).click();
  await expect(page.getByTestId('active-session')).toContainText('回放');
  await expect(page.getByTestId('replay-status')).toContainText('completed');
  await page.getByRole('button', { name: '查看异常', exact: true }).first().click();
  await expect(page.getByRole('button', { name: '开始调查', exact: true }).first()).toBeVisible();
});

test('installed: queued investigation cancellation never starts model or publishes a report', async ({ page }) => {
  const worker = env.UI_AUDIT_WORKER!;
  expect(worker).toMatch(/^trace-ui-audit-[a-f0-9]+-worker$/);
  execFileSync('docker', ['pause', worker]);
  try {
    await connect(page);
    await page.getByRole('button', { name: '查看异常', exact: true }).first().click();
    await page.getByText('调查设置', { exact: true }).click();
    await page.getByRole('combobox', { name: '调查模式', exact: true }).selectOption('deterministic');
    const created = page.waitForResponse(r => r.request().method() === 'POST' && r.url().endsWith('/investigations'));
    await page.getByRole('button', { name: '开始调查', exact: true }).first().click();
    const run = await (await created).json();
    const cancelled = page.waitForResponse(r => r.request().method() === 'POST' && r.url().endsWith('/cancel'));
    await page.getByRole('button', { name: '取消调查', exact: true }).click();
    expect((await cancelled).ok()).toBeTruthy();
    const status = await get<RunStatus>(`/investigations/${run.run_id}`);
    expect(status.state).toBe('cancelled'); expect(status.report_id).toBeNull();
    await expect(page.getByRole('region', { name: '报告与人工复核' })).toHaveCount(0);
    await page.getByRole('button', { name: '返回异常列表', exact: true }).click();
    await expect(page.getByRole('heading', { name: /^待核查异常/ })).toBeVisible();
  } finally { execFileSync('docker', ['unpause', worker]); }
});

test('installed: timeline, graph paging/focus and path evidence remain reachable', async ({ page }) => {
  const chosen = histories.findIndex(item => (item.report.path_analysis?.paths.length ?? 0) > 0);
  expect(chosen).toBeGreaterThanOrEqual(0);
  await page.route('**/investigations/*/graph*', async route => {
    const url = new URL(route.request().url()); url.searchParams.set('limit', '2');
    await route.fulfill({ response: await route.fetch({ url: url.toString() }) });
  });
  await page.route('**/investigations/*/timeline*', async route => {
    const url = new URL(route.request().url()); url.searchParams.set('limit', '2');
    await route.fulfill({ response: await route.fetch({ url: url.toString() }) });
  });
  await openHistory(page, chosen);
  await page.getByRole('button', { name: '关系与时间线', exact: true }).click();
  await expect(page.getByRole('button', { name: '查看时间线证据' })).toHaveCount(2);
  await page.getByRole('button', { name: '下一页时间线' }).click();
  await page.getByRole('button', { name: '查看时间线证据' }).first().click();
  await expect(page.getByRole('dialog')).toBeVisible(); await page.keyboard.press('Escape');
  await page.getByText('展开全部边及证据', { exact: true }).click();
  await expect(page.getByRole('button', { name: '查看原始行脱敏投影' })).toHaveCount(2);
  await page.getByRole('button', { name: '载入下一页关系' }).click();
  await expect(page.getByRole('button', { name: '查看原始行脱敏投影' })).toHaveCount(4);
  await page.getByRole('button', { name: '查看原始行脱敏投影' }).last().click();
  await expect(page.getByRole('dialog')).toBeVisible(); await page.getByRole('button', { name: '关闭', exact: true }).click();
  await page.getByRole('combobox', { name: '图节点焦点' }).selectOption({ index: 1 });
  const focused = page.waitForResponse(r => r.url().includes('/graph?') && r.url().includes('focus_entity='));
  await page.getByRole('button', { name: '查询焦点关系' }).click();
  expect((await focused).ok()).toBeTruthy();
  await page.getByRole('button', { name: '候选路径 1', exact: true }).click();
  await page.getByRole('button', { name: '查看路径边证据' }).first().click();
  await expect(page.getByRole('dialog')).toBeVisible(); await page.keyboard.press('Escape');
  await page.locator('summary').filter({ hasText: /^候选入口 ·/ }).click();
  await page.getByRole('button', { name: '查看入口证据' }).first().click();
  await expect(page.getByRole('dialog')).toBeVisible(); await page.keyboard.press('Escape');
  await page.locator('summary').filter({ hasText: /^其他路径与限制/ }).click();
  await expect(page.getByText(/未观测的攻击步骤数量未知/)).toBeVisible();
});

test('installed: comparison, missing evidence, budgets and historical versions remain readable without generation', async ({ page }) => {
  const writes: string[] = [];
  page.on('request', r => { if (r.method() === 'POST') writes.push(r.url()); });
  await openHistory(page);
  await page.getByText('校验详情', { exact: true }).click();
  await expect(page.getByRole('region', { name: '缺证与校验' })).toContainText('校验通过不代表完整攻击链');
  await page.getByRole('button', { name: '补证对比', exact: true }).click();
  await expect(page.getByRole('region', { name: '补证前后对比' })).toBeVisible();
  await expect(page.getByRole('region', { name: '补证前后对比' })).toContainText('本次没有得到能改变这些判断的新证据');
  await page.getByRole('button', { name: '运行记录', exact: true }).click();
  await page.getByRole('button', { name: '刷新 Agent 记录' }).click();
  await expect(page.getByText(/模型预算 0\//)).toBeVisible();
  await page.locator('summary').filter({ hasText: /^持久化状态转换/ }).click();
  await page.getByRole('button', { name: '结论', exact: true }).click();
  await page.getByText('版本与费用', { exact: true }).click();
  await page.getByRole('button', { name: '刷新报告版本' }).click();
  await page.getByRole('button', { name: '打开历史版本' }).first().click();
  await expect(page.getByRole('region', { name: '报告与人工复核' })).toBeVisible();
  expect(writes).toEqual([]);
});

test('installed: review retry, all decisions, pagination and unchanged report facts', async ({ page }) => {
  await openHistory(page);
  const report = histories[0].report;
  await page.getByRole('button', { name: '复核本条' }).first().click();
  const ids: string[] = [], keys: string[] = [];
  await page.route('**/reports/*/reviews', async route => {
    if (route.request().method() !== 'POST') return route.continue();
    const response = await route.fetch(); ids.push((await response.json()).review_id);
    keys.push(route.request().headers()['idempotency-key']);
    if (ids.length === 1) await route.abort('failed'); else await route.fulfill({ response });
  });
  for (const decision of ['accepted', 'rejected', 'needs_more_evidence']) {
    await page.getByLabel('复核决定').selectOption(decision);
    await page.getByLabel('复核说明').fill(`隔离审计 ${decision}`);
    await page.getByRole('button', { name: '保存复核意见' }).click();
    if (decision === 'accepted') {
      await expect(page.getByRole('region', { name: '报告与人工复核' }).getByRole('alert')).toBeVisible();
      await page.getByRole('button', { name: '保存复核意见' }).click();
    }
    await expect(page.getByRole('list', { name: '人工复核记录' })).toContainText(`隔离审计 ${decision}`);
  }
  expect(ids[0]).toBe(ids[1]); expect(keys[0]).toBe(keys[1]);
  for (let i = 0; i < 18; i++) {
    expect((await api.post(`/api/v1/reports/${report.report_id}/reviews`, {
      headers: { 'Idempotency-Key': crypto.randomUUID() },
      data: { claim_id: report.claims[0].claim_id, decision: 'needs_more_evidence', comment: `分页 ${i}` },
    })).ok()).toBeTruthy();
  }
  await page.getByRole('button', { name: '刷新人工复核' }).click();
  await expect(page.getByRole('list', { name: '人工复核记录' }).getByRole('listitem')).toHaveCount(20);
  await page.getByRole('button', { name: '更多复核记录' }).click();
  await expect(page.getByRole('list', { name: '人工复核记录' }).getByRole('listitem')).toHaveCount(21);
  expect(await get<Report>(`/reports/${report.report_id}`)).toEqual(report);
});

test('installed: downloaded JSON and offline HTML keep evidence, timestamps and links', async ({ page, context }) => {
  await openHistory(page);
  const report = histories[0].report;
  for (const format of ['JSON', 'HTML']) {
    const download = page.waitForEvent('download');
    await page.getByRole('button', { name: `导出 ${format}` }).click();
    const path = await (await download).path(); expect(path).toBeTruthy();
    const content = await readFile(path!, 'utf8');
    if (format === 'JSON') {
      const bundle = JSON.parse(content);
      expect(bundle.report).toEqual(report);
      expect(bundle.evidence.length).toBeGreaterThan(0);
      for (const item of bundle.evidence) { expect(item.verified).toBe(true); expect(item.redacted).toBe(true); }
      expect(bundle.snapshot.event_ids.length).toBe(bundle.evidence.length);
    } else {
      const offline = await context.newPage();
      await offline.setContent(content);
      await expect(offline.getByRole('heading', { name: '调查报告 · 离线脱敏导出' })).toBeVisible();
      expect(await offline.locator('a[href^="#"]').evaluateAll(links => links.every(a =>
        document.getElementById(a.getAttribute('href')!.slice(1))))).toBeTruthy();
      expect(await offline.locator('script').count()).toBe(0);
      await offline.close();
    }
    await writeFile(`${env.TRACE_E2E_ARTIFACTS}/isolated-export.${format.toLowerCase()}`, content);
  }
});

test('installed: viewer can read history but cannot investigate or append reviews', async ({ page }) => {
  await openHistory(page, 0, env.D9_E2E_VIEWER!);
  await page.getByRole('button', { name: '复核本条' }).first().click();
  await page.getByLabel('复核说明').fill('只读角色拒绝测试');
  await page.getByRole('button', { name: '保存复核意见' }).click();
  await expect(page.getByRole('region', { name: '报告与人工复核' }).getByRole('alert')).toContainText('403');
  await page.getByRole('button', { name: '返回异常列表', exact: true }).click();
  await page.getByRole('button', { name: '开始调查', exact: true }).first().click();
  await expect(page.getByRole('alert').filter({ hasText: '403' }).first()).toBeVisible();
  await page.getByRole('button', { name: '导入数据', exact: true }).click();
  await page.getByRole('button', { name: '断开连接', exact: true }).click();
  await expect(page.getByRole('region', { name: '报告与人工复核' })).toHaveCount(0);
  await page.getByLabel('访问令牌', { exact: true }).fill('invalid-isolated-token');
  await page.getByRole('button', { name: '连接', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('401');
});

test('installed: upload retry preserves batch, duplicate records and quarantine are explicit', async ({ page }) => {
  await connect(page);
  await page.getByLabel('新数据集名称').fill('导入重试隔离检查');
  await page.getByRole('button', { name: '创建合成数据集' }).click();
  await expect(page.getByTestId('active-session')).toContainText('导入重试隔离检查');
  const record = { ts: 1794618000, uid: 'isolated-import-retry', 'id.orig_h': '192.0.2.10',
    'id.orig_p': 40001, 'id.resp_h': '10.10.0.20', 'id.resp_p': 443, proto: 'tcp', synthetic: true };
  const file = { name: 'isolated.jsonl', mimeType: 'application/json',
    buffer: Buffer.from(`${JSON.stringify(record)}\nnot-valid-json\n`) };
  await page.getByLabel('日志文件', { exact: true }).setInputFiles(file);
  await page.getByRole('combobox', { name: '日志类型', exact: true }).selectOption('zeek');
  await page.getByLabel('传感器', { exact: true }).fill('browser');
  const keys: string[] = [], batches: string[] = [];
  await page.route('**/api/v1/imports', async route => {
    const response = await route.fetch(); batches.push((await response.json()).batch_id);
    keys.push(route.request().headers()['idempotency-key']);
    if (batches.length === 1) await route.abort('failed'); else await route.fulfill({ response });
  });
  await page.getByRole('button', { name: '上传日志', exact: true }).click();
  await expect(page.getByLabel('日志文件', { exact: true })).toBeDisabled();
  await page.getByRole('button', { name: '重试上传', exact: true }).click();
  await expect(page.getByTestId('import-status')).toContainText('新增 1 · 重复 0 · 隔离 1');
  expect(batches[0]).toBe(batches[1]); expect(keys[0]).toBe(keys[1]);
  await page.getByText('导入详情', { exact: true }).click();
  await expect(page.getByTestId('import-status')).toContainText('物理记录 2');
  await page.getByLabel('日志文件', { exact: true }).setInputFiles(file);
  await page.getByRole('combobox', { name: '日志类型', exact: true }).selectOption('zeek');
  await page.getByRole('button', { name: '上传日志', exact: true }).click();
  await expect(page.getByTestId('import-status')).toContainText('新增 0 · 重复 1 · 隔离 1');
  await page.getByRole('button', { name: '查看导入结果', exact: true }).click();
  await expect(page.getByText('当前没有规则命中；这不证明没有攻击。', { exact: true })).toBeVisible();
});
