import { useEffect, useRef, useState } from 'react';
import type { AgentActionPage, AgentTransitionPage, EventPage, IncidentPage, RunResponse, RunStatus, GraphResponse, Report, ReportPage, EvidenceResponse } from '../../../packages/contracts/generated/api';
import { Paths } from './Paths';
import { AgentHistory } from './AgentHistory';
import { EvidenceChanges } from './EvidenceChanges';
import { PipelineProgressView } from './PipelineProgress';
import { MissingEvidence } from './MissingEvidence';
import { ReportPanel } from './ReportPanel';
import { EvidenceDialog } from './EvidenceDialog';
import { api, ApiError, type Connection } from './client';
export type { Connection } from './client';

const stateLabels: Record<string, string> = { queued: '等待处理', running: '正在调查', completed: '调查完成', partial: '调查未完成', failed: '调查失败', cancelled: '已取消' };
const resultTabs = ['结论', '关系与时间线', '补证对比', '运行记录'] as const;

export function Investigation({ connection, view, active, onReport, onIncidents, onConnect }: {
  connection: Connection; view: 'incidents' | 'report'; active: boolean;
  onReport: () => void; onIncidents: () => void; onConnect: () => void;
}) {
  const [tab, setTab] = useState<typeof resultTabs[number]>('结论');
  const [loading, setLoading] = useState(false);
  const [listError, setListError] = useState('');
  const [pollRevision, setPollRevision] = useState(0);
  const [readError, setReadError] = useState('');
  const [creating, setCreating] = useState(false);
  const [pendingCreate, setPendingCreate] = useState<{ incident: string; key: string; body: string } | null>(null);
  const working = useRef(false);
  const [incidents, setIncidents] = useState<IncidentPage | null>(null);
  const [eventCount, setEventCount] = useState<number | null>(null);
  const [run, setRun] = useState<RunResponse | null>(null);
  const [status, setStatus] = useState<RunStatus | null>(null);
  const [graph, setGraph] = useState<GraphResponse | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [savedReports, setSavedReports] = useState<ReportPage | null>(null);
  const [evidence, setEvidence] = useState<EvidenceResponse | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [timeline, setTimeline] = useState<EventPage | null>(null);
  const [focus, setFocus] = useState('');
  const [graphFocus, setGraphFocus] = useState('');
  const [graphLimit, setGraphLimit] = useState(20);
  const [selectedNode, setSelectedNode] = useState('');
  const [selectedEdge, setSelectedEdge] = useState<string>('');
  const [investigationMode, setInvestigationMode] = useState<'auto' | 'live' | 'deterministic'>('auto');
  const [toolBudget, setToolBudget] = useState(6);
  const [modelBudget, setModelBudget] = useState(4);
  const [agentActions, setAgentActions] = useState<AgentActionPage | null>(null);
  const [agentTransitions, setAgentTransitions] = useState<AgentTransitionPage | null>(null);
  const lifecycle = useRef(new AbortController());
  useEffect(() => {
    const controller = new AbortController(); lifecycle.current = controller;
    setIncidents(null); setEventCount(null); setRun(null); setStatus(null); setGraph(null); setReport(null); setEvidence(null); setError(''); setBusy(false);
    setTimeline(null); setFocus(''); setGraphFocus('');
    setSelectedNode(''); setSelectedEdge(''); setGraphLimit(20);
    setAgentActions(null); setAgentTransitions(null);
    setSavedReports(null);
    return () => controller.abort();
  }, [connection.token, connection.dataset?.dataset_id, connection.sessionId]);

  async function action(work: (signal: AbortSignal) => Promise<void>) {
    if (working.current) return;
    const signal = lifecycle.current.signal;
    working.current = true;
    setBusy(true); setError('');
    try { await work(signal); } catch (e) {
      if (!signal.aborted) setError(e instanceof Error ? e.message : '操作失败');
    } finally { working.current = false; if (!signal.aborted) setBusy(false); }
  }

  useEffect(() => {
    if (!run || !active) return;
    const controller = new AbortController();
    setReadError('');
    let timer = 0;
    async function poll() {
      if (document.hidden) { timer = window.setTimeout(() => void poll(), 3000); return; }
      try {
        const next = await api<RunStatus>(connection, `/investigations/${run!.run_id}`, controller.signal);
        if (controller.signal.aborted) return;
        setStatus(next);
        if (['completed', 'partial'].includes(next.state) && next.report_id) {
          const [g, r, t] = await Promise.allSettled([
            api<GraphResponse>(connection, `/investigations/${run!.run_id}/graph`, controller.signal),
            api<Report>(connection, `/reports/${next.report_id}`, controller.signal),
            api<EventPage>(connection, `/investigations/${run!.run_id}/timeline?limit=20`, controller.signal),
          ]);
          if (!controller.signal.aborted) {
            setGraph(g.status === 'fulfilled' ? g.value : null);
            setReport(r.status === 'fulfilled' ? r.value : null);
            setTimeline(t.status === 'fulfilled' ? t.value : null);
            const failures = [g, r, t].filter(item => item.status === 'rejected');
            if (failures.length) setReadError(failures.map(item => item.reason instanceof Error ? item.reason.message : '部分内容读取失败').join(' · '));
          }
        } else if (next.state === 'queued' || next.state === 'running') {
          timer = window.setTimeout(() => void poll(), 2000);
        }
      } catch (e) { if (!controller.signal.aborted) setReadError(e instanceof Error ? e.message : '查询失败'); }
    }
    void poll();
    return () => { controller.abort(); window.clearTimeout(timer); };
  }, [run, connection, active, pollRevision]);

  async function openEvidence(eventId: string, signal: AbortSignal, cursor?: string | null) {
    if (!run) return;
    setEvidence(null);
    const data = await api<EvidenceResponse>(connection,
      `/evidence/${eventId}?snapshot_id=${run.snapshot_id}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`, signal);
    if (!signal.aborted) setEvidence(data);
  }

  async function openRun(id: string, signal: AbortSignal) {
    const historical = await api<RunStatus>(connection, `/investigations/${id}`, signal);
    if (signal.aborted) return;
    setReport(null); setGraph(null); setTimeline(null); setEvidence(null);
    setAgentActions(null); setAgentTransitions(null); setStatus(historical);
    setRun({ run_id: id, snapshot_id: historical.snapshot_id, job_id: historical.job_id, state: historical.state });
    setTab('结论'); onReport();
  }

  async function loadAgent(signal: AbortSignal, cursor?: string | null) {
    if (!run) return;
    const base = `/investigations/${run.run_id}`;
    const actions = await api<AgentActionPage>(connection, `${base}/tool-calls?limit=20${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`, signal);
    if (!signal.aborted) setAgentActions(actions);
    if (!cursor) {
      const transitions = await api<AgentTransitionPage>(connection, `${base}/transitions?limit=100`, signal);
      if (!signal.aborted) setAgentTransitions(transitions);
    }
  }

  async function loadIncidents(signal: AbortSignal, cursor?: string | null) {
    const p = new URLSearchParams({ dataset_id: connection.dataset!.dataset_id,
      session_id: connection.sessionId ?? connection.dataset!.default_session_id, limit: '20' });
    if (cursor) p.set('cursor', cursor);
    const overviewParams = new URLSearchParams({ dataset_id: connection.dataset!.dataset_id,
      session_id: connection.sessionId ?? connection.dataset!.default_session_id });
    const [data, overview] = await Promise.all([
      api<IncidentPage>(connection, `/incidents?${p}`, signal),
      api<{ event_count: number }>(connection, `/overview?${overviewParams}`, signal),
    ]);
    if (!signal.aborted) { setIncidents(data); setEventCount(overview.event_count); }
  }

  useEffect(() => {
    if (!active || view !== 'incidents' || !connection.dataset || !connection.token) return;
    const controller = new AbortController(); setLoading(true); setListError(''); setIncidents(null);
    const params = new URLSearchParams({ dataset_id: connection.dataset.dataset_id,
      session_id: connection.sessionId ?? connection.dataset.default_session_id, limit: '20' });
    Promise.all([
      api<IncidentPage>(connection, `/incidents?${params}`, controller.signal),
      api<{ event_count: number }>(connection, `/overview?${params}`, controller.signal),
    ]).then(([data, overview]) => {
      if (!controller.signal.aborted) { setIncidents(data); setEventCount(overview.event_count); }
    }).catch((e: unknown) => {
      if (!controller.signal.aborted) setListError(e instanceof Error ? e.message : '查询失败');
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [active, view, connection]);

  async function loadGraph(signal: AbortSignal, cursor?: string | null, selectedFocus = cursor ? graphFocus : focus) {
    if (!run) return;
    const p = new URLSearchParams({ limit: '50' });
    if (cursor) p.set('cursor', cursor);
    if (selectedFocus) p.set('focus_entity', selectedFocus);
    const data = await api<GraphResponse>(connection, `/investigations/${run.run_id}/graph?${p}`, signal);
    if (!signal.aborted) { setGraph((old) => cursor && old ? { ...data, edges: [...old.edges, ...data.edges] } : data); setGraphFocus(selectedFocus); }
  }

  if (!connection.token || !connection.dataset) return <section className="panel empty-state"><h3>请先连接工作区</h3><button className="primary" onClick={onConnect}>去连接</button></section>;
  const displayId = new Map(graph?.nodes.map((node) => [node.entity_id,
    node.type === 'Endpoint' ? node.entity_id.slice(0, node.entity_id.lastIndexOf(':')) : node.entity_id]) ?? []);
  const nodeLabels = new Map(graph?.nodes.map((node) => [node.entity_id, node.label]) ?? []);
  const displayLabels = new Map(graph?.nodes.map((node) => [displayId.get(node.entity_id)!, node.label]) ?? []);
  const ids = [...displayLabels.keys()].slice(0, graphLimit);
  const points = new Map(ids.map((id, i) => [id,
    { x: 600 + (ids.length > 30 ? 430 : 360) * Math.cos(2 * Math.PI * i / ids.length), y: 390 + (ids.length > 30 ? 300 : 250) * Math.sin(2 * Math.PI * i / ids.length) }]));
  const displayEdges = new Map<string, { source: string; target: string; count: number; relation: string; inferred: boolean; edgeIds: string[] }>();
  for (const edge of graph?.edges ?? []) {
    const source = displayId.get(edge.source)!, target = displayId.get(edge.target)!;
    if (!points.has(source) || !points.has(target)) continue;
    const key = `${source}/${target}/${edge.relation}/${edge.kind}`;
    const old = displayEdges.get(key);
    displayEdges.set(key, { source, target, count: (old?.count ?? 0) + 1, relation: edge.relation, inferred: edge.kind === 'inferred', edgeIds: [...(old?.edgeIds ?? []), edge.edge_id] });
  }
  const selectedEdgeValue = graph?.edges.find(edge => edge.edge_id === selectedEdge) ?? null;
  const selectedNodeEdges = selectedNode ? (graph?.edges ?? []).filter(edge => displayId.get(edge.source) === selectedNode || displayId.get(edge.target) === selectedNode) : [];
  return <>
    <div className="workspace-entry" hidden={view !== 'incidents'}>
    <section className="panel"><div className="section-heading"><h3>待核查异常</h3>
      <button disabled={busy || loading} onClick={() => { setListError(''); void action((signal) => loadIncidents(signal)); }}>刷新检测事件</button></div>
      <p className="muted">规则命中不等于攻击，请结合证据核查。</p>
      {incidents ? <dl className="incident-metrics">
        <div><dt>会话规范事件</dt><dd>{eventCount?.toLocaleString('zh-CN') ?? '未知'}</dd></div>
        <div><dt>本页候选</dt><dd>{incidents.items.length} 条{incidents.next_cursor ? ' · 还有下一页' : ''}</dd></div>
      </dl> : null}
      <details className="inset"><summary>调查设置</summary>
      <div className="form-row"><label>调查模式<select disabled={busy || !!pendingCreate} value={investigationMode}
        onChange={(e) => setInvestigationMode(e.target.value as typeof investigationMode)}>
        <option value="auto">自动 · 按服务配置</option><option value="live">模型辅助 · 可能产生费用</option>
        <option value="deterministic">仅规则 · 不调用模型</option></select></label>
        <label>工具调用上限<input disabled={busy || !!pendingCreate} type="number" min="0" max="6" value={toolBudget} onChange={(e) => setToolBudget(Number(e.target.value))}/></label>
        <label>模型调用上限<input disabled={busy || !!pendingCreate} type="number" min="0" max="4" value={modelBudget} onChange={(e) => setModelBudget(Number(e.target.value))}/></label></div></details>
      <p className="mode-note">{investigationMode === 'deterministic' ? '仅规则 · 不调用模型' : investigationMode === 'live' ? '模型辅助 · 开始调查可能产生费用' : '自动模式 · 已配置模型时可能产生费用'}</p>
      {loading ? <p role="status">正在读取异常…</p> : null}
      {listError ? <p role="alert" className="error">{listError}</p> : null}
      {pendingCreate ? <p role="status">请求结果未确认。请重试同一调查，不要刷新页面重复创建。</p> : null}
      {incidents?.warnings?.includes('RULE_SCOPE_TOO_LARGE') ? <p role="alert">检测范围超限：已保留导入事件，当前候选目录不覆盖全部数据，请缩小后续分析范围。</p> : null}
      {incidents?.warnings?.filter(w => w !== 'RULE_SCOPE_TOO_LARGE').length ? <p role="alert">检测尚不完整：{incidents.warnings.filter(w => w !== 'RULE_SCOPE_TOO_LARGE').join(' · ')}</p> : null}
      {incidents?.items.length ? <ul className="incident-list">{incidents.items.map((item) => <li key={item.id}>
        <h4>{item.title}</h4><p className="muted">{item.start_time} — {item.end_time}（UTC）</p>
        {item.flood_observation ? <p className="muted">
          贡献证据可见 {item.flood_observation.observed_source_ip_count} 个源 IP，DoS / DDoS 来源分布未知。
        </p> : null}
        <div className="actions"><button className="primary" disabled={busy || creating || Boolean(pendingCreate && pendingCreate.incident !== item.id) || Boolean(run && (!status || ['queued', 'running'].includes(status.state))) || !Number.isInteger(toolBudget) || toolBudget < 0 || toolBudget > 6 || !Number.isInteger(modelBudget) || modelBudget < 0 || modelBudget > 4} onClick={() => void action(async (signal) => {
          setCreating(true);
          const pending = pendingCreate ?? { incident: item.id, key: crypto.randomUUID(),
            body: JSON.stringify({ mode: investigationMode, budget: { max_tool_calls: toolBudget, max_model_calls: modelBudget } }) };
          setPendingCreate(pending);
          try {
          const result = await api<RunResponse>(connection, `/incidents/${item.id}/investigations`, signal, {
            method: 'POST', headers: { 'Content-Type': 'application/json', 'Idempotency-Key': pending.key }, body: pending.body,
          });
          if (!signal.aborted) { setPendingCreate(null); setRun(result); setStatus(null); setGraph(null); setReport(null); setEvidence(null); setTimeline(null); setFocus(''); setGraphFocus(''); setAgentActions(null); setAgentTransitions(null); setTab('结论'); onReport(); }
          } catch (e) {
            if (!signal.aborted && e instanceof ApiError && e.status >= 400 && e.status < 500) setPendingCreate(null);
            throw e;
          } finally { if (!signal.aborted) setCreating(false); }
        })}>{pendingCreate?.incident === item.id ? '重试调查请求' : '开始调查'}</button>
        <button disabled={busy} onClick={() => void action(async signal => {
          const versions = await api<ReportPage>(connection, `/incidents/${item.id}/reports?limit=50`, signal);
          if (!signal.aborted) setSavedReports(versions);
        })}>查看历史报告</button></div>
        {item.aggregation_reasons?.length ? <details><summary>查看聚合理由</summary>
          <p>成员规则 {item.finding_ids?.length ?? 1} · 仅表示共同调查范围。</p>
          <pre>{JSON.stringify(item.aggregation_reasons, null, 2)}</pre></details> : null}
        </li>)}</ul> : !loading && !listError ? <p className="muted">{!incidents ? '点击刷新重试查询。'
          : incidents.warnings?.length ? '检测覆盖不足，不能据此判断是否存在规则命中。'
          : eventCount === 0 ? '当前数据集暂无规范事件，尚不能进行检测。'
          : '当前没有规则命中；这不证明没有攻击。'}</p> : null}
      {run && (!status || ['queued', 'running'].includes(status.state)) ? <button onClick={onReport}>查看正在进行的调查</button> : null}
      {incidents?.next_cursor ? <button disabled={busy} onClick={() => void action((signal) => loadIncidents(signal, incidents.next_cursor))}>下一页候选</button> : null}
    </section>
    {savedReports ? <section className="panel" role="region" aria-label="已有报告版本">
      <h3>已有报告版本</h3><p className="muted">打开历史报告不调用模型。</p>
      {savedReports.items.length ? <ul>{savedReports.items.map(item => <li key={item.report_id}>
        {item.generated_at} · {item.mode} · 快照 {item.snapshot_id}
        <button disabled={busy} onClick={() => void action(signal => openRun(item.run_id, signal))}>载入报告</button>
      </li>)}</ul> : <p>这个候选尚无已发布报告。</p>}
    </section> : null}
    </div>
    <div className="workspace-entry" hidden={view !== 'report'}>
    {!run ? <section className="panel empty-state"><h3>还未选择调查</h3><p>选择一条异常，开始调查或打开历史报告。</p><button className="primary" onClick={onIncidents}>选择异常</button></section> : null}
    {run ? <section className="panel run-banner" data-state={status?.state ?? run.state}><div className="section-heading"><h3 role="status">{stateLabels[status?.state ?? run.state] ?? status?.state}</h3><button onClick={onIncidents}>返回异常列表</button></div>
      {report && report.validation !== 'passed' ? <p role="alert">当前证据不可验证，历史结论仅供参考。</p> : null}
      {status?.state === 'partial' ? <p role="alert">调查未完成，仅保留已核验的结果。</p> : null}
      {status?.stop_reason ? <p role="status">停止原因：{status.stop_reason}</p> : null}
      {(!status || ['queued', 'running'].includes(status.state)) ? <button disabled={busy} onClick={() => void action(async (signal) => {
        const next = await api<RunStatus>(connection, `/investigations/${run.run_id}/cancel`, signal, { method: 'POST' });
        if (!signal.aborted) { setStatus(next); setRun({ ...run, state: next.state }); }
      })}>取消调查</button> : null}
      {readError ? <div role="alert" className="error">{readError}<button onClick={() => setPollRevision(old => old + 1)}>重试读取结果</button></div> : null}
      {!report && status && ['completed', 'partial'].includes(status.state) && !readError ? <p role="status">正在读取报告…</p> : null}
    </section> : null}
    {run ? <div className="result-tabs" role="group" aria-label="报告内容">{resultTabs.map(value => <button key={value} aria-pressed={tab === value} onClick={() => setTab(value)}>{value}</button>)}</div> : null}
    <div className="report-content" hidden={tab !== '运行记录'}>
    {status?.pipeline_progress && !report ? <PipelineProgressView progress={status.pipeline_progress}/> : null}
    {run ? <details className="panel"><summary>调查信息</summary><p>请求模式 {status?.requested_mode ?? investigationMode}</p><p>快照 {run.snapshot_id}</p><p>调查 {run.run_id}</p></details> : null}
    {run ? <AgentHistory status={status} actions={agentActions} transitions={agentTransitions} busy={busy}
      refresh={() => void action((signal) => loadAgent(signal))}
      next={() => void action((signal) => loadAgent(signal, agentActions?.next_cursor))}
      evidence={(id) => void action((signal) => openEvidence(id, signal))}/> : null}
    </div>
    <div className="report-content" hidden={tab !== '结论'}>
    {report ? <ReportPanel key={`${connection.token}:${report.report_id}`} report={report} connection={connection}
      onEvidence={id => void action(signal => openEvidence(id, signal))} onCached={setReport}
      onHistory={id => void action(signal => openRun(id, signal))}/> : null}
    {report ? <MissingEvidence report={report} status={status} busy={busy}
      onEvidence={(id) => void action((signal) => openEvidence(id, signal))}/> : null}
    </div>
    <div className="report-content" hidden={tab !== '补证对比'}>
    {report?.investigation_analysis && report.validation === 'passed' ? <EvidenceChanges analysis={report.investigation_analysis}
      busy={busy} onEvidence={(id) => void action((signal) => openEvidence(id, signal))}/> : null}
    {report && (!report.investigation_analysis || report.validation !== 'passed') ? <p className="notice">{report.validation !== 'passed' ? '证据尚未通过校验，无法展示补证对比。' : '本报告没有补证对比记录。'}</p> : null}
    </div>
    <div className="report-content" hidden={tab !== '关系与时间线'}>
    {timeline ? <section className="panel"><h3>冻结快照时间线</h3><p>本页 {timeline.items.length} 条</p>
      <p>按 UTC 时间、事件 ID 稳定排序，后续导入不会改变此快照。</p>
      <div className="table-wrap"><table><thead><tr><th>UTC 时间</th><th>类型 / 来源</th><th>引用</th></tr></thead>
        <tbody>{timeline.items.map((event) => <tr key={event.event_id}><td>{event.event_time}</td>
          <td>{event.event_type} / {event.sensor.type}</td><td><button disabled={busy}
            onClick={() => void action((signal) => openEvidence(event.event_id, signal))}>查看时间线证据</button></td></tr>)}</tbody></table></div>
      {timeline.next_cursor ? <button disabled={busy} onClick={() => void action(async (signal) => {
        const data = await api<EventPage>(connection, `/investigations/${run!.run_id}/timeline?limit=20&cursor=${encodeURIComponent(timeline.next_cursor!)}`, signal);
        if (!signal.aborted) setTimeline(data);
      })}>下一页时间线</button> : null}</section> : null}
    {report?.path_analysis && report.validation === 'passed' ? <Paths key={run?.run_id} analysis={report.path_analysis}
      busy={busy} onEvidence={(eventId) => void action((signal) => openEvidence(eventId, signal))}/> : null}
    {graph ? <section className="panel"><h3>证据关系图</h3><p>此图覆盖完整冻结快照；Agent 已核查的事件范围见补证对比。</p>
      <p>总量 {graph.total_nodes ?? graph.nodes.length} 节点 / {graph.total_edges ?? graph.edges.length} 边；已载入 {graph.nodes.length} 节点、{graph.edges.length} 边；实际绘制 {ids.length} 节点、{[...displayEdges.values()].reduce((sum, edge) => sum + edge.count, 0)} 条聚合前边。实线表示记录关系，虚线表示有约束的关联推断；均不等同攻击因果。</p>
      {graph.truncated ? <p role="alert">关系图已裁剪，不能视为全部关系。</p> : null}
      <div className="form-row"><label>图节点焦点<select value={focus} onChange={(e) => setFocus(e.target.value)}>
        <option value="">全部节点</option>{graph.nodes.map((node) => <option key={node.entity_id} value={node.entity_id}>{node.type} · {node.label}</option>)}
      </select></label><button disabled={busy} onClick={() => void action((signal) => loadGraph(signal))}>查询焦点关系</button>
      <label>绘制节点数<select value={graphLimit} onChange={(e) => setGraphLimit(Number(e.target.value))}>
        <option value={20}>20</option><option value={50}>50</option><option value={100}>100</option>
      </select></label></div>
      <p className="muted">端点按IP聚合展示，主机、账号和进程按独立身份展示。点击节点查看相关边，点击边查看判据、支持证据和限制。</p>
      <svg viewBox="0 0 1200 800" className="evidence-graph" role="img" aria-label="当前快照证据关系图">
        {[...displayEdges.entries()].map(([key, edge]) => {
          const a = points.get(edge.source), b = points.get(edge.target);
          const selected = selectedEdgeValue ? edge.edgeIds.includes(selectedEdgeValue.edge_id) : false;
          return a && b ? <g key={key}><line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={selected ? '#b45309' : '#729fac'} strokeWidth={selected ? '4' : '2'} strokeDasharray={edge.inferred ? '6 4' : undefined} style={{ cursor: 'pointer' }} onClick={() => setSelectedEdge(edge.edgeIds[0])}/>
            <text x={(a.x+b.x)/2} y={(a.y+b.y)/2-14} textAnchor="middle" fontSize="13">{edge.relation} ×{edge.count}</text></g> : null;
        })}
        {ids.map((id) => {
          const p = points.get(id)!, label = displayLabels.get(id)!;
          return <g key={id} role="button" tabIndex={0} aria-label={`图节点 ${label}`} style={{ cursor: 'pointer' }}
            onClick={() => { setSelectedNode(id); setFocus(id); }} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { setSelectedNode(id); setFocus(id); } }}>
            <circle cx={p.x} cy={p.y} r="22" fill={selectedNode === id ? '#b45309' : '#247b83'}><title>{label}</title></circle>
            <text x={p.x} y={p.y + 45} textAnchor="middle" fontSize="13">{label}</text></g>;
        })}
      </svg>
      {selectedEdgeValue ? <div className="inset" role="region" aria-label="图边详情"><h4>边详情 · {selectedEdgeValue.relation}</h4>
        <p>{nodeLabels.get(selectedEdgeValue.source)} → {nodeLabels.get(selectedEdgeValue.target)} · {selectedEdgeValue.kind} · 支持度 {selectedEdgeValue.score.toFixed(3)}</p>
        <p>{selectedEdgeValue.explanation} · {selectedEdgeValue.method}@{selectedEdgeValue.method_version}</p>
        <p>{selectedEdgeValue.observation_domain ? `观测域 ${selectedEdgeValue.observation_domain} · ` : ''}{selectedEdgeValue.valid_from ?? ''} — {selectedEdgeValue.valid_to ?? ''}</p>
        {selectedEdgeValue.limitations?.length ? <ul>{selectedEdgeValue.limitations.map(item => <li key={item}>{item}</li>)}</ul> : null}
        <div className="actions">{selectedEdgeValue.evidence_refs.map(ref => <button key={ref.event_id} disabled={busy}
          onClick={() => void action((signal) => openEvidence(ref.event_id, signal))}>查看证据 {ref.event_id.slice(0, 8)}</button>)}</div>
        <button onClick={() => setSelectedEdge('')}>关闭边详情</button></div> : null}
      {selectedNode ? <div className="inset" role="region" aria-label="图节点详情"><h4>节点详情 · {displayLabels.get(selectedNode) ?? nodeLabels.get(selectedNode) ?? selectedNode}</h4>
        <p>相关边 {selectedNodeEdges.length} 条；以下证据来自已载入关系，不代表完整快照。</p>
        <ul>{selectedNodeEdges.slice(0, 50).map(edge => <li key={edge.edge_id}>{edge.relation} · {edge.kind}
          <button disabled={busy} onClick={() => setSelectedEdge(edge.edge_id)}>查看判据</button>
          {edge.evidence_refs[0] ? <button disabled={busy} onClick={() => void action((signal) => openEvidence(edge.evidence_refs[0].event_id, signal))}>查看证据</button> : null}
        </li>)}</ul>
        <button onClick={() => setSelectedNode('')}>关闭节点详情</button></div> : null}
      <details><summary>展开全部边及证据</summary><ul>{graph.edges.map((edge) => <li key={edge.edge_id}>
        {nodeLabels.get(edge.source)} → {nodeLabels.get(edge.target)} · {edge.relation} · {edge.kind}
        <p>{edge.explanation} · {edge.method}@{edge.method_version}</p>
        <button disabled={busy} onClick={() => setSelectedEdge(edge.edge_id)}>查看边详情</button>
        <button disabled={busy} onClick={() => void action((signal) => openEvidence(edge.evidence_refs[0].event_id, signal))}>查看原始行脱敏投影</button>
      </li>)}</ul></details>
      {graph.next_cursor ? <button disabled={busy} onClick={() => void action((signal) => loadGraph(signal, graph.next_cursor))}>载入下一页关系</button> : null}
    </section> : null}
    </div>
    </div>
    {evidence ? <EvidenceDialog evidence={evidence} busy={busy} onClose={() => setEvidence(null)}
      next={() => void action(signal => openEvidence(evidence.event_id, signal, evidence.next_cursor))}/> : null}
    {error ? <section className="panel"><p role="alert" className="error">{error}</p></section> : null}
  </>;
}
