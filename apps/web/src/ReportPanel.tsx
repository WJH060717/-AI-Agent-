import { useEffect, useRef, useState } from 'react';
import type { Report, ReportPage, ReviewCreate, ReviewPage, ReviewRecord } from '../../../packages/contracts/generated/api';
import { api, type Connection } from './client';
import { PipelineProgressView } from './PipelineProgress';

export function ReportPanel({ report, connection, onEvidence, onCached, onHistory }: {
  report: Report; connection: Connection; onEvidence: (id: string) => void;
  onCached: (report: Report) => void; onHistory: (runId: string) => void;
}) {
  const [reviews, setReviews] = useState<ReviewPage | null>(null);
  const [history, setHistory] = useState<ReportPage | null>(null);
  const [claimId, setClaimId] = useState('');
  const [decision, setDecision] = useState<ReviewCreate['decision']>('needs_more_evidence');
  const [comment, setComment] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const pendingReview = useRef<{ body: string; key: string } | null>(null);
  const lifecycle = useRef(new AbortController());
  useEffect(() => {
    const controller = new AbortController(); lifecycle.current = controller;
    return () => controller.abort();
  }, []);
  const base = `/reports/${report.report_id}`;
  async function action(work: (signal: AbortSignal) => Promise<void>) {
    const signal = lifecycle.current.signal;
    setBusy(true); setError('');
    try { await work(signal); } catch (e) {
      if (!signal.aborted) setError(e instanceof Error ? e.message : '操作失败');
    } finally { if (!signal.aborted) setBusy(false); }
  }
  async function loadReviews(signal: AbortSignal, cursor?: string | null) {
    const data = await api<ReviewPage>(connection, `${base}/reviews?limit=20${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`, signal);
    if (!signal.aborted) setReviews(old => cursor && old ? { ...data, items: [...old.items, ...data.items] } : data);
  }
  async function download(format: 'json' | 'html', signal: AbortSignal) {
    const response = await fetch(`/api/v1${base}/export?format=${format}`, {
      signal, headers: { Authorization: `Bearer ${connection.token}` },
    });
    if (!response.ok) {
      const data = await response.json();
      throw new Error(`${data.error?.message ?? '下载失败'} (${response.status})`);
    }
    const blob = await response.blob();
    if (signal.aborted) return;
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a'); anchor.href = url;
    anchor.download = `report-${report.report_id}.${format}`; anchor.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  return <section className="panel" role="region" aria-label="报告与人工复核">
    <h3>{report.mode === 'cached' ? '历史缓存报告' : report.mode === 'live' ? '模型调查报告' : '规则调查报告'}</h3>
    <p>{report.mode === 'cached' ? `历史结果 · 原模式 ${report.provenance.source_mode} · 本次没有调用模型` : report.provenance.model_execution === 'protocol_test_stub' ? '本地协议测试桩（非真实LLM）' : report.mode === 'live' ? '已配置模型的本次调用结果' : '确定性结果 / 模型未完成或未启用'}</p>
    {report.mode === 'cached' && report.provenance.model_execution === 'protocol_test_stub' ? <p>原运行：本地协议测试桩（非真实LLM）</p> : null}
    <p>{report.summary}</p><p>模式：{report.mode} · 校验：{report.validation} · 生成：{report.generated_at}</p>
    <PipelineProgressView progress={report.pipeline_progress}/>
    <div className="actions"><button className="primary" disabled={busy} onClick={() => void action(signal => download('html', signal))}>导出 HTML</button>
      <button disabled={busy} onClick={() => void action(signal => download('json', signal))}>导出 JSON</button></div>
    <details className="inset"><summary>版本与费用</summary>
      <p>快照 {report.snapshot_id} · 报告 {report.report_id}</p>
      <p>费用预留 USD {(Number(report.provenance.cost_microusd ?? 0) / 1_000_000).toFixed(6)} · 返回用量估算 USD {(Number(report.provenance.actual_cost_microusd ?? 0) / 1_000_000).toFixed(6)}。非账单；失败和中断保留预留。</p>
    <div className="form-row">
      <button disabled={busy} onClick={() => void action(async signal => {
        const value = await api<Report>(connection, `${base}?mode=cached`, signal);
        if (!signal.aborted) onCached(value);
      })}>读取匹配缓存</button>
      <button disabled={busy} onClick={() => void action(async signal => {
        const value = await api<ReportPage>(connection, `/incidents/${report.provenance.incident_id}/reports?limit=50`, signal);
        if (!signal.aborted) setHistory(value);
      })}>刷新报告版本</button></div>
    <p>导出为脱敏证据附件，需要 analyst/admin；当前显示为缓存时，下载保留原报告模式与生成时间。</p>
    {history ? <ul>{history.items.map(item => <li key={item.report_id}>{item.generated_at} · {item.mode} · {item.snapshot_id} <button disabled={busy} onClick={() => onHistory(item.run_id)}>打开历史版本</button></li>)}</ul> : null}
    </details>
    {report.behavior_assessments == null ? <p>历史报告未记录溯源结果。</p>
      : report.behavior_assessments.length === 0 ? <p>本次未记录第 13.9 节的行为命中。</p>
      : report.behavior_assessments.map(assessment => <article className="claim" key={assessment.finding_id}>
        <h4>检测到 {assessment.label} · {assessment.trace_status === 'successful' ? '溯源成功' : '溯源未成功'}</h4>
        <p>{assessment.rule_id} / {assessment.rule_version} · {assessment.start_time} 至 {assessment.end_time}</p>
        <p>观测范围 {[...assessment.observation_domains, ...assessment.sensor_instances].join(' / ')}</p>
        <p>溯源范围 {assessment.trace_scope}。{assessment.trace_clue} {assessment.trace_reason}</p>
        {assessment.limitations?.length ? <ul>{assessment.limitations.map((text, index) => <li key={index}>{text}</li>)}</ul> : null}
        <details><summary>查看检测与溯源证据</summary>
          {assessment.evidence_refs.map((ref, index) => <button key={ref.event_id} disabled={busy} onClick={() => onEvidence(ref.event_id)}>检测证据 {index + 1}</button>)}
          {assessment.trace_evidence_refs?.map((ref, index) => <button key={ref.event_id} disabled={busy} onClick={() => onEvidence(ref.event_id)}>溯源证据 {index + 1}</button>)}
        </details>
      </article>)}
    {report.claims.map(claim => <article className="claim" key={claim.claim_id}><h4><span className="badge" data-kind={claim.kind}>{{ observed: '事实', inferred: '推断', hypothesized: '假设', unknown: '未知' }[claim.kind] ?? claim.kind}</span>{claim.statement}</h4>
      {claim.limitations?.length ? <details><summary>适用限制</summary><ul>{claim.limitations.map((text, i) => <li key={i}>{text}</li>)}</ul></details> : null}
      {claim.evidence_refs?.length ? <details><summary>查看证据 · {claim.evidence_refs.length}</summary>
        {claim.evidence_refs.map((ref, i) => <button key={ref.event_id} disabled={busy} onClick={() => onEvidence(ref.event_id)}>证据 {i + 1}</button>)}
      </details> : null}
      <button disabled={busy} onClick={() => setClaimId(claim.claim_id)}>复核本条</button>
    </article>)}
    {claimId ? <form onSubmit={event => {
      event.preventDefault();
      void action(async signal => {
        const body = JSON.stringify({ claim_id: claimId, decision, comment });
        if (pendingReview.current?.body !== body) pendingReview.current = { body, key: crypto.randomUUID() };
        await api<ReviewRecord>(connection, `${base}/reviews`, signal, { method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Idempotency-Key': pendingReview.current.key }, body });
        if (!signal.aborted) { pendingReview.current = null; setComment(''); }
        await loadReviews(signal);
      });
    }}><p>复核意见不改变报告事实。</p><details><summary>结论标识</summary><code>{claimId}</code></details>
      <label>复核决定<select disabled={busy} value={decision} onChange={e => setDecision(e.target.value as ReviewCreate['decision'])}>
        <option value="accepted">接受该条</option><option value="rejected">不接受该条</option><option value="needs_more_evidence">需要补证</option>
      </select></label><label>复核说明<textarea required maxLength={2000} disabled={busy} value={comment} onChange={e => setComment(e.target.value)}/></label>
      <div className="actions"><button disabled={busy || !comment.trim()}>保存复核意见</button>
        <button type="button" disabled={busy} onClick={() => { setClaimId(''); setComment(''); }}>收起复核</button></div></form> : null}
    <button disabled={busy} onClick={() => void action(signal => loadReviews(signal))}>刷新人工复核</button>
    {reviews ? <ul aria-label="人工复核记录">{reviews.items.map(item => <li key={item.review_id}>{item.claim_id} · {item.decision} · {item.comment}<p>{item.created_at} · 复核身份 {item.actor_id}</p></li>)}</ul> : null}
    {reviews?.next_cursor ? <button disabled={busy} onClick={() => void action(signal => loadReviews(signal, reviews.next_cursor))}>更多复核记录</button> : null}
    <h4>其他解释</h4><ul>{(report.alternatives ?? []).map(text => <li key={text}>{text}</li>)}</ul>
    <h4>未知与缺口</h4><ul>{(report.gaps ?? []).map(text => <li key={text}>{text}</li>)}</ul>
    <h4>建议人工检查</h4><ul>{(report.recommendations ?? []).map(text => <li key={text}>{text}</li>)}</ul>
    <details><summary>报告版本与来源</summary><pre>{JSON.stringify(report.provenance, null, 2)}</pre></details>
    {error ? <p role="alert">{error}</p> : null}
  </section>;
}
