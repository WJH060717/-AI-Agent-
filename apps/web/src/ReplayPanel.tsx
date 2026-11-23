import { useEffect, useRef, useState } from 'react';
import type { ReplayCreate, ReplayStatus } from '../../../packages/contracts/generated/api';
import { api, type Connection } from './client';

export function ReplayPanel({ connection, onSelect }: {
  connection: Connection; onSelect: (session: string) => void;
}) {
  const [rate, setRate] = useState(50);
  const [jobId, setJobId] = useState('');
  const [status, setStatus] = useState<ReplayStatus | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [pending, setPending] = useState<{ key: string; body: ReplayCreate } | null>(null);
  const lifecycle = useRef(new AbortController());
  useEffect(() => {
    const controller = new AbortController(); lifecycle.current = controller;
    return () => controller.abort();
  }, []);

  const accept = (value: ReplayStatus) => {
    if (value.dataset_id !== connection.dataset!.dataset_id) throw new Error('回放不属于当前数据集');
    setStatus(value); setJobId(value.job_id); onSelect(value.session_id);
  };

  async function action(work: (signal: AbortSignal) => Promise<void>) {
    const signal = lifecycle.current.signal;
    setBusy(true); setError('');
    try { await work(signal); }
    catch (e) { if (!signal.aborted) setError(e instanceof Error ? e.message : '回放请求失败'); }
    finally { if (!signal.aborted) setBusy(false); }
  }

  const pollingId = status && ['queued', 'running'].includes(status.state) ? status.job_id : null;
  useEffect(() => {
    if (!pollingId) return;
    const controller = new AbortController();
    let timer = 0;
    async function poll() {
      try {
        const value = await api<ReplayStatus>(connection, `/replays/${pollingId}`, controller.signal);
        if (controller.signal.aborted) return;
        setStatus(value);
        if (['queued', 'running'].includes(value.state)) timer = window.setTimeout(() => void poll(), 1000);
      } catch (e) {
        if (!controller.signal.aborted) {
          setError(e instanceof Error ? e.message : '进度查询失败');
          timer = window.setTimeout(() => void poll(), 3000);
        }
      }
    }
    timer = window.setTimeout(() => void poll(), 500);
    return () => { controller.abort(); window.clearTimeout(timer); };
  }, [pollingId, connection.token, connection.dataset?.dataset_id]);

  return <section className="panel" aria-label="回放控制">
    <h3>已有事件回放</h3>
    <p className="muted">按指定速度重现已有事件，结束后检测；不采集新数据。</p>
    <div className="form-row">
      <label>回放速率（EPS）<input type="number" min="1" max="1000" step="1" value={rate}
        disabled={busy || !!pending} onChange={e => setRate(Number(e.target.value))}/></label>
      <button disabled={busy || !!pollingId || !Number.isInteger(rate) || rate < 1 || rate > 1000}
        onClick={() => void action(async signal => {
          const request = pending ?? { key: crypto.randomUUID(), body: {
            source_session_id: connection.dataset!.default_session_id, rate_eps: rate,
          } };
          setPending(request);
          const value = await api<ReplayStatus>(connection, `/datasets/${connection.dataset!.dataset_id}/replays`, signal, {
            method: 'POST', headers: { 'Content-Type': 'application/json', 'Idempotency-Key': request.key },
            body: JSON.stringify(request.body),
          });
          if (!signal.aborted) { accept(value); setPending(null); }
        })}>{pending ? '重试创建（同一请求）' : '创建回放'}</button>
      <button disabled={busy} onClick={() => onSelect(connection.dataset!.default_session_id)}>返回导入会话</button>
    </div>
    {pending ? <p>创建结果尚未确认。重试会使用同一幂等键和参数；请勿刷新页面后重复创建。</p> : null}
    <div className="form-row"><label>回放作业 ID<input value={jobId} disabled={busy}
      onChange={e => setJobId(e.target.value)}/></label>
      <button disabled={busy || !/^[a-f0-9-]{36}$/i.test(jobId)} onClick={() => void action(async signal => {
        const value = await api<ReplayStatus>(connection, `/replays/${encodeURIComponent(jobId)}`, signal);
        if (!signal.aborted) accept(value);
      })}>打开回放</button>
    </div>
    {status ? <div data-testid="replay-status">
      <p role="status">{status.state} · {status.published_events} / {status.total_events} · 检测 {status.detection_status}</p>
      <progress value={status.published_events} max={Math.max(1, status.total_events)} aria-label="回放进度"/>
      <details><summary>回放详情</summary><p>作业 {status.job_id}<br/>回放会话 {status.session_id}<br/>源水位 {status.source_high_water} · {status.rate_eps} EPS</p></details>
      {status.warnings?.length ? <p role="alert">检测尚不完整：{status.warnings?.join(' · ')}</p> : null}
      <button disabled={busy || !pollingId} onClick={() => void action(async signal => {
        await api(connection, `/jobs/${status.job_id}/cancel`, signal, { method: 'POST' });
        const value = await api<ReplayStatus>(connection, `/replays/${status.job_id}`, signal);
        if (!signal.aborted) setStatus(value);
      })}>取消回放</button>
    </div> : null}
    {error ? <p role="alert" className="error">{error}</p> : null}
  </section>;
}
