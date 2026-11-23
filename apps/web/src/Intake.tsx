import { useEffect, useRef, useState } from 'react';
import { EvidenceDialog } from './EvidenceDialog';
import { ReplayPanel } from './ReplayPanel';
import { api, ApiError } from './client';
import { identifySource, isClassicPcap, sourceFamily } from './importHints';
import type { ContextResponse, DatasetPage, DatasetResponse, EventPage, EvidenceResponse, ImportResponse, ImportStatus } from '../../../packages/contracts/generated/api';

const importLabels = { queued: '等待处理', running: '正在导入', succeeded: '导入完成', partial: '部分导入', failed: '导入失败', cancelled: '已取消' };

export function Intake({ onScopeChange, onContinue }: {
  onScopeChange: (token: string, dataset: DatasetResponse | null, sessionId?: string) => void;
  onContinue: () => void;
}) {
  const [draftToken, setDraftToken] = useState('');
  const [token, setToken] = useState('');
  const [connected, setConnected] = useState(false);
  const [datasets, setDatasets] = useState<DatasetResponse[]>([]);
  const [selected, setSelected] = useState('');
  const [name, setName] = useState('');
  const [source, setSource] = useState('zeek');
  const [sensor, setSensor] = useState('');
  const [suggestedSensors, setSuggestedSensors] = useState<string[]>([]);
  const [configuredSensors, setConfiguredSensors] = useState<{ sensor_id: string; source_type: string }[]>([]);
  const [identifying, setIdentifying] = useState(false);
  const [fileHint, setFileHint] = useState('');
  const fileSelection = useRef(0);
  const [file, setFile] = useState<File | null>(null);
  const [batchId, setBatchId] = useState('');
  const [status, setStatus] = useState<ImportStatus | null>(null);
  const [events, setEvents] = useState<EventPage | null>(null);
  const [packetEvidence, setPacketEvidence] = useState<EvidenceResponse | null>(null);
  const [evidenceBusy, setEvidenceBusy] = useState(false);
  const packetScope = events?.packet_evidence_scope;
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [eventBusy, setEventBusy] = useState(false);
  const [eventError, setEventError] = useState('');
  const [contextFile, setContextFile] = useState<File | null>(null);
  const [contextHash, setContextHash] = useState('');
  const [datasetCursor, setDatasetCursor] = useState<string | null>(null);
  const [session, setSession] = useState<{ scope: string; id: string } | null>(null);
  const [showEvents, setShowEvents] = useState(false);
  const [eventRevision, setEventRevision] = useState(0);
  const [pollRevision, setPollRevision] = useState(0);
  const dataset = datasets.find(d => d.dataset_id === selected);
  const scopeKey = `${token}:${selected}`;
  const sessionId = session?.scope === scopeKey ? session.id : dataset?.default_session_id;
  const lifecycle = useRef(new AbortController());
  const eventRequest = useRef(new AbortController());
  const evidenceRequest = useRef(new AbortController());
  const working = useRef(false);
  const upload = useRef<{ key: string; form: FormData } | null>(null);
  const [uncertain, setUncertain] = useState(false);
  const [uploadAccepted, setUploadAccepted] = useState(false);
  const connection = { token, dataset: dataset ?? null, sessionId };
  const sensorOptions = suggestedSensors.length ? suggestedSensors :
    configuredSensors.filter(item => item.source_type === sourceFamily(source)).map(item => item.sensor_id);
  useEffect(() => {
    const controller = new AbortController(); lifecycle.current = controller;
    return () => controller.abort();
  }, []);
  useEffect(() => { onScopeChange(token, dataset ?? null, sessionId); }, [token, dataset, sessionId, onScopeChange]);

  function resetScope() {
    lifecycle.current.abort(); lifecycle.current = new AbortController();
    eventRequest.current.abort(); evidenceRequest.current.abort();
    setPacketEvidence(null); setEvidenceBusy(false);
    setEvents(null); setError(''); setEventError(''); setBatchId(''); setStatus(null);
    setContextHash(''); setSession(null); upload.current = null;
    setConfiguredSensors([]); setSensor(''); setSuggestedSensors([]); setFileHint(''); fileSelection.current++; setIdentifying(false);
    setUncertain(false); setUploadAccepted(false);
  }
  function chooseSource(value: string) {
    if (value === source) return;
    setSource(value); setSuggestedSensors([]);
    const matches = configuredSensors.filter(item => item.source_type === sourceFamily(value));
    setSensor(matches.length === 1 ? matches[0].sensor_id : '');
  }
  async function chooseFile(value: File | null) {
    const selection = ++fileSelection.current;
    setFile(value); upload.current = null; setUploadAccepted(false); setFileHint('');
    if (!value) return;
    setIdentifying(true);
    try {
      const prefix = new Uint8Array(await value.slice(0, 64 * 1024).arrayBuffer());
      if (selection !== fileSelection.current) return;
      const detected = isClassicPcap(prefix) ? 'pcap_packet' : identifySource(new TextDecoder().decode(prefix));
      chooseSource(detected ?? '');
      setFileHint(detected ? '已识别日志类型，可手动调整。' : '无法确认日志类型，请手动选择。');
    } catch { if (selection === fileSelection.current) { setSource(''); setFileHint('无法读取文件，请重新选择。'); } }
    finally { if (selection === fileSelection.current) setIdentifying(false); }
  }
  async function action(work: (signal: AbortSignal) => Promise<void>) {
    if (working.current) return;
    const signal = lifecycle.current.signal;
    working.current = true; setError(''); setBusy(true);
    try { await work(signal); }
    catch (e) { if (!signal.aborted) setError(e instanceof Error ? e.message : '操作失败'); }
    finally { working.current = false; if (!signal.aborted) setBusy(false); }
  }

  async function loadPacketEvidence(eventId: string, scope: string) {
    evidenceRequest.current.abort();
    const controller = new AbortController();
    evidenceRequest.current = controller;
    setEvidenceBusy(true); setEventError('');
    const params = new URLSearchParams({ packet_scope: scope });
    try {
      const evidence = await api<EvidenceResponse>(connection, '/evidence/' + eventId + '?' + params, controller.signal);
      if (!controller.signal.aborted) setPacketEvidence(evidence);
    } catch (e) {
      if (!controller.signal.aborted) setEventError(e instanceof Error ? e.message : '证据回查失败');
    } finally {
      if (!controller.signal.aborted) setEvidenceBusy(false);
    }
  }

  async function loadEvents(cursor?: string | null) {
    if (!dataset || !sessionId) return;
    eventRequest.current.abort();
    const controller = new AbortController(); eventRequest.current = controller;
    setEventBusy(true); setEventError('');
    const params = new URLSearchParams({ dataset_id: dataset.dataset_id, session_id: sessionId, limit: '20' });
    if (cursor) params.set('cursor', cursor);
    try {
      const result = await api<EventPage>(connection, `/events?${params}`, controller.signal);
      if (!controller.signal.aborted) setEvents(result);
    } catch (e) { if (!controller.signal.aborted) setEventError(e instanceof Error ? e.message : '查询失败'); }
    finally { if (!controller.signal.aborted) setEventBusy(false); }
  }
  useEffect(() => {
    eventRequest.current.abort(); evidenceRequest.current.abort();
    setPacketEvidence(null); setEvidenceBusy(false); setEvents(null); setEventError(''); setEventBusy(false);
    if (!showEvents || !token || !selected || !sessionId) return;
    const controller = new AbortController(); eventRequest.current = controller;
    setEventBusy(true);
    const params = new URLSearchParams({ dataset_id: selected, session_id: sessionId, limit: '20' });
    api<EventPage>({ token, dataset: null }, `/events?${params}`, controller.signal)
      .then(value => { if (!controller.signal.aborted) setEvents(value); })
      .catch((e: unknown) => { if (!controller.signal.aborted) setEventError(e instanceof Error ? e.message : '查询失败'); })
      .finally(() => { if (!controller.signal.aborted) setEventBusy(false); });
    return () => { controller.abort(); evidenceRequest.current.abort(); };
  }, [token, selected, sessionId, showEvents, eventRevision]);

  const importActive = Boolean(batchId && (!status || ['queued', 'running'].includes(status.status)));
  useEffect(() => {
    if (!batchId || !token || !importActive) return;
    const controller = new AbortController();
    let timer = 0;
    async function poll() {
      try {
        const value = await api<ImportStatus>({ token, dataset: null }, `/imports/${batchId}`, controller.signal);
        if (controller.signal.aborted) return;
        setStatus(value);
        if (['queued', 'running'].includes(value.status)) timer = window.setTimeout(() => void poll(), 2000);
        else setEventRevision(old => old + 1);
      } catch (e) { if (!controller.signal.aborted) setError(e instanceof Error ? e.message : '进度查询失败'); }
    }
    void poll();
    return () => { controller.abort(); window.clearTimeout(timer); };
  }, [batchId, token, importActive, pollRevision]);

  return <>
    {!connected ? <section className="panel connect-panel"><h3>连接工作区</h3>
      <form className="form-row" onSubmit={e => { e.preventDefault(); void action(async signal => {
        const value = draftToken.trim();
        const result = await api<DatasetPage>({ token: value, dataset: null }, '/datasets', signal);
        if (signal.aborted) return;
        setToken(value); setDatasets(result.items); setDatasetCursor(result.next_cursor);
        setSelected(result.items[0]?.dataset_id ?? ''); setConnected(true); setDraftToken('');
      }); }}><label>访问令牌<input disabled={busy} type="password" autoComplete="off" value={draftToken}
        placeholder="粘贴管理员提供的令牌" onChange={e => setDraftToken(e.target.value)}/></label>
        <button className="primary" disabled={busy || !draftToken.trim()}>{busy ? '连接中…' : '连接'}</button></form>
      <p className="muted">令牌仅保留在当前页面，刷新后需重新连接。</p>
    </section> : <>
      <section className="panel workspace-panel"><div className="section-heading"><div><span className="muted">当前数据集</span>
        <h3>{dataset?.name ?? '新建一个数据集开始'}</h3></div><div className="actions">
        {dataset ? <button className="primary" disabled={busy} onClick={onContinue}>查看异常</button> : null}
        <button disabled={busy} onClick={() => { resetScope(); setToken(''); setConnected(false); setDatasets([]); setSelected(''); }}>断开连接</button>
      </div></div>
      <details open={!dataset}><summary>切换或新建数据集</summary>
        {importActive ? <p className="muted">切换数据集后，当前导入仍会在后台继续。</p> : null}
        <div className="form-row"><label>数据集<select disabled={busy} value={selected} onChange={e => { resetScope(); setSelected(e.target.value); }}>
          <option value="">请选择</option>{datasets.map(d => <option key={d.dataset_id} value={d.dataset_id}>{d.name} · {d.provenance_type === 'synthetic' ? '合成数据' : d.provenance_type}</option>)}</select></label>
          <button disabled={busy} onClick={() => void action(async signal => {
            const result = await api<DatasetPage>(connection, `/datasets${datasetCursor ? `?cursor=${encodeURIComponent(datasetCursor)}` : ''}`, signal);
            if (!signal.aborted) { setDatasets(old => [...new Map([...old, ...result.items].map(d => [d.dataset_id, d])).values()]); setDatasetCursor(result.next_cursor); }
          })}>{datasetCursor ? '载入更多数据集' : '刷新列表'}</button></div>
        <form className="form-row" onSubmit={e => { e.preventDefault(); void action(async signal => {
          const result = await api<DatasetResponse>(connection, '/datasets', signal, { method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Idempotency-Key': crypto.randomUUID() },
            body: JSON.stringify({ name: name.trim(), provenance_type: 'synthetic' }) });
          if (!signal.aborted) { resetScope(); setDatasets(old => [...old, result]); setSelected(result.dataset_id); setName(''); setBusy(false); }
        }); }}><label>新数据集名称<input disabled={busy} maxLength={200} value={name} onChange={e => setName(e.target.value)}/></label>
          <button disabled={busy || !name.trim()}>创建合成数据集</button></form>
      </details></section>
      {dataset ? <>
        <section className="panel"><div className="section-heading"><h3>导入日志</h3><span className="muted">JSON / JSONL · 每个文件不超过 100 MB</span></div>
          <details className="inset"><summary>资产配置</summary>
            <p className="muted">Linux 日志需先上传管理员提供的配置。首次导入后不可修改。</p>
            <div className="form-row"><label>上下文 JSON<input disabled={busy || importActive} type="file" accept=".json" onChange={e => setContextFile(e.target.files?.[0] ?? null)}/></label>
              <button disabled={busy || importActive || !contextFile} onClick={() => void action(async signal => {
                if (!contextFile) return;
                if (contextFile.size > 1024 * 1024) throw new Error('配置文件超过 1 MB');
                const body: unknown = JSON.parse(await contextFile.text());
                const result = await api<ContextResponse>(connection, `/datasets/${dataset.dataset_id}/context`, signal, {
                  method: 'POST', headers: { 'Content-Type': 'application/json', 'Idempotency-Key': crypto.randomUUID() }, body: JSON.stringify(body) });
                if (!signal.aborted) {
                  setContextHash(result.context_hash);
                  // Only retain identifiers after the server accepted the full context.
                  const sensors = (body as { sensors: { sensor_id: string; source_type: string }[] }).sensors;
                  setConfiguredSensors(sensors.map(item => ({ sensor_id: item.sensor_id, source_type: item.source_type })));
                  const matches = sensors.filter(item => item.source_type === sourceFamily(source));
                  setSuggestedSensors([]);
                  setSensor(matches.length === 1 ? matches[0].sensor_id : '');
                }
              })}>配置上下文</button></div>
            {contextHash ? <p role="status" title={contextHash}>配置已保存</p> : null}
          </details>
          <label className="file-picker">日志文件<input disabled={busy || importActive || uncertain} type="file" accept=".jsonl,.json,.pcap,.pcp" onChange={e => void chooseFile(e.target.files?.[0] ?? null)}/></label>
          {identifying ? <p role="status">正在识别文件…</p> : fileHint ? <p className="muted">{fileHint}</p> : null}
          <div className="form-row"><label>日志类型<select disabled={busy || importActive || uncertain || identifying} value={source} onChange={e => chooseSource(e.target.value)}>
            <option value="">请选择日志类型</option>
            <option value="zeek">网络连接 · Zeek</option><option value="suricata">安全告警 · Suricata</option>
            <option value="zeek_http">网页请求 · HTTP</option><option value="zeek_dns">域名查询 · DNS</option>
            <option value="pcap">抓包连接 · JSONL</option><option value="pcap_http">抓包请求 · JSONL</option><option value="pcap_packet">包观测 · PCAP</option>
            <option value="linux_auth">登录记录 · Linux auth</option><option value="linux_audit">主机行为 · Linux audit</option></select></label>
            <label>传感器<input list="configured-sensors" placeholder="留空自动选择" aria-describedby="import-sensor-hint" disabled={busy || importActive || uncertain || identifying} value={sensor} onChange={e => setSensor(e.target.value)}/></label>
            <datalist id="configured-sensors">{sensorOptions.map(id => <option key={id} value={id}/>)}</datalist></div>
          <p className="muted" id="import-sensor-hint">{sensorOptions.length > 1
            ? '有多个匹配的采集点，请选择对应传感器。'
            : '传感器留空时自动选择；Linux 日志采用资产配置中的采集点。'}</p>
          <div className="actions"><button className="primary" disabled={busy || importActive || uploadAccepted || identifying || !source || !file} onClick={() => void action(async signal => {
            if (!file) return;
            if (file.size > 100 * 1024 * 1024) throw new Error('文件超过 100 MB，请拆分后上传');
            if (!upload.current) {
              const form = new FormData(); form.set('file', file); form.set('dataset_id', dataset.dataset_id);
              form.set('source_type', source); form.set('timezone', 'UTC');
              if (sensor.trim()) form.set('sensor_id', sensor.trim());
              upload.current = { key: crypto.randomUUID(), form };
            }
            setUncertain(true);
            try {
              const result = await api<ImportResponse>(connection, '/imports', signal, { method: 'POST',
                headers: { 'Idempotency-Key': upload.current.key }, body: upload.current.form });
              if (!signal.aborted) {
                setUncertain(false); setUploadAccepted(true); setBatchId(result.batch_id); setStatus(null);
                setSuggestedSensors([]); setSession({ scope: scopeKey, id: dataset.default_session_id });
              }
            } catch (e) {
              if (!signal.aborted && e instanceof ApiError && e.status === 422) {
                setUncertain(false); upload.current = null;
                if (e.code === 'SENSOR_SELECTION_REQUIRED') {
                  const options = e.details?.sensor_ids;
                  setSuggestedSensors(Array.isArray(options)
                    ? options.filter((id): id is string => typeof id === 'string') : []);
                  throw new Error('此数据集有多个匹配的采集点，请选择传感器后上传。', { cause: e });
                }
              }
              throw e;
            }
          })}>{busy ? '正在处理…' : uncertain ? '重试上传' : '上传日志'}</button>
          {status && ['succeeded', 'partial'].includes(status.status) ? <button onClick={() => { setSession({ scope: scopeKey, id: dataset.default_session_id }); onContinue(); }}>查看导入结果</button> : null}
          {uncertain ? <button disabled={busy} onClick={() => { upload.current = null; setUncertain(false); }}>调整文件或设置</button> : null}</div>
          {uncertain ? <p role="status">上传结果未确认。重试沿用同一请求；调整后提交可能重复，请先核查。</p> : null}
          {status ? <div data-testid="import-status" className={`notice ${status.status === 'partial' || status.status === 'failed' ? 'warning' : ''}`}>
            <p role="status">{importLabels[status.status]} · 新增 {status.accepted} · 重复 {status.duplicate} · 隔离 {status.quarantined}</p>
            {status.error_code ? <p role="alert">{status.error_code}</p> : null}
            {status.status === 'partial' ? <p role="alert">检测或导入尚不完整，请查看异常页的覆盖限制。</p> : null}
            <details><summary>导入详情</summary><p>批次 {batchId} · {status.status}</p><p>物理记录 {status.raw_records} · 已聚合记录 {status.aggregated_records}{status.skipped != null && <span> · 跳过 {status.skipped}</span>}</p></details>
          </div> : importActive ? <p role="status">等待后台处理…</p> : null}
          {importActive && error ? <button onClick={() => { setError(''); setPollRevision(old => old + 1); }}>重试进度查询</button> : null}
        </section>
        <details className="panel disclosure"><summary>已有事件回放</summary><ReplayPanel key={scopeKey} connection={connection} onSelect={id => setSession({ scope: scopeKey, id })}/></details>
        <details className="panel disclosure" onToggle={e => setShowEvents(e.currentTarget.open)}><summary>原始事件查询</summary>
          <button disabled={eventBusy} onClick={() => void loadEvents()}>刷新事件</button>
          {eventBusy ? <p role="status">正在读取…</p> : null}
          {eventError ? <p role="alert">{eventError}</p> : null}
          {events?.items.length ? <div className="table-wrap"><table><thead><tr><th>时间（UTC）</th><th>类型</th><th>来源</th><th>原始位置</th></tr></thead>
            <tbody>{events.items.map(e => <tr key={e.event_id}><td>{e.event_time}</td><td>{e.event_type}</td><td>{e.sensor.type}</td><td><details><summary>查看事件与引用</summary><pre>{JSON.stringify(e, null, 2)}</pre></details>{e.event_type === 'network.packet' && packetScope && <button disabled={evidenceBusy} onClick={() => void loadPacketEvidence(e.event_id, packetScope)}>核验原始包</button>}</td></tr>)}</tbody></table></div>
            : events ? <p className="muted">当前会话暂无事件。</p> : null}
          {events?.next_cursor ? <button disabled={eventBusy} onClick={() => void loadEvents(events.next_cursor)}>下一页</button> : null}
        </details>
      </> : null}
    </>}
    {packetEvidence && <EvidenceDialog evidence={packetEvidence} busy={false} onClose={() => setPacketEvidence(null)}/>}
    {error ? <div className="notice error" role="alert">{error}</div> : null}
  </>;
}
