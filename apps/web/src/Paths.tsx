import { useState } from 'react';
import type { PathAnalysis } from '../../../packages/contracts/generated/api';

export function Paths({ analysis, onEvidence, busy }: {
  analysis: PathAnalysis; onEvidence: (eventId: string) => void; busy: boolean;
}) {
  const [selected, setSelected] = useState(0);
  const path = analysis.paths[selected];
  const links = new Map(analysis.links.map((link) => [link.edge_id, link]));
  return <section className="panel"><h3>候选入口与证据路径</h3>
    <p>范围：{analysis.scope.start} — {analysis.scope.end}（UTC）。{analysis.status === 'candidates' ? '发现可追证的候选路径' : '证据不足，未生成路径'}。</p>
    <p>以下关系不证明恶意、完整攻击链或真实操作者；分数是启发式支持度。</p>
    <details><summary>候选入口 · {analysis.origins.length}</summary>
      <ul>{analysis.origins.map((origin) => <li key={origin.origin_id}>
        {origin.classification} · {origin.event_id.slice(0, 12)} · left_censored={String(origin.left_censored)}
        <p>{origin.explanation}</p><button disabled={busy} onClick={() => onEvidence(origin.event_id)}>查看入口证据</button>
      </li>)}</ul>
    </details>
    {analysis.origins.length ? <p>left_censored=true：缺少窗口之前完整采集的证明。</p> : null}
    <div className="form-row">{analysis.paths.map((candidate, i) => <button key={candidate.path_id}
      aria-pressed={selected === i} onClick={() => setSelected(i)}>候选路径 {i + 1}</button>)}</div>
    {path ? <article>
      <p>支持度 {path.support_level} · {path.score.toFixed(3)} · observed {path.observed_steps} / inferred {path.inferred_steps}</p>
      <p>链内证据覆盖 {Math.round(path.coverage * 100)}% · 链内缺跳 {path.missing_steps}；未观测的攻击步骤数量未知。</p>
      <ol>{path.edge_ids.map((id) => {
        const link = links.get(id)!;
        return <li key={id}><strong>{link.relation} · {link.kind}</strong>
          <p>{link.from_event_id.slice(0, 12)} → {link.to_event_id.slice(0, 12)} · {link.explanation}</p>
          <details><summary>匹配依据与分数分解</summary><pre>{JSON.stringify(link.components, null, 2)}</pre>
            <p>实体边：{link.entity_edge_ids.join(', ')}</p></details>
          <button disabled={busy} onClick={() => onEvidence(link.from_event_id)}>查看路径边证据</button>
          <button disabled={busy} onClick={() => onEvidence(link.to_event_id)}>查看目标证据</button>
        </li>;
      })}</ol>
    </article> : null}
    {analysis.breakpoints.length ? <details><summary>未证实的跳跃 / 断点 · {analysis.breakpoints.length}</summary>
      <ul>{analysis.breakpoints.map((gap, i) => <li key={i}>{gap.reason} · {gap.explanation}
        {(gap.evidence_refs ?? []).map((ref) => <button key={ref.event_id} disabled={busy} onClick={() => onEvidence(ref.event_id)}>查看断点上下文</button>)}
      </li>)}</ul></details> : null}
    <details><summary>其他路径与限制 · {analysis.alternatives.length} 条未选候选</summary>
      <ul>{analysis.alternatives.map((candidate) => <li key={candidate.path_id}>
        {candidate.path_id.slice(0, 12)} · {candidate.score.toFixed(3)} · 与首选差异事件 {(candidate.difference_event_ids ?? []).map((id) => id.slice(0, 8)).join(', ')}
      </li>)}</ul><ul>{analysis.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}</ul>
    </details>
    {analysis.truncated ? <p role="status">搜索已按 beam 20 / 6 跳 / 输出上限裁剪，未保证枚举全部解释。</p> : null}
  </section>;
}
