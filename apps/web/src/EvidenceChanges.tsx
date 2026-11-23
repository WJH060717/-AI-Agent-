import type { InvestigationComparison } from '../../../packages/contracts/generated/api';

const statusLabels = { open: '待补证', supported: '关系已有支持', weakened: '恶意解释被削弱' } as const;

export function EvidenceChanges({ analysis, busy, onEvidence }: {
  analysis: InvestigationComparison; busy: boolean; onEvidence: (id: string) => void;
}) {
  const before = new Map(analysis.before.hypotheses.map(h => [h.hypothesis_id, h]));
  const remaining = analysis.after.gaps.filter(g => g.status !== 'resolved');
  const changes = analysis.changes ?? [];
  return <section className="panel" role="region" aria-label="补证前后对比">
    <h3>缺口补证与分析变化</h3>
    <p>种子证据 {analysis.before.known_evidence_ids.length} 条 → 已核查证据 {analysis.after.known_evidence_ids.length} 条</p>
    <p>同一冻结快照内比较规则种子与工具检索后的已知证据，后续导入不会改写此记录。</p>
    <p>查询终止：{analysis.stop_reason}</p>
    <p>正常进程仅为替代解释线索，不证明流量归属或没有攻击。</p>
    {analysis.before.truncated || analysis.after.truncated ? <p role="status">判断数量达到上限，当前对比已显式截断，不能视作全部缺口都已处理。</p> : null}
    <div className="table-wrap"><table><thead><tr><th>规则与待检验解释</th><th>补证前</th><th>补证后</th><th>依据</th></tr></thead>
      <tbody>{analysis.after.hypotheses.map(h => <tr key={h.hypothesis_id}>
        <td><strong>{h.rule_id}</strong><p>{h.statement}</p><p>{h.observation}</p></td>
        <td>{statusLabels[before.get(h.hypothesis_id)?.status ?? 'open']}</td><td>{statusLabels[h.status]}</td>
        <td>{h.counterevidence_kind === 'context_only' ? <p>反向线索：仅同窗正常进程上下文</p> : null}
          {[...(h.supporting_refs ?? []), ...(h.contradicting_refs ?? [])].map(ref => <button key={ref.event_id} disabled={busy} onClick={() => onEvidence(ref.event_id)}>查看补证依据</button>)}
          <details><summary>适用限制</summary><ul>{(h.limitations ?? []).map(text => <li key={text}>{text}</li>)}</ul></details></td>
      </tr>)}</tbody></table></div>
    {analysis.after.hypotheses.length === 0 ? <p>当前规则没有可由该流程处理的假设；原始规则与路径事实仍可复核。</p> : null}
    <h4>有证据支持的变化 · {changes.length}</h4>
    {changes.length ? <ul>{changes.map(change => <li key={`${change.action_seq}:${change.hypothesis_id}`}>
      行动 {change.action_seq} · {statusLabels[change.before_status]} → {statusLabels[change.after_status]} · {change.reason}
    </li>)}</ul> : <p>本次没有得到能改变这些判断的新证据；空结果不表示相关活动没有发生。</p>}
    <details><summary>仍未解决的缺口 · {remaining.length}</summary><ul>{remaining.map(g => <li key={g.gap_id}>
      {g.code} · {g.status === 'unavailable' ? '当前能力无法补齐' : '仍待补证'} · {g.explanation}
    </li>)}</ul></details>
  </section>;
}
