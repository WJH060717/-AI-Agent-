import type { Report, RunStatus } from '../../../packages/contracts/generated/api';

export function MissingEvidence({ report, status, busy, onEvidence }: {
  report: Report; status: RunStatus | null; busy: boolean; onEvidence: (id: string) => void;
}) {
  const validation = report.claim_validation;
  const gaps = (report.investigation_analysis?.after.gaps ?? []).filter(gap => gap.status !== 'resolved');
  const unverifiable = report.validation !== 'passed';
  const incomplete = status?.state === 'partial' || Boolean(validation?.stop_reason);
  return <section className="panel" aria-label="缺证与校验">
    <h3>缺证与校验</h3>
    {unverifiable ? <p role="alert" className="error">当前原始证据不可验证 · 历史结论仅供参考</p>
      : <p role="status">{incomplete ? '调查未完成 · 保留已验证事实' : '有限事实校验完成 · 仍有未知项'}</p>}
    <p className="muted">校验通过不代表完整攻击链已获证实。</p>
    {unverifiable ? <p>下方是生成时的校验记录与缺口，不能作为本次读取的完整性证明。请核查原始对象是否缺失或损坏；历史报告未改写。</p>
      : null}
    <details><summary>校验详情</summary>
    {validation ? <>
      <p>{unverifiable ? '生成时的校验记录' : '有限事实校验'}：{validation.validated_observed} 条观测事实 · {validation.unknown_claims} 条未知 · 修复 {validation.repair_attempts}/1 次</p>
      {validation.stop_reason ? <p>停止原因：{validation.stop_reason}</p> : null}
      {(validation.rejected_codes ?? []).length ? <details open><summary>被拒绝的模型输出</summary>
        <ul>{validation.rejected_codes!.map((code, index) => <li key={`${index}-${code}`}>{code}</li>)}</ul>
        <p>上述输出未作为事实发布；修复仍计入累计模型预算。</p>
      </details> : <p>未记录模型事实拒绝；不表示所有活动均已核实。</p>}
    </> : <p>历史报告没有逐次校验摘要，未对其重新推理。</p>}
    </details>
    {gaps.length ? <ul>{gaps.map(gap => <li key={gap.gap_id}>
      <strong>{gap.code}</strong> · {gap.status === 'unavailable' ? '当前证据不可补足' : '待补证'}
      <p>{gap.explanation}</p>
      <p>{gap.actionable ? '可在当前快照中核查；空结果不证明活动未发生。' : '需补充授权数据或人工核查。'}</p>
      {(gap.evidence_refs ?? []).map(ref => <button key={ref.event_id} disabled={busy || unverifiable} onClick={() => onEvidence(ref.event_id)}>查看缺口上下文</button>)}
    </li>)}</ul> : null}
    <details><summary>报告未知项与建议</summary>
      <ul>{(report.gaps ?? []).map((text, index) => <li key={index}>{text}</li>)}</ul>
      <ul>{(report.recommendations ?? []).map((text, index) => <li key={index}>{text}</li>)}</ul>
    </details>
  </section>;
}
