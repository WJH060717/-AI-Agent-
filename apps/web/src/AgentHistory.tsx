import type { AgentActionPage, AgentTransitionPage, RunStatus } from '../../../packages/contracts/generated/api';

export function AgentHistory({ status, actions, transitions, busy, refresh, next, evidence }: {
  status: RunStatus | null; actions: AgentActionPage | null; transitions: AgentTransitionPage | null;
  busy: boolean; refresh: () => void; next: () => void; evidence: (id: string) => void;
}) {
  return <section className="panel"><h3>Agent 阶段与受控调用</h3>
    <p>阶段 {status?.phase ?? 'queued'} · 状态版本 {status?.state_version ?? 0} · 快照补证记录 {status?.retrieved_count ?? 0} 条</p>
    <p>工具预算 {status?.budget_used?.tool_calls ?? 0}/{status?.budget?.max_tool_calls ?? 6} · 模型预算 {status?.budget_used?.model_calls ?? 0}/{status?.budget?.max_model_calls ?? 4} · 缓存复用 {status?.cache_hits ?? 0}</p>
    <p>输入 token 计数 {status?.budget_used?.input_tokens ?? 0} · 输出 {status?.budget_used?.output_tokens ?? 0} · 模型等待预算 {((status?.budget_used?.model_wait_ms ?? 0) / 1000).toFixed(2)} 秒。失败与中断调用保守保留预留，计数不等同实测费用。</p>
    <p>费用预算 USD {((status?.budget_used?.cost_microusd ?? 0) / 1_000_000).toFixed(6)} / {((status?.budget?.max_cost_microusd ?? 0) / 1_000_000).toFixed(6)} · 已返回用量估算 USD {((status?.budget_used?.actual_cost_microusd ?? 0) / 1_000_000).toFixed(6)}；按配置定价，不等于提供商账单。</p>
    {status?.stop_reason ? <p role="status">停止原因：{status.stop_reason}</p> : null}
    {status?.query_stop_reason ? <p>补证循环终止：{status.query_stop_reason}</p> : null}
    <button disabled={busy} onClick={refresh}>刷新 Agent 记录</button>
    <p className="muted">调用详情仅 analyst/admin 可读。这里只展示行动摘要和校验结果，不记录模型隐式思维链。</p>
    {actions ? <div className="table-wrap"><table><thead><tr><th>序号 / 类型</th><th>工具或阶段</th><th>结果</th><th>补证与引用</th></tr></thead>
      <tbody>{actions.items.map((item) => <tr key={item.seq}><td>{item.seq} / {item.kind}</td><td>{item.name}</td>
        <td>{item.status}{item.error_code ? ` · ${item.error_code}` : ''}<details><summary>行动摘要</summary>
          <p>{item.reason_summary}</p><pre>{JSON.stringify(item.args_payload, null, 2)}</pre>
          <p>结果摘要哈希：{item.result_digest ?? '无完成结果'}</p></details></td>
        <td><p>补充证据 {item.new_evidence_count} 条</p>{(item.evidence_ids ?? []).map((id) => <button key={id} disabled={busy} onClick={() => evidence(id)}>查看工具证据</button>)}</td>
      </tr>)}</tbody></table></div> : <p>尚未加载调用记录。</p>}
    {actions?.next_cursor ? <button disabled={busy} onClick={next}>下一页 Agent 调用</button> : null}
    {transitions ? <details><summary>持久化状态转换 · {transitions.items.length}</summary>
      <ol>{transitions.items.map((item) => <li key={item.version}>v{item.version} · {item.phase} · {item.reason} · {item.occurred_at}</li>)}</ol>
      {transitions.next_cursor ? <p>转换记录仅显示当前页，完整列表可通过带游标的 transitions API 获取。</p> : null}
    </details> : null}
  </section>;
}
