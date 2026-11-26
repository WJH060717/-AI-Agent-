import type { PipelineProgress } from '../../../packages/contracts/generated/api';

const stageLabels = {
  collect: '采集', normalize: '归一化', detect: '规则检测与标注',
  trace: '图构建与溯源', intelligence: '情报归因', present: '前端展示',
} as const;
const statusLabels = {
  available: '输入已备', running: '执行中', completed: '本范围已执行',
  partial: '部分完成', failed: '执行失败', cancelled: '已取消', not_run: '未执行',
} as const;

export function PipelineProgressView({ progress }: {
  progress: PipelineProgress | null | undefined;
}) {
  return <section className="panel" aria-label="六阶段执行状态">
    <h3>六阶段执行状态</h3>
    <p>仅反映当前冻结快照的执行情况，检测及溯源结果见对应结论。</p>
    {progress ? <ol>{progress.stages.map(stage => <li key={stage.stage}>
      <strong>{stageLabels[stage.stage]} · {statusLabels[stage.status]}</strong>
      <p>{stage.detail}</p>
      {stage.action_seqs?.length ? <p>知识工具行动 {stage.action_seqs.join('、')}</p> : null}
    </li>)}</ol> : <p>历史报告未记录六阶段执行状态。</p>}
  </section>;
}
