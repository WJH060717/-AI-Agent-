# dev19 模型上下文表示压缩

工具Schema移除title注释，事实null对象属性省略并标未知；种子列表只保留可见事实中的种子ID，减少时标truncated。scope、工具参数、游标、coverage、warnings、预算原值保留。完整证据与原始状态不改写。

plan/draft提示分开，draft只解释有限谓词和格式，不给场景答案。提示evidence_agent@2.1.0，代码指纹绑定恢复和精确缓存。输入仍按UTF8请求字节保守预留，20秒、4次、12000输入/3000输出、调用前费用预留不变。

最终 p1-context-candidate-02/dev19（candidate-01为过时本地候选），迁移0006_d9/规则/依赖锁不变；保留dev18失败与dev17原部署。用户新增授权仅1次官方DeepSeek S1合成脱敏调查、USD0.10。先本地验证，后真实实测；模型结果、费用预留/usage估计/账单分别记录；不自动关闭D10-001。


候选02补充：MODEL_PLAN_FACT_LIMIT默认1、范围1–6，计划阶段优先新检索事实并考虑事件类型多样性；减少时facts_truncated=true。草稿阶段不受计划额外上限影响。省略模型不消费的内部run_id/hypothesis_id/gap_id，保留scope/incident_id/所有证据与资产进程引用/状态/缺证code。候选01和较高usage暴露的失败记录保留，不能拿其旧测试结果当修正版成绩。


本次新增一次授权已执行且用完，实际 completed/live/passed；完整结果、剩余边界与网页查看步骤见 验证记录（本地记录）。当前已恢复原dev17 disabled；不要重跑 trial.py 新开调查。
