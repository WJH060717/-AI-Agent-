# D3实施计划

目标：持续消费、60秒租约/10秒心跳、最多3次尝试、分段检查点、取消和旧worker写入隔离；R01→事件→冻结快照→观测图→确定性模板报告→原始引用。
依据：PROJECT_SPEC.md与docs/01、03、05、06。沿用已批准计划直接实施，使用executing-plans、TDD、React best practices技能。

- [x] 先测租约过期接管、旧owner拒写、检查点恢复、退避/上限、取消与持续循环。
- [x] 新增0002迁移，保持schema_v1冻结；500行分段，事件先持久化、完成后才发布到session。
- [x] R01端口扫描与内部目标扫描纯函数及正反例；不把扫描候选等同攻击事实。
- [x] 导入完成后幂等产生finding/incident；调查创建时固定事件ID快照，调查job生成观测图及模板报告。
- [x] API任务状态/取消、incident/run/graph/report、脱敏证据片段；所有路由继承工作区和角色边界。
- [x] 前端事件列表、创建调查、图/报告、逐条引用；明确deterministic_fallback。
- [x] SQLite与真实PostgreSQL、进程终止恢复、构建检查、独立审查和运行说明。

验收证据与未覆盖项见d3-verification.md；孤立对象只做安全清单，不自动删除。Docker集成未执行，不列为已验证能力。

Ruling：首条规则选R01，因为D3已有网络连接遥测，主机auth解析仍属D4。R01配置采用JSON（YAML兼容子集），不为单规则增加解析依赖。
Ruling：D3单worker串行消费import/investigation两类作业，不做双槽并发；多worker仍用数据库领取与fencing保证不重复发布。
Ruling：D3快照先限250事件（拒绝超限，不静默裁剪）；图为连接观测图，不声明已实现攻击路径或AI推理。
