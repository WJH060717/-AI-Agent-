# 六阶段流程改造实施计划

> 使用 executing-plans 在当前工作区逐项实施。用户已授权执行设计。

目标为完成可在现有材料上验证的 M2、M3 路径可见性、M4 补证展示，并复验 M1 既有多源链路。
规约见 ../specs/2026-11-25-tracex-agent-pipeline-design.md。

## 全局约束

预算、权限、快照边界沿用设计。规则和迁移冻结。真实数据不足的逐类验收保留阻塞。
当前目录无 Git 元数据，直接编辑用户提供的工作区，变更前保存将改动文件的副本。
M5 本地 IOC 为规约中的可选阶段，本轮复用已冻结 ATT&CK 目录。

## 任务与验收

- [x] 查询契约和建议。修改 contracts/agent.py、agent/retrieval.py、model.py；增加抓包类型，建议带目标和预期证据，续页保持参数。以 contract/test_pipeline_retrieval.py 验证已知锚点、游标、非法输入和包摘要。
- [x] 路径只使用已知集合。修改 executor.py、runtime.py，服务端注入 K，路径工具不增加事件；缓存绑定 K。integration/test_pipeline_paths.py 验证隐藏中间事件、检索后路径、跨范围、重复调用。
- [x] 前端补证增益。EvidenceChanges.tsx 展示新增集合、逐条引用及无新增状态；沿用报告持久字段和导出。
- [x] 契约及历史回归。生成现有 schema/TS，更新提示与应用版本及四模块契约，运行相关 Agent、图、摄取和报告回归、前端类型/lint/build。
- [x] 独立审阅与最终记录。审查边界、缓存、未知、预算及历史兼容，修复后复验，记录未验证材料与阶段状态。

## 审查重点

未见图节点不得泄露给模型；路径缓存随 K 改变；旧游标不复活已完成分页；抓包不能证明连接；上下文增加不得突破预算。

实际阶段限制见 ../../pipeline-dev42-verification.md。
