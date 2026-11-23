# D1 实施记录

**Goal:** 建立可安装骨架与机器可校验的核心契约，为D2/D3最小闭环准备。
**Architecture:** API、worker、web分开入口；领域包不依赖HTTP；Pydantic为契约唯一来源，生成JSON Schema及TypeScript。
**Tech Stack:** Python、FastAPI、Pydantic v2；React/TypeScript/Vite。
**Spec:** PROJECT_SPEC.md；docs/02-data-contracts.md；docs/04-agent.md。

## 执行步骤

- [x] 1. 契约正反测试先失败，再实现事件/证据/图边/报告/工具/预算契约。
- [x] 2. 建API健康检查、worker预检、类型化配置；不提前提供无鉴权业务路由。
- [x] 3. 建三源合成夹具、真实字节哈希、24条规范事件与manifest核验入口。
- [x] 4. 从后端Schema生成前端类型，搭四页导航骨架，明确D1状态。
- [x] 5. 锁依赖，运行测试/lint/构建，记录环境与未通过项。

结果及外部条件缺项见d1-verification.md。以上复选框仅指本次软件实施范围，不表示模型连通、真实采集或团队批准已完成。

## 评审重点

时区缺失应拒绝；未知字段应拒绝；弱PID不能成为强实体；观察边和事实结论需证据；重复定位须稳定且跨dataset隔离；夹具不能携带真值进入运行事件。

## Rulings

- 当前用户明确要求开始实施D1，沿用已批准规划直接执行，不重开设计确认。
- 当前目录无Git，按项目规约不自动创建仓库或提交；直接复用工作目录。
- 本机只有Python 3.13.5已核实可用；支持范围设为3.12–3.13，当前实测3.13，3.12兼容性仍待验证。
- 没有模型凭据，不进行真实模型调用；通过严格ToolDecision契约准备接口，真实连通性标待完成。
