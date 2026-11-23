# 剩余七项 P1：本地可验证增量

依据：PROJECT_SPEC、docs/02–05、07、D12 缺陷清单；用户已授权继续七项 P1。旧 D15 发布结论与归档保持。此次不是完整 P0 验收。

基线：artifacts/p1-baseline.json 与 p1-baseline-source.zip 保存改动前 472 个源文件；无 Git 仓库，沿用当前工作区，不创建提交。应用增量 dev16，数据库仍 0006_d9，不改冻结迁移。

## 契约与计划

1. 精选知识：从固定 MITRE ATT&CK Enterprise 18.1 官方提交选取六规则对应技术，保留实际对象、版本、来源、摘要和许可证。构建时离线验证映射；运行时只有白名单摘要，最多五条，不读取网络/eval。知识引用独立于现场 evidence_refs，且必须来自同 run 的实际已完成工具返回。内容/开关纳入恢复配置及缓存身份。先写失败测试，再实现，再回归。
2. 事件回放：增加幂等创建与状态 API，绑定工作区、源 import session 固定 publication 水位；按稳定时间/ID 游标、速率和有界批量发布到新 replay session。不复制原事件、不改原始证据；进度与成员写入经 Queue.guard，同事务恢复，无重复发布。超过检测上限继续明确 partial，不能关闭完整大规模检测缺口。先测权限、幂等、取消、恢复、水位和模式，再接 worker/API、规模实测。
3. 部署及其余 P1：准备四服务配置，验证可本地检查的构建输入/Compose 配置；无引擎时不声称容器启动。检查真实模型、正式样本、独立恢复和人工彩排的实际依赖，逐项记录而不伪造签署/数据。
4. 最终相关回归、一次独立只读代码复核、源文件摘要和新验收记录。保留全部未满足关闭条件。

## 接口预检查

知识 → Agent：ToolResult 仍有界；DraftClaim 新增可缺省 knowledge_refs；历史报告兼容。工具知识不增加 retrieved evidence，不改规则种子 before。
回放 → Queue：新增 kind=replay；必须修正 investigation 专用关联逻辑；job payload 持久化进度，现有表足够。
回放 → 数据列表：只把 import session 作为 default，overview 返回真实 input_mode；旧默认路由行为兼容。
所有任务 → 发布：新源码不回写 D15 包；开发检查与完整发布门禁分开。

## 执行台账

- Task 1: complete；知识源离线核对 6 技术/6策略/24 analytics/10 data components；含同 run 引用及配置身份的核心回归 47 passed（artifacts/p1-core-tests.xml）。
- Task 2: complete for replay engineering；50 EPS/2000事件与修复后1000 EPS/100000事件实测通过，成员集合/原事件摘要一致。100k首次准备503失败保留；集合发布从1004 SQL失败到11项相关回归通过。>10000完整检测与回放UI明确未完成，D10-004仍开放。
- Task 3: complete for local checks；四服务配置解析/就绪检查测试通过。Docker Linux 引擎不可达，四个模型环境变量未配置；正式门禁exit2，33 planned/3 prepared/0 reviewed。无人工/独立环境签署，不把这些外部条件记作完成。
- Task 4: complete；最终全量509 passed，PostgreSQL130 passed，Ruff/前端构建通过。独立只读复核无Critical，1 Important已以RED→GREEN修复：pending回放空目录缺warning；无Minor。新P1候选模块烟测12/12回放通过，独立候选及历史原件按摘要封存；仅本地工程交付，六项P1继续开放。

Ruling：100k回放源准备暴露导入批末逐事件 SQL 的 P0 依赖，采用 INSERT SELECT/NOT EXISTS，保持工作区锁、完整批次原子发布与末尾 Queue.guard；未改冻结迁移/原始事件。
Ruling：本增量回放通过API/脚本操作；前端仍默认 import session，尚无回放选择器，不声称完成回放UI演示。

Ruling：全量首轮507 passed/1 failed，D14故障桩控制请求未读body就返回导致Windows连接中止。确定性RED验证响应发生在body完成前；修复有界消费body后，故障桩+历史D15交付28项回归通过。旧fault脚本/测试原件已按冻结摘要补入历史保全目录，不覆盖旧包。最终全量另写新日志。
