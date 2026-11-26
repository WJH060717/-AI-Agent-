# dev20 补证策略验证（2026-11-16）

用户范围：优化不同只读工具与种子外证据检索，**新增付费调查0**。应用源码dev20，数据库head仍0006_d9，六规则和依赖冻结不变。用户原服务未替换；现有dev19真实报告仍为历史结果。

## 行为变化

新 `packages/agent/retrieval.py` 从种子和已完成工具返回的已知事件生成建议。强进程实体用于进程上下文；资产及可补证缺口用于事件搜索/时间线。最多2种有用工具，跳过已完成的等价查询。建议不访问未检索快照内容，不读取eval/ground_truth，不替模型执行固定流程。

`runtime.py` 优先将实际检索的非种子事实放进上下文，续页指向原tool_results；`context_wire.py` 区分计划和草稿，避免重复索引、已支持判断详细项和工具正文耗尽预算，所有省略均有标记。草稿保留有界事实详细对象；scope、工具参数、游标、coverage、warnings、完整审计与before/after未改变。`model.py` 明确证据复核与新证据发现的区别，提示版本evidence_agent@2.2.0；新代码进入恢复/缓存身份。

## 本地实测

两组独立 SQLite/HTTP 协议桩实测均为 `completed / live / passed`，其中 **live 带 provenance.model_execution=protocol_test_stub，不是真实LLM**。父进程与模型传输子进程只允许回环连接，使用本地虚拟密钥，无付费API调用。

| 场景 | 实际工具序列 | 种子外证据 | 结果边界 |
|---|---|---|---|
| 原 S1 合成数据副本，37事件/34种子 | get_process_context → get_asset_timeline | 1条真实检索到的 /lab/helper 进程记录 | 种子before保持34，after增加该ID；原有3个判断均已supported，新增记录没有造成判断变化；不证明恶意用途 |
| D7 合成数据，11事件/9种子 | search_events → get_process_context | 2条正常进程线索 | 2个判断open→weakened，均context_only，变化绑定第一次工具行动seq=2；缺socket仍不可证明流量归属 |

两组均调用本地模型协议3次、真实领域只读工具2次；输入计量分别7216、7370，输出均300，原12000/3000上限保持。S1草稿保留1条新事实，D7保留2条。快照内容摘要未变，JSON/HTML脱敏导出成功。费用预留/用量费用均0，仅因本地协议桩；供应商账单字段null，不是正式成本成绩。

26项针对性测试已通过，覆盖以上行为、未知边界、原参数分页、跨run游标拒绝、恢复不重复更新、上下文身份和小预算拒绝。全量Python回归606 passed（495.88秒），仅1条Starlette/httpx依赖弃用警告；未为此改变锁定依赖。34个实际依赖版本均与锁文件匹配。源码/测试摘要在执行前后保持一致。独立只读复核未发现需修复的P0/P1/P2问题。

保留了早期预算/草稿事实不足的RED与失败日志，以及首轮本地运维脚本错误：将SecretStr数据库URL误作普通字符串，在创建调查前失败，原目录保留；修正后在全新02目录重做。旧context_load协议桩曾假设草稿必含auth；现因优先新进程事实，改为必须有已知事实，有auth时校验auth谓词，否则保持unknown，禁止凭进程记录构造认证结果。没有把测试空事实条件放宽。

## 工件与限制

- 专项测试（本地归档 `../artifacts/p1-retrieval-01/targeted-final.xml`）、源码/测试摘要（本地归档 `../artifacts/p1-retrieval-01/test-input-freeze-01.json`）、本地实测摘要（本地归档 `../artifacts/p1-retrieval-01/local-acceptance.json`）。
- S1结果（本地归档 `../artifacts/p1-retrieval-01/s1-02/summary.json`）与D7结果（本地归档 `../artifacts/p1-retrieval-01/d7-02/summary.json`），相邻目录保留动作、上下文、报告与脱敏导出。原数据仅位于受控本地测试目录，不写入用户运行库。
- 本地桩按建议作出协议响应，只证明建议、真实查询、审计、恢复与校验闭环，不证明DeepSeek实际会选择这些工具或稳定发现新证据。S1只新增1条已存在于快照的记录，不是采集了新日志。
- 包括D10-001在内的五项P1仍open；新增真实模型测试需以后单独授权。本轮未验证dev20在用户运行数据库上的部署，也未做浏览器人工验收。

最终独立候选：p1-retrieval-candidate-01（本地归档 `../release/p1-retrieval-candidate-01.zip`），外部冻结：p1-retrieval-freeze-01（本地归档 `../release/p1-retrieval-freeze-01.json`）。候选完整性不等于正式发布批准。全量日志与JUnit位于artifacts/p1-retrieval-01/full-tests-01.*。
