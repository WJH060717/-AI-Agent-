# D11 构建与验证记录

本记录只对本地工程构建负责，完整P0发布保持阻断。当前候选311个冻结文件，版本0.1.0.dev11、迁移0006_d9；无Git提交，使用内容哈希。D10候选284个文件复验仍为原摘要，未覆盖旧记录。D10外部清单44项中42项原文件未变；本轮更新的README与实施计划已按原SHA-256精确保存在artifacts/d10-source-docs-preserved，旧清单本身未改。

## 构建身份

- 候选：release/d11-candidate-03，ZIP为release/d11-candidate-03.zip（315个归档条目，614170字节）；01保留为查询未通过版本，02因手册Node版本误写被03替代（仅文档变化）。
- 冻结：release/d11-freeze-03.json，规范摘要7115c6dd3da425036ccdfe8504702aa246b0b9a73071329c19070751ed5d0f31。
- ZIP SHA-256：f085186c228b6dfb84445b41c6ecf13d2e445c25e89644e2ae83f5e11df01bcd。逐个冻结条目哈希已核对。
- 完整检查命令：`.venv/Scripts/python -m scripts.check_d11 --freeze release/d11-freeze-03.json --output artifacts/d11-check-03 --benchmark artifacts/d11-benchmark-full-03 --postgres --browser --candidate release/d11-candidate-03`。
- 首候选检查实际exit1：第二轮查询P95 2759.550ms超过2000ms，原候选和原始结果保留。最终工程检查exit0；严格发布门禁实际exit2。全部18项检查记录绑定同一冻结，原始输出哈希复验通过。

## 已完成的检查

最终冻结版本全量Python：388 passed；有1条Starlette TestClient的httpx弃用提示，没有更换锁定依赖。契约导出、Ruff、格式、pip check、依赖版本比对、TS生成/typecheck、ESLint、Vite构建与资料冻结检查全部exit0。PostgreSQL16.16实际120 passed，角色边界与D2→D9迁移保留检查通过；候选浏览器6项通过（D8两项、D9三项、D11一项）。最终冻结版工程四组12/12完成且复算一致，正式指标仍不可用。

正式入口实际运行返回`EVALUATION_FAILED:DATA_AND_LABELS_NOT_READY`、exit2，未创建输出目录。测试中用于版本完整性回归的33份临时元数据与144条假执行器预测只是单元测试，不是新采集资料或正式成绩。

## 修复与独立审查

- 超10000事件曾在最终检测时回滚发布；现在仅RULE_SCOPE_TOO_LARGE允许摄取partial发布，其余检测异常仍回滚。API/UI明确检测不足，原始事件可核验。
- 图超过500节点或1000边由整个构建失败改为确定性裁剪且传播truncated；裁剪前校验全部输入，无悬空边，不制造因果关系。
- 空数据、未查询、无规则命中与检测不完整分别显示；恶意HTML只作为文本显示。
- 离线评估使用实际核心管线，B0/B1模板、B2单摘要、B3受控Agent；最大一对一匹配、step投影去重、未知与零分母、按run聚合及可复算原始输出。
- 真实Agent子进程硬退出再等lease过期恢复，before/预算不重置，中断预留不退款，报告仅一份。
- 最终fresh审查无Critical，3项Important全部用失败反例修复：历史检测缺口被提高配置清除；压测继承环境导致不同负载；formal运行期间标签/冻结被替换。修复后固定有效参数、持久覆盖警告和原标签引用，并重验输入。额外反例防止正式test不足12、组不独立或场景错绑。

审查未确认模型哈希/缓存问题（报告保留配置哈希且分组显式live）；路径大于500事件拒绝是已有边界，线上快照最多250。真实模型/独立数据/完整回放和生产容量保持未验收范围。当前覆盖提示保守保留历史partial，不提供专用检测水位修复。

## 全部实验轮次保留

| 目录 | 实际结果与用途 |
|---|---|
| artifacts/d11-benchmark-smoke-01 | 中间版本1000事件smoke，不是30分钟验收 |
| artifacts/d11-benchmark-full-01 | 首轮90000接受、P95 958.399ms；缺完整有效配置记录且源码随后修复，已过期，不绑定最终候选 |
| artifacts/d11-benchmark-smoke-02 | 隔离配置修复后smoke通过，非全时长验收 |
| artifacts/d11-benchmark-full-02 | 90000条全接受、0重复/隔离/失败；排空4.836s，十万事件100查询全部200，但P95 2759.550ms超2000ms，真实失败并保留 |
| artifacts/d11-benchmark-full-03 | 最终版本180批90000/90000接受，原始计数无重复/隔离/失败；排空5.154s；100000事件100查询全部200，P95 83.091ms；180资源点，复算通过 |
| artifacts/d11-eval-01 | 12执行中4完成、8失败；暴露跨run上传幂等键冲突，原记录保留 |
| artifacts/d11-eval-02 | 修复幂等键后12完成；审查前版本，已被最终版本取代 |
| artifacts/d11-check-01/evaluation | 首候选12/12完成且复算一致；整体check-01因性能失败 |
| artifacts/d11-check-02 | 代码回归388通过；手册更正导致旧冻结拒绝继续，保留原日志 |
| artifacts/d11-check-03/evaluation | 最终候选12/12完成并复算一致，输入/代码版本未漂移，正式指标不可用 |
| artifacts/d11-browser-red、d11-browser-green | 空态缺失及定位器失败的真实迭代记录 |
| artifacts/d11-browser-green-02 | 修复后真实API空态/无命中/partial浏览器1项通过；最终候选浏览器另记录 |

所有工程资料沿用同一开发谱系，不能作为独立test或真实LLM对比。性能仅为本机SQLite新摄取/查询；检测超过上限partial，回放吞吐未实现。基准期间同机运行开发回归，资源记录只采集基准API/worker进程树，不是整机空闲容量评测。

## 持续缺口

40项映射目前34 implemented、5 partial、1 blocked。D10-007/008解决，7项P1保持open：真实LLM、33项独立资料与双人标签、整库/原始对象恢复、回放/大规模完整检测、干净机器/Compose/非作者启动、断网计时彩排、知识条目。严格发布门禁必须继续拒绝，不能把工程全绿当完整P0完成。

硬件实读：Intel Core i7-14650HX、16物理核/24逻辑处理器，系统报告物理内存16944848896字节（约15.78GiB）；Windows版本与Python版本见protocol，实际依赖见versions.log。采样时间与字段保存于artifacts/d11-hardware.json，不含机器名、账号或序列号。

查询回归：旧分页join在2000事件上取5条需要34400 SQLite VM steps；已沿既有时间索引分页并用成员EXISTS核scope与publication，回归要求小于8000 steps，8项相关分页与覆盖测试通过。概览不再通过事件列表校验scope，避免重复全量排序。

查询计划诊断另存artifacts/d11-query-plan.json：旧join使用成员publication索引再逐条取事件，出现USE TEMP B-TREE FOR ORDER BY；新查询沿ix_events_scope_time并逐条核成员。该EXPLAIN在实际表/索引定义的空内存库生成，只解释计划，不能冒充吞吐指标；实际2000事件VM回归与完整30分钟复测分别留证。

## 最终实测

新摄取持续1800.000003秒，90000条；十万事件查询P50 60.538ms、P95 83.091ms，进程树工作集峰值266.15MiB。检测仍partial，回放未测。

[资源曲线](../artifacts/d11-resource-curves.svg)从全部实际采样生成；CPU按相邻采样累计CPU差值/真实秒差计算，100%代表一个逻辑核，首点不伪造CPU值。

完整记录：[工程门禁](../artifacts/d11-check-03/gate.json)、[命令与文件摘要](../artifacts/d11-check-03/checks.json)、[基准原始记录](../artifacts/d11-benchmark-full-03/samples.jsonl)、[工程预测](../artifacts/d11-check-03/evaluation/predictions.jsonl)、[指标复算](../artifacts/d11-check-03/evaluation/metrics.json)、[汇总文件哈希](../artifacts/d11-build-manifest.json)。
