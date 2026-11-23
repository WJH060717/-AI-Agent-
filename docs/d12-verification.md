# D12 验证记录

实际归档时间：2026-11-15T09:08:54.498078+00:00。应用0.1.0.dev12，数据库0006_d9，无迁移/规则阈值更改。当前是本地工程构建完成，完整P0尚未验收。

## 行为与涉及文件

- scripts/backup.py、backup_contracts.py：停机/排空/写锁下整库与原始对象备份；同版空库/新目录恢复；28表逻辑摘要、高水位、全部事件及报告引用核验；不覆盖、删除或清空用户目标。私有dump不打包。
- eval/analysis_d12.py、runner.py、contracts.py：每个接受的调查失败也保留持久预算；B3观察Queue退避与重试，未达终态为censored；历史失败0ms为未测。按冻结清单复算耗时、token、费用口径、资源曲线、失败案例和截图。
- scripts/check_d12.py、d12_evidence.py及共享冻结/门禁：D12有19项实际检查，分析清单本身纳入冻结，拒绝空结果或删轮。API/前端仅更新D12标记；BACKUP_PG_BIN/TIMEOUT配置进入类型化入口和.env.example。

## 实际结果

运行命令：`.venv/Scripts/python -m scripts.check_d12 --freeze release/d12-freeze-04.json --output artifacts/d12-check-04 --candidate release/d12-candidate-04 --analysis-input eval/d12-inputs.json --postgres --browser`。

- 422 Python测试、123 PostgreSQL集成测试、6 浏览器测试通过；Ruff/format、依赖锁核验、契约导出、TypeScript/lint/build、数据清单均exit0。
- 独立PostgreSQL16.16恢复：28表、32事件、1旧报告核验；旧报告字节语义不变，新调查完成，原令牌与HMAC保持。实际备份1.330s、恢复1.674s，只是本机小型合成夹具；并发写被锁阻断，原目录与新目录下的非空库均拒绝。
- 当轮B0–B3工程12次执行均completed，协议桩、同源夹具；formal_metrics_available=false。
- 分析纳入5轮工程实验共60次执行，保留D11初轮8次失败；三轮30分钟性能记录共540个资源点，含第二轮P95未达目标。所有统计/图表/截图可按42文件输入清单重算。D12未重跑30分钟，不宣传历史83ms为D12性能。
- 工程门禁exit0，实际严格发布门禁exit2；34项implemented、5项partial、1项blocked，仍7个P1。TC-036工程子集完成，非作者验收未完成。
- 保留1条Starlette/httpx弃用提示；未为此更换锁定依赖。

## 复核与失败保留

一次fresh-context独立整体复核发现3项Important、无Critical，已按正反测试修复数据库目标歧义、失败预算漏记、空分析可通过。另纠正未知资源画零、实际PG非空分支覆盖与TC-038旧表述。所有失败日志保留，未抹去结果。

首轮全量预检405 passed/1 failed（旧health期待d11，已同步d12并验证）。候选01漏打包旧D11验收文档，独立目录回归真实失败；check-01主动中止并标superseded，候选02补入两文件后回归通过；其19项子进程检查均exit0，但最终门禁同名summary绑定错误，已增加3项路径冲突回归并修复。候选03仅测试import格式被候选04取代，未做验收。候选04为最终重新完整验收版本。没有覆盖候选01或旧D10/D11工件。

## 发布工件与限制

候选`release/d12-candidate-04.zip`：325冻结文件，329ZIP条目，650358字节。
冻结摘要 `9110dae9674ddedb75f08e538466df68ec9ff6e4b38eac5720f64fcd8ca11673`。
ZIP SHA256 `2535637744190a3a2106424d8892aeaeec132ff5f71b2087dafa0ef1e7f7fb6a`。

真实LLM、33次独立采集/双人标签、正式F1/误报率/账单、非作者恢复/部署、回放性能、精选知识、物理断网和8分钟彩排仍未验收。备份只支持可信本地停机环境、同应用与迁移版；角色ACL由运维者另配，不声称加密或跨用户隔离。
