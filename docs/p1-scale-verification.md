# P1 全量检测与回放验证记录

应用 dev17，数据库 head 0006_d9，冻结迁移与六规则配置不变。只使用授权本地合成工程数据；模型关闭。旧 dev16 及 D15 包保留。

| 项目 | 实际结果 | 证据 |
|---|---|---|
| 规则回归与密集窗口 | 61 passed；12001 条连续周期及旧算法对照 | p1-scale-red.log、核心测试日志 |
| 新检测/回放集成 | 24 passed；10100 条六规则尾部证据、10001 实际导入、资源回滚 | p1-scale-core-02.log |
| 100000 六规则工程样本 | R01–R06 均命中尾部证据，与小范围参考结果相同；0.5047 秒 | p1-scale-100k-rules.json |
| 100000 密集周期连接 | 2.5353 秒；连续有界候选段包含全部成员 | p1-scale-100k-rules.json |
| 100000 真实 HTTP 导入和回放 | 源 succeeded；100000/100000；completed/complete；108.322 秒（包含最终检测） | p1-scale-replay-100k-02/summary.json |
| 回放成员与证据 | 精确成员集合相同，原 events 数量及 payload 摘要不变 | 同上，samples.jsonl |
| HTTP 查询 | 完成后交替事件/概览 100 次；P95 45.49ms | 同上 |
| 暂时性不可用 | 第二轮 1 次状态 GET 503，有界重试后成功；首轮直接失败记录保留 | p1-scale-replay-100k-01、02 |
| 真浏览器 | 2 passed / 14.8 秒；10001 回放、pending、完成、切换、恢复、取消、POST 同键重试、旧响应隔离、viewer 403 | p1-scale-browser-02/playwright.log 及 PNG |
| 前端 | 类型生成、生产构建、eslint 通过 | p1-scale-typegen-02.log、web-build-02.log、web-lint.log |
| 独立复核 | 1 Important 已修：Connection 流式选项污染 PostgreSQL 写入/savepoint；RED→GREEN | p1-scale-review-red.log、review-green.log |
| PostgreSQL 专项 | 9 passed / 21.38 秒；正常导入/回放及预算耗尽回滚 | p1-scale-postgres-focused.log |
| 修复连带验证 | 8 passed；状态 503 可记录重试，403/500/超时不吞错 | p1-scale-fix-tests.log |

证据路径均相对于 `artifacts/`。离线规则时间不包含输入准备、数据库读取、报告生成，也不是正式检测效果指标。回放实测速率约 923.17 EPS，计时包含最终检测等待；请求速率为 1000 EPS。没有把 33 planned 当成已采集样本，也没有把合成工程验证当真实 LLM、非作者验收或真人彩排。

最终全量 Python：**532 passed，1 warning，293.60秒**（artifacts/p1-scale-final-tests.xml/log）。PostgreSQL16.16：**135 passed，1 warning，168.99秒**（artifacts/p1-scale-postgres-full.log），使用新临时数据库，旧迁移与权限边界检查通过。警告为 Starlette TestClient 的 httpx 依赖弃用提示，未修改锁定依赖。Ruff 全库检查通过。

历史保全：dev16 的 376 个引用文件、此前 600 个历史引用及 23 个冻结迁移/规则定义摘要验证通过（p1-scale-history-preservation.json）。旧 p1-candidate-01.zip 的 SHA256 保持 8288c0c1bb76310d8d872ca51bea417024b3bf2d058e05850ec3f2c3bfd28d3f。

D10-004 本地工程缺口关闭，剩余五项 D10-001/002/003/005/006 仍 open，完整发布未就绪。外部条件复查：真实模型配置均缺、正式资料门禁 exit2、Docker 引擎 exit1（p1-scale-external-readiness.json）。没有远程提交、发布或人工签署。


## 新交付候选

新候选 `release/p1-scale-candidate-01.zip`，外部逐文件与 ZIP 摘要 `release/p1-scale-freeze-01.json`。本机使用候选目录实际模块及生产静态资源通过 ASGI 烟测：默认检测上限 100000，导入及回放 12/12，原 events 仍 12，知识目录核验通过（artifacts/p1-scale-candidate-smoke.json）。生产 JS 已包含回放 UI。该检查复用本机依赖，不是干净机器或容器验收。

候选不含 Python/Node 运行时、依赖安装包、eval、私有数据库、原始日志或失败浏览器 trace。开发验证脚本及测试仍在工作区；此包为本地工程候选，不替代 D15 非作者离线部署验收。构建索引见 artifacts/p1-scale-build-manifest.json。
