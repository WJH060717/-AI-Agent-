# P1 本地增量验证记录

本轮应用0.1.0.dev16，迁移0006_d9。新增知识、回放、批末发布优化、四服务候选配置；没有真实LLM、正式标签、人类签署或容器启动。七项中仅D10-009精选知识的工程缺口关闭，完整P0仍未就绪。

| 检查 | 实际结果 | 证据 |
|---|---|---|
| 知识官方对象与映射 | 6技术、6策略、24 analytics、10 data components | artifacts/p1-knowledge-source-check.json；knowledge/attack-18.1/source.json |
| 核心规则/Agent/回放正反回归 | 47 passed | artifacts/p1-core-tests.xml |
| 原子集合发布/幂等/租约恢复 | 11 passed；RED阶段501条触发1004次成员SQL | artifacts/p1-publication-tests.xml、p1-publication-red.log |
| 独立静态复核 | 无Critical；1 Important已修：pending空目录警告；4项回放复测通过 | artifacts/p1-review-red.log、p1-review-green.log |
| PostgreSQL16.16 | 130 passed，1条依赖弃用警告；新库/权限/旧迁移保留 | artifacts/p1-postgres-tests.log |
| Python全量首轮 | 507 passed，1 failed；旧D14故障桩Windows控制连接异常 | artifacts/p1-full-tests.xml |
| 故障桩修复及历史交付 | 28 passed；确定性RED与原D14源码均保留 | artifacts/p1-fault-red.log、p1-fault-final.xml |
| 前端 | 生成类型及生产构建通过；没有新增回放UI | artifacts/p1-typegen.log、p1-web-build.log |
| Compose | 四服务配置解析通过；引擎不可达，未构建/启动镜像 | artifacts/p1-compose-config.json、p1-docker-unavailable.log |
| 正式资料门禁 | exit2；33 planned、3 prepared、0 reviewed | artifacts/p1-formal-readiness.log、p1-external-readiness.json |

最终全量复测 **509 passed，1条依赖弃用警告，282.89秒**（artifacts/p1-final-tests.xml/log）；Ruff通过（p1-final-lint.log）。该警告为Starlette TestClient提示httpx依赖将弃用，未改动锁定依赖。PostgreSQL临时服务已停止。

故障桩修复后的首次连带D15检查曾因历史原件寻址缺口出现20 passed/8 errors（p1-fault-green.log）；补入与原摘要完全相同的历史脚本/测试副本后28 passed，未放宽旧清单或覆盖旧包。

## 回放实测

本机Windows、Intel i7-14650HX/24逻辑CPU、约16GiB内存，新建SQLite实验库，模型关闭；硬件清单采于测量后，不作为测量期间资源使用曲线。源为明确标记的合成记录，使用真实回环HTTP/API/worker。输入准备不计新增日志吞吐。

| 测量 | 实际可见事件 | 速率/耗时 | 100次查询P95 | 检测 |
|---|---:|---|---:|---|
| p1-replay-50eps-02 | 2000/2000 | 请求50 EPS；实际49.48 EPS / 40.42秒 | 58.17ms | complete（仅所选会话的规则扫描） |
| p1-replay-100k-02 | 100000/100000 | 请求1000 EPS；实际996.85 EPS / 100.32秒 | 77.22ms | partial / RULE_SCOPE_TOO_LARGE |

summary/protocol/samples 位于对应 artifacts 目录。原events payload摘要前后一致，另用数据库只读核对源/目标event ID集合摘要一致（artifacts/p1-replay-membership.json）。50EPS轮在集合发布优化前执行，100k-02为优化及pending警告修复后执行；每轮应用源码摘要保留，不能混称同一冻结运行。

失败均保留：50eps-01因测量器误用最多500条的生成器接口而在准备前失败，已加回归修复；100k-01在旧逐事件成员发布阶段发生HTTP503，未记为回放通过。既有D11三轮30分钟新摄取数据仍是历史结果，本轮未重复该协议。

## 外部与剩余工程限制

真实模型四个配置变量及.env均缺失，未调用/计费。33次独立采集与双人标签仍未完成；恢复/干净机器部署必须由非作者真实执行；Docker Linux引擎未运行；物理断网、真人8分钟彩排和问答仍无签署。>10000的完整规则检测与回放UI仍未完成。测试桩、自动测量、同机检查不替代这些验收。

本次仅本地工程候选；没有远程提交/发布。旧D15 ZIP与其所有索引原件继续保全，摘要不是人类签名。

## 候选封存

独立候选为 `release/p1-candidate-01.zip`，外部冻结为 `release/p1-freeze-01.json`。候选目录的实际模块及知识文件已通过本机ASGI烟测：导入12个合成事件，经新增API创建回放、worker完成12/12成员，原events仍12条；应用版本dev16，模型disabled（artifacts/p1-candidate-smoke.json）。这是同机已有依赖环境的检查，不是干净机器/真实容器部署。

ZIP完整文件集合、字节摘要、旧D15包摘要与历史原件保全由 artifacts/p1-final-integrity.json、history-preservation-p1-final.json 给出；源码/证据总索引见 artifacts/p1-build-manifest.json。候选包含源码、已构建前端、知识及许可、运行说明与本轮公开验证记录，不含解释器、wheel缓存、私有实验库/备份或真实令牌；完整历史D15档案保留在原交付路径。
