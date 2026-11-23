# D11 运行与实验说明

版本0.1.0.dev11，数据库仍0006_d9。D10候选和工件不覆盖。Python3.13.5、Node22.17.0和锁定依赖沿用D10（实际运行版本见versions.log）；原生同源启动、角色令牌、安全预检见[d10-runbook.md](d10-runbook.md)。本候选README-install对应本页。

## 启动现有应用

在项目或候选目录使用现有`.venv`，新环境先按D10手册安装依赖。只对获准数据库运行迁移；不得替换既有密钥或清库。

```powershell
.venv/Scripts/python -m scripts.verify_environment
.venv/Scripts/python -m scripts.preflight
$env:WEB_DIST='apps/web/dist'
.venv/Scripts/python -m apps.api.main
# 第二个终端，同一配置
.venv/Scripts/python -m apps.worker
```

网页显示D11；模型默认disabled。新配置`DETECTION_EVENT_LIMIT=10000`只允许1–10000，不能用放宽上限消除检测限制。超过此范围的导入仍持久发布，批次/job为partial、error_code为RULE_SCOPE_TOO_LARGE；overview/事件组列表给覆盖警告，历史目录和已发布报告保留原版本。无告警不能被解释为全量无攻击。历史partial依据持久化批次错误保守保留，提高配置不能消除缺口；当前没有检测水位修复流程，后续完整重算也不会自动撤销历史partial提示。

## 真正的新摄取基准

每次必须选择不存在的结果目录。脚本创建自己的临时SQLite、回环API和worker，结束只关闭自身进程。输入是本地合成连接记录，不读取用户原始日志；所有模型关闭。资源采样当前支持Windows。子进程在临时目录启动，不读仓库.env，移除继承的全部Settings变量，再写入明确默认值与基准覆盖值；检测上限10000、分块500、lease60秒/heartbeat10秒/poll0.05秒等有效参数写入protocol并参与复验。

```powershell
.venv/Scripts/python -m scripts.benchmark_d11 --profile smoke --output artifacts/d11-smoke-new
.venv/Scripts/python -m scripts.benchmark_d11 --profile full --output artifacts/d11-full-new
.venv/Scripts/python -m scripts.d11_evidence benchmark --input artifacts/d11-full-new --output artifacts/d11-full-new-verified.json
```

full固定500条/10秒、180批、1800秒，共90000新记录；随后单独预载10000条到十万事件并发起100次串行HTTP查询（事件第一页/overview各半）。含上传失败、队列末态、原始/接受/重复/隔离计数、上传与查询延迟、180个CPU/内存采样；协议、运行源码哈希、样本和摘要均落盘。1800秒结束后排空不超过60秒、查询P95不超过2000ms为这一子协议目标；smoke不能替代。读取配额6000/min、写入1000/min已记录，不是默认配置容量结论。

结果字段`full_protocol_passed`只指新摄取+查询子协议。检测超过10000明确partial；回放尚未测量，TC-038保持partial。本机SQLite结果不能外推PG/生产/完整检测吞吐。运行期间不可修改运行时代码；版本漂移拒绝复验。

## 离线四组实验

```powershell
.venv/Scripts/python -m eval.validate_manifest --config eval/configs/d11-engineering.json
.venv/Scripts/python -m eval.run --config eval/configs/d11-engineering.json --output artifacts/d11-eval-new
.venv/Scripts/python -m eval.metrics --input artifacts/d11-eval-new --output artifacts/d11-eval-new-recomputed.json
.venv/Scripts/python -m scripts.d11_evidence evaluation --input artifacts/d11-eval-new --output artifacts/d11-eval-new-verified.json
```

工程配置为3个既有同源开发场景×B0/B1/B2/B3×1次，明确protocol_stub。B0规则基线，B1图+确定性模板，B2单次模型摘要且不补证/修复，B3完整受控Agent。复用实际导入/检测/图/Agent；预算上限相同，B2策略只减能力。每组实际模式、用量、失败、引用校验、before/after留在predictions.jsonl。耗时从该组调查开始计，不包括共享导入，不能称端到端延迟。此桩验证协议行为，不衡量真实模型质量或费用收益。

formal必须有新冻结资料清单、完整独立test集、双人复核、3次重复及获准configured模型。当前33项仍planned，正式入口在创建输出前返回DATA_AND_LABELS_NOT_READY（exit2）。不要修改旧freeze或把工程配置复制成正式成绩。formal通过预检后会先写一次性消费登记，即使失败也不自动重跑同批盲测。原始预测全部持久写完后才加载标签复算，运行组件不导入eval。预检固定清单、复核摘要及标签引用；结束时重验同一版本，运行中换标签或连同清单一起重冻均拒绝，保留预测及failure.json。正式test必须12个独立组且各S1/S2/S3四个。

## 新候选及门禁

先完成前端构建、类型生成和必要修复，再新建冻结。下面名称均须未存在；本项目没有Git，采用内容哈希记录源码身份。

```powershell
.venv/Scripts/python -m scripts.release_manifest freeze --freeze release/d11-freeze-new.json --id d11-candidate-new
.venv/Scripts/python -m scripts.release_manifest package --freeze release/d11-freeze-new.json --target release/d11-candidate-new
# PostgreSQL沙箱已由现有工具配置；此处只启动，不初始化/重建
.venv/Scripts/python -m scripts.pg_sandbox start
./scripts/check-d11.ps1 -Freeze release/d11-freeze-new.json -Output artifacts/d11-check-new -Benchmark artifacts/d11-full-new -Postgres -Browser -Candidate release/d11-candidate-new
.venv/Scripts/python -m scripts.d11_gate --freeze release/d11-freeze-new.json --evidence artifacts/d11-check-new --require-release
.venv/Scripts/python -m scripts.pg_sandbox stop
```

工程检查要求完整Python/PG/前端/三组浏览器、四组实验重跑与指标复算、全时长基准证据核验；省略必要检查不能exit0。每项命令、时间、退出码、日志、JUnit/实验原文件哈希绑定同一冻结。严格门禁在P1缺口仍存在时exit2，不能把工程通过当完整P0就绪。基准复验不再重复30分钟，但要求当前运行时代码哈希与原实测一致。若指定已启动但尚未完成的full目录，检查入口最多等待1900秒；不存在protocol或超时仍缺summary则失败，不自动伪造或启动替代运行。

当前结果见[d11-verification.md](d11-verification.md)，限制见[d11-limitations.md](d11-limitations.md)，40项映射见[d11-acceptance.json](d11-acceptance.json)。

D11性能修复补充：事件分页沿既有ix_events_scope_time索引取有序候选，并用EXISTS核对同工作区/session成员及固定publication水位；概览直接校验scope并计数，不再调用事件分页。未修改schema或冻结迁移。第二轮100k查询P95 2759.550ms未达目标，原结果保留；修复后新建第三轮，门槛仍2000ms。
