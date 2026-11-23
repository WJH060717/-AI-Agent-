# dev17 五项 P1 本地验收记录

执行日期 2026-11-16。基线应用 0.1.0.dev17 / 0006_d9，固定原 p1-scale-candidate-01，用户选择“尚未配置，先完成本地验收准备”。API/Agent/规则/前端运行源码不变；修改部署镜像标签并补充离线工具、既有备份 CLI 与材料。本轮没有真实 LLM 调用、正式检测成绩、人工签署、远程提交或发布。

| 实际检查 | 结果与证据（相对工作区） | 证明范围 |
|---|---|---|
| 新工具正反测试 | 初次模块缺失 RED；初次 GREEN 17 项；最终加入 Compose 版本校验后纳入下述 85 项。`artifacts/p1-acceptance-preflight-red.log`、`p1-acceptance-preflight-green.log` | 私有输入缺失/异常/重复字段/未知字段/过大文件、继承环境隔离、输出不泄密、不覆盖及不自动放行 |
| 针对性回归 | **85 passed，125.10 秒**；`artifacts/p1-acceptance-tests.xml` / `.log` | 模型协议、失败预算、取消/恢复、引用、备份权限、正式数据门禁、部署角色；本机新 venv 执行 |
| 离线依赖 | **34 个 wheel** 摘要及版本与锁文件匹配，安装成功；`p1-acceptance-native-inputs.json`、`p1-acceptance-offline-install.log` | 本机 Windows CPython3.13.5 x64 新 venv，no-index/hash 校验；不代表新机器或 Linux 镜像 |
| 实际 HTTP 与重启 | **24 导入 + 24 回放**，complete，成员集合一致；报告 deterministic_fallback，重启后原令牌和原报告保持；`p1-acceptance-native-http-02/summary.json` | 固定候选模块、生产静态资源、实际 API/worker，本轮未重新测浏览器交互 |
| PostgreSQL16.16 实际恢复 | **28 表 / 32 事件 / 1 报告**；备份 1.304010 秒、恢复 1.644509 秒；旧报告/令牌/HMAC保持，新调查完成，并发写入受阻、既有目标拒绝；`p1-acceptance-recovery-01/recovery.json` | 当前 dev17 源码执行既有 D12 恢复程序；JSON 的 d12-recovery 是格式版本，非历史结果复用 |
| 新候选包内恢复 | **28 表 / 24 事件 / 1 报告**；SQLite 备份 0.215407 秒、恢复 0.129433 秒；preflight ready，非空目标拒绝；`p1-acceptance-packaged-recovery.json` | 新候选实际导入的 backup/preflight 模块；worker 存活在此步仍 not_verified，HTTP 运行单独记录 |
| 就绪报告 | `p1-acceptance-readiness-final.json`，实际 exit 2；缺模型配置、Compose 配置有效而引擎不可达；33 planned / 3 prepared / 0 reviewed | 字段齐备与外部验收分开，五项继续 open，签署为空 |

最终 `ruff check .` exit 0；包内 `python -m scripts.backup verify` 和 `python -m scripts.preflight` CLI 均 exit 0（`p1-acceptance-packaged-cli.json/.log`）。自启 API/worker 与 PostgreSQL 沙箱已停止，私有源库/备份/失败目标保留。候选逐文件摘要、测试绑定与历史保全分别在 `p1-acceptance-freeze-01.json`、`p1-acceptance-build-manifest.json`、`p1-acceptance-history-preservation.json`，最终复核记录在 `p1-acceptance-final-integrity.json`。

针对性回归命令（开发工作区）：

```powershell
.tools/p1-acceptance-native-01/venv/Scripts/python -m pytest tests/unit/test_p1_acceptance.py tests/unit/test_p1_deployment.py tests/unit/test_fault_d14.py tests/integration/test_d6_agent.py tests/integration/test_d8_agent.py tests/contract/test_d6_model.py tests/contract/test_d9_cost.py tests/contract/test_d12_backup.py tests/contract/test_d8_evaluation.py tests/integration/test_d10_deployment.py --junitxml=artifacts/p1-acceptance-tests.xml -q
```

这是已执行记录，不应复用上述输出路径覆盖原件。测试前冻结 `p1-acceptance-test-freeze.json` 的 224 个输入；SHA-256 为 `a3e07dd5c16d5aeda75fd7c7000abb731487866816cec79ffc88e5c5c898d73c`。最终构建索引把它与 JUnit/日志绑定并复核未漂移。当前无 Git 仓库，提交标识为空；使用字节基线、逐文件摘要和独立候选号追踪。新代码初次 lint 输出也保留，不抹除失败过程。

首次 HTTP 验收脚本错误使用未实现的 `/health/ready`，因此返回 404，原 `p1-acceptance-native-http-01` 与失败日志保留。只修改验收脚本，第二轮在全新 state-02 使用 `/health/live` 和已实现的容器健康 CLI 后成功；没有修改应用路由或原始失败。实测脚本另存 `p1-acceptance-native-http-script-02.py`，仅为本轮固定目录的取证代码，不是可在任意机器直接复跑的安装器。

旧 100000 条回放、532 Python、135 PostgreSQL、2 浏览器数据属于 p1-scale 历史验证，没有宣称本轮重测。当前单次备份/恢复秒数是合成小数据工程实测，不是大库性能承诺。

本轮 Docker CLI 可解析配置，但 desktop-linux 引擎不可达；没有执行镜像构建、容器启动或系统安装。34 wheel 的离线安装与协议故障测试不证明物理断网。所有真实模型/账单、独立输入/双人标签、非作者恢复/干净机器启动、真人两轮 8 分钟彩排继续留在五项 P1。详细准备条件见 `p1-user-actions.md`。
