# dev17 本地验收准备与交付

本轮只补充离线就绪检查、部署标签、已有运维 CLI 和验收材料，应用仍 0.1.0.dev17，迁移仍 0006_d9。API、Agent、六规则及前端行为沿用 p1-scale-candidate-01，不改变冻结配置。当前剩余五项 P1，完整 P0 发布仍被阻断。

新材料为 `release/p1-acceptance-candidate-01.zip` 和 `release/p1-acceptance-freeze-01.json`。外部清单含 ZIP 及逐文件摘要，只有完整性含义，不是签名或发布许可。旧 D10–D15/P1 候选与原始失败不覆盖。

## 已完成的本地准备

- 从固定 D14 wheel 清单核对 34 个依赖与当前锁文件一致，在本机全新 CPython 3.13.5 x64 venv 通过 `--no-index --require-hashes --only-binary=:all:` 安装；没有下载或变更依赖。
- 使用固定 dev17 候选模块与生产静态前端，真实回环 HTTP 启动 API/worker，导入及回放 24 条合成事件、生成 fallback 报告，重启后原令牌/原报告保持。
- 当前源码实际 PostgreSQL 16.16 停机备份/新目标恢复，28 表/32 事件/1 报告及新调查通过；新候选内已有备份模块另做 SQLite 28 表/24 事件/1 报告恢复，拒绝非空目标。
- 85 项针对就绪检查、模型协议故障/费用/引用、恢复/角色权限及正式数据门禁的回归通过。此数字不是此前 532 项全量回归的重复执行。

详见 `p1-acceptance-verification.md`。本机新 venv 不等于独立干净机器；HTTP/静态入口验证不等于本轮重新执行浏览器 UI 验收；本地协议桩不等于真实模型或物理断网。

## 候选的使用边界

候选包含原 dev17 应用、已构建的前端/知识目录，补入既有 `scripts.backup`、`backup_contracts`、`preflight`、`verify_environment`；不含 Python/OS、wheel、私有运行库、原始日志或 eval。新增离线就绪工具 `scripts.p1_acceptance` 位于开发工作区，因为它离线读取 eval，不能装入运行 Agent。

Windows 离线依赖可复用经核验的 D14 `wheels/` 目录和配套 `requirements-hashed.txt`，但必须先按 D14 清单校验，再检查当前锁文件；不要运行 D14 安装器覆盖此 dev17 应用。D14 应用本身是 dev12，不能拿其数据库备份冒充 dev17 同版恢复。34 个 wheel 仅适用 Windows CPython 3.13 x64。Docker/Linux 仍需独立取得并验证依赖与镜像。

只向全新目录解包。启动前在私有环境设置 `DATABASE_URL`、`RAW_STORE`、`STAGING_STORE`、`WEB_DIST=apps/web/dist`、回环 APP_BIND 和 `MODEL_PROVIDER=disabled`。用已核验 venv 的 Python，在候选根目录按已有运维入口执行：

```powershell
python -m apps.api.manage migrate
python -m apps.api.manage init-demo
python -m scripts.preflight
python -m apps.api.main
# 第二个终端使用相同私有环境：
python -m apps.worker
# 服务运行时：
python -m scripts.container_health
```

只对新库执行初始化。`init-demo` 的一次性令牌私存，不放入公开日志；`preflight` 不验证 worker 消费，须实际导入/调查/回放。HTTP 存活路由是 `/api/v1/health/live`；目录与迁移就绪通过 `scripts.container_health` CLI 检查，未提供 `/health/ready` 路由。PostgreSQL 使用迁移/应用/只读账号分工；Compose 具体步骤及本机限制见 `p1-compose.md`。

## 包内停机备份和新目标恢复

先阻止新作业并排空队列，停止 API 与 worker；备份工具取得数据库写排斥锁。备份目录必须受控且位于应用/公开包范围外。恢复前换成全新 raw/staging 目录与不存在的 SQLite 文件或已创建的空 PostgreSQL 库，保留原数据和原密钥。PG 工具路径可通过 `BACKUP_PG_BIN` 指向匹配版本。

```powershell
python -m scripts.backup create --folder C:/private/backup-new
python -m scripts.backup verify --folder C:/private/backup-new
# 私下切换 DATABASE_URL/RAW_STORE/STAGING_STORE 到全新目标后：
python -m scripts.backup restore --folder C:/private/backup-new
python -m scripts.preflight
```

路径是占位，须替换为获准私有目录。创建/验证/恢复共用同版可信候选；已有目标拒绝，失败目标保留，不执行 drop/clean/down -v。整库备份含 HMAC 和令牌摘要，不打入此候选或公开报告。恢复后核验旧令牌、旧报告与引用，再创建新调查。恢复仅到备份高水位，后续写入未合并不能声称零损失。

## 下一步

配置清单和真人步骤见 `p1-user-actions.md`，私有模型字段样例见 `p1-model-config.example.json`，空白人工记录见 `p1-human-acceptance.template.json`。目前没有真实模型配置，不会发起付费调用。准备好条件后按各 P1 的真实证据单独验收，不用自动测试或完整性 exit 0 自动销项。
