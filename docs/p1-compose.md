# P1 四服务候选配置

GitHub 源码快照的 Compose 镜像标签对应 dev41，配置可解析。以下部署记录保留当时的 dev17 验收范围。

2026-11-16：当前 Compose 镜像名已从 dev16 校正为 dev17，与 pyproject.toml 一致；旧包未改，不自动重标旧镜像或迁移既有卷。容器方面仅完成本地配置解析/源码构建输入检查，Docker Linux 引擎不可达，镜像尚未构建或启动；不得据此关闭 D10-005。使用独立 Compose project 名称，不与旧部署共用数据卷；禁止执行 down -v。本增量不发布公网端口，默认只监听 127.0.0.1:8080。

`infra/compose.p1.yaml` 提供 db/api/worker/web：DB 不映射主机端口；API raw 只读、staging 可写；worker 可写 raw/staging；应用以 UID 10001 运行；web 以 UID 101 运行。模型关闭且后端网络无外网。构建上下文白名单排除 .env、原始日志、备份和 eval。依赖使用现有 Python/npm 锁，基础镜像按版本标签固定，尚未取得本机镜像 digest；不能称为完整离线镜像包。

运行前需要本机可用 Docker Linux 引擎，并在私有文件保存新的 DB owner 密码。设置 `TRACE_OWNER_PASSWORD_FILE` 指向它；设置 `TRACE_DATABASE_URL` 为 `postgresql+psycopg://trace_app:<经过URL编码的密码>@db:5432/trace`。不要使用 owner URL 作为长期应用凭据，不要把实际 URL/密码放入文档或公开日志。

在仓库根目录，以下命令仅为已实现配置的操作步骤，容器执行本轮尚未验证：

```powershell
docker compose -f infra/compose.p1.yaml config --quiet
docker compose -f infra/compose.p1.yaml build
docker compose -f infra/compose.p1.yaml up -d db
# 私下把 DATABASE_URL 设置为 trace_owner 的 URL，再运行一次性迁移：
docker compose -f infra/compose.p1.yaml run --rm --no-deps -e DATABASE_URL api python -m apps.api.manage migrate
# 在 DB 管理终端执行 infra/roles.sql（仅新库一次），然后用 \password 设置
# trace_app、trace_reader 的独立密码，显式 ALTER ROLE ... LOGIN。
# 清除临时 owner DATABASE_URL，长期配置继续使用 TRACE_DATABASE_URL。
docker compose -f infra/compose.p1.yaml run --rm --no-deps api python -m apps.api.manage init-demo
# 上一步只展示一次角色令牌；妥善私存，不写入公开服务日志。
docker compose -f infra/compose.p1.yaml up -d api worker web
docker compose -f infra/compose.p1.yaml ps
```

API readiness 检查当前迁移 head、归档目录可读、暂存目录可写和 HTTP 存活。worker 的实际消费/租约须通过导入和调查检查，不能仅依据容器进程存活判定成功。验证角色权限、重启持久化、恢复、模型 disabled、知识可读和回放后，由非作者在干净机器签署。既有 D14 Windows wheel 包不作为 Linux 镜像依赖缓存。

本轮同机全新 venv 的 34 个依赖离线安装、实际 HTTP/worker/24 条导入回放及重启已通过，见 p1-acceptance-verification.md；这些原生进程证据不替代此 Compose 的镜像/容器验证。原生候选的备份与预检工具已补入 p1-acceptance-candidate-01。
