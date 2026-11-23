# D2运行说明

当前支持：PostgreSQL/Alembic迁移、工作区角色令牌、dataset/default session、上传暂存、worker单次封存解析、Zeek conn与Suricata EVE alert、隔离计数、幂等、带签名游标的规范事件查询、连接观测图与受限只读工具骨架、前端实际导入交互。

当前不是攻击检测闭环：没有主机日志解析、告警关联、攻击路径搜索、LLM调用或报告。安全事件队列仍为空态，导入的规范事件在概览页显示。

## 1. 安装和数据库

根目录：`.venv/Scripts/python -m pip install -r requirements-dev.lock`。前端在apps/web执行`npm ci`。不要重新覆盖已有.env，按.env.example补充实际DATABASE_URL。

PostgreSQL目标16；Docker可用时，先在当前终端安全设置POSTGRES_PASSWORD，然后运行：

```powershell
docker compose -f infra/compose.postgres.yaml up -d
```

Compose模板未在本机执行（未安装Docker），数据库行为实际用官方便携PostgreSQL16.16验证；镜像摘要尚待容器环境锁定。

迁移使用owner连接，API使用trace_app连接；生产/共享环境不得用超级用户启动API。将对应DSN临时配置到当前终端DATABASE_URL（密码须正确URL编码），然后：

```powershell
.venv/Scripts/python -m apps.api.manage migrate
.venv/Scripts/python -m apps.api.manage init-demo
```

init-demo首次打印三角色令牌，数据库只存SHA-256摘要，请自行安全保存。再次执行返回原demo工作区、不重建令牌、不回显旧令牌。不要把令牌写进Git或截图。迁移只升级，不提供破坏性downgrade。

在psql中以owner执行infra/roles.sql一次，使用`\password trace_app`和`\password trace_reader`交互设置密码，再明确启用相应角色LOGIN。模板角色初始NOLOGIN，不能误用空密码。API使用trace_app；trace_reader预留只读查询连接。当前ReadOnlyTools由服务端注入仓库，不持有模型可见凭据；D6再完成执行器与专属连接集成。每次新迁移增加表后需复核grant。

## 2. 启动与操作

配置API/worker的DATABASE_URL为应用账号；确认raw_store/staging_store为预期本地目录。启动：

```powershell
.venv/Scripts/python -m apps.api.main
```

另一个终端在apps/web执行`npm run dev`。在概览页输入admin令牌（只存内存），连接、创建合成数据集，上传data/fixtures/d1/zeek.jsonl或suricata.jsonl。不要上传预制events.jsonl到来源解析器；该文件是D1规范事件夹具。

上传返回202与batch_id/job_id，状态queued。另一个配置相同DSN/目录的终端执行：

```powershell
.venv/Scripts/python -m apps.worker --once
```

一次处理一个queued任务；有多个任务则再次执行。页面每2秒查询当前批次，显示新增/重复/隔离计数；随后点击“刷新事件”。业务接口都要求Bearer认证，viewer可读规范事件、不可上传或看批次管理详情，analyst可看批次。

## 3. D2行为边界

- API只写staging；worker核验上传哈希，复制到随机.partial对象，fsync、复核后rename并事务发布封存清单。用户文件名不用作路径。原始对象只创建、不由接口覆盖，完整性校验失败即停止。
- 每个非空输入文件有一批次。逐行accepted+duplicate+quarantined可核对；空行也作为非法记录计数，不悄悄忽略。JSONL仅支持UTF-8；EVE非alert事件目前记unsupported隔离，不能宣称已经解析全部EVE类型。
- 单文件100MB上限；实际HTTP体也限制为文件上限+64KiB表单余量，无Content-Length同样计数。规范事件不包含源文件任意扩展字段；原始字节仍完整封存。
- D2导入只接受timezone=UTC作为归一化约定，Zeek使用epoch，EVE原始时间必须带offset并保留原时区。offset_ms=0是未额外校正，uncertainty=1000ms只是初始假设，clock_uncertain显式标记。
- 默认instance/observation_domain取dataset ID，适用于同一实验数据集。真实多观测域、NAT、时钟校准和传感器配置还需D4扩展，不能据此做跨域强关联。
- 同一幂等键24小时内同内容返回原结果，不同内容409；重新传相同对象的新批次按事件ID记duplicate。D2串行化工作区变更以处理并发幂等，后续可优化粒度。
- worker只支持单消费者一次执行。进程被杀可能留running任务或孤立.partial对象；D3补租约、游标、恢复与安全清理，当前不要用手工改库冒充恢复测试。
- D2每个导入在单事务中发布事件；D3再增加500条分段与检查点。旧报告/快照尚未实现，不能对当前查询宣称具有冻结调查快照。
- 只读工具骨架依赖后端注入的scope与允许事件集合，最多100条；发现还有分页时拒绝，防止静默漏证。还没有LLM调度、完整六工具参数Schema或模型预算执行器。
- 图服务仅给网络端点画communicated_with观测边，每条带原始引用；不宣称因果关系或攻击意图。不开放HTTP调查图路由。
- 未实现HTTP原始证据下载/脱敏抽屉；当前事件返回可验证引用，完整性核验在服务与测试中执行，D3接界面追查。

## 4. 自动复验

```powershell
./scripts/check-d2.ps1
```

包含全套Python测试、Ruff、依赖检查、Schema/OpenAPI导出、前端typegen/typecheck/lint/build。SQLite是隔离测试适配，不能替代PostgreSQL专属验证。

本机已准备官方便携运行文件于忽略目录.tools；PostgreSQL Windows引导程序在中文路径下失败，因此隔离测试集群位于ASCII临时路径，未注册系统服务。来源：[PostgreSQL Windows官方入口](https://www.postgresql.org/download/windows/)、[EDB官方二进制页](https://productsdl.enterprisedb.com/download-postgresql-binaries)。新机器可使用Docker，或自行准备官方zip；本工具不自动重新下载。

```powershell
.venv/Scripts/python -m scripts.pg_sandbox init  # 仅首次；已初始化不重复覆盖
.venv/Scripts/python -m scripts.pg_sandbox start
.venv/Scripts/python -m scripts.test_postgres
.venv/Scripts/python -m scripts.pg_sandbox stop
```

test_postgres每次创建新的随机命名测试库及临时app/reader角色，不连接用户业务库；用owner迁移、受限app账号跑集成测试，独立检查读写权限。测试不自动删库，数据仅位于可丢弃集群。最终停止实例，不后台占用端口。
