# D10本地部署候选运行说明

候选为本地原生部署，版本0.1.0.dev10、数据库head 0006_d9。默认模型disabled。本机独立目录验证不等于全新机器、Compose或非作者安装验收；完整发布状态以门禁与缺陷表为准。不得用生产库执行演示初始化或测试。

## 验证候选

在候选目录内，用已具备requirements-dev.lock锁定依赖的Python执行：

```powershell
python -m scripts.release_manifest verify --freeze freeze.json
```

SHA256SUMS覆盖冻结的源码、契约、规则、开发夹具与生产前端；freeze.json自身的摘要见version-manifest.json及外部验收记录。这是完整性与版本定位，不是发布签名。任一冻结文件新增/缺失/变更须创建新候选，不修改旧freeze来消除告警。

运行源码目录的未知可执行文件、根目录额外Python模块、未经允许的前端配置均拒绝核验。合法__pycache__等运行缓存不进入候选。夹具/测试数据和规则对象只从infra/release-inputs.json的明确路径与hash收录，未知输入或字节变化阻断新冻结；此清单不是人工真值复核。依赖检查逐项比较实际Python包及已安装Node包与锁文件，缺少必需包或版本漂移即失败；平台可选Node包的缺席会单列记录。

候选不含Python/Node运行时、wheel缓存、node_modules、数据库、原始运行归档、.env或模型密钥。若机器没有依赖，可在获准联网环境用Python3.12/3.13创建虚拟环境并安装锁文件；当前实跑平台为Windows/Python3.13，其他平台仍待验证：

```powershell
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements-dev.lock
```

生产前端已包含apps/web/dist，不需要Vite开发服务器。需要重新构建时，在源码apps/web中运行npm ci、npm run typegen、npm run build，并重新冻结；不要悄悄替换旧候选的dist。

## 启动一个新的本地演示工作区

下面命令在候选目录执行，运行数据放相邻独立目录。已有工作区继续使用其原配置和令牌，不清库、不重新init、不覆盖归档；migrate只能由迁移账号执行。

```powershell
$demoRuntime = Join-Path (Split-Path -Parent (Get-Location).Path) 'd10-runtime'
New-Item -ItemType Directory -Force -Path $demoRuntime | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $demoRuntime 'raw'),(Join-Path $demoRuntime 'staging') | Out-Null
$env:DATABASE_URL = 'sqlite:///' + (Join-Path $demoRuntime 'demo.db').Replace('\','/')
$env:RAW_STORE = Join-Path $demoRuntime 'raw'
$env:STAGING_STORE = Join-Path $demoRuntime 'staging'
$env:WEB_DIST = Join-Path (Get-Location).Path 'apps/web/dist'
$env:APP_BIND = '127.0.0.1'
$env:APP_PORT = '8000'
$env:APP_ENV = 'demo'
$env:MODEL_PROVIDER = 'disabled'
.venv/Scripts/python -m apps.api.manage migrate
.venv/Scripts/python -m apps.api.manage init-demo
.venv/Scripts/python -m scripts.preflight
.venv/Scripts/python -m apps.api.main
```

init-demo仅第一次显示高熵角色令牌；妥善保存在本地，不把终端输出存入验收日志或截图。另一个终端设置同样的DATABASE_URL、RAW_STORE、STAGING_STORE、APP_ENV和MODEL_PROVIDER，然后运行`.venv/Scripts/python -m apps.worker`。浏览器打开http://127.0.0.1:8000，输入admin角色令牌导入。停止时分别在API/worker终端Ctrl+C，保留运行数据。

SQLite路径用于小型本地工程演示。PostgreSQL沿用独立迁移/应用/只读角色；应用角色不能执行迁移、更新/删除报告复核。实际角色权限模板在infra/roles.sql，已有角色只按需要授权，不重复创建或改密钥。单实例API限流会随重启重置，不替代持久Agent预算。

预检只做只读连接、迁移head、raw可读/staging可写、生产静态文件存在与绑定检查；不写库、不初始化。ready仅指这些检查通过；worker空闲存活和真实模型连通性明确not_verified，不将它作为完整运行健康证明。API只提供根入口及/assets，不挂载工作目录；/api/v1仍按原权限运行。远程部署需要获准内网/TLS边界。

## 冻结与工程门禁（开发目录）

先生成契约并构建前端，再选择尚不存在的冻结文件和候选目录：

```powershell
.venv/Scripts/python -m scripts.export_contracts
# apps/web终端中：npm run typegen; npm run build
.venv/Scripts/python -m scripts.release_manifest freeze --freeze release/d10-freeze-01.json --id d10-candidate-01
.venv/Scripts/python -m scripts.release_manifest package --freeze release/d10-freeze-01.json --target release/d10-candidate-01
.venv/Scripts/python -m scripts.pg_sandbox start
./scripts/check-d10.ps1 -Freeze release/d10-freeze-01.json -Output artifacts/d10-check-01 -Postgres -Browser -Candidate release/d10-candidate-01
.venv/Scripts/python -m scripts.pg_sandbox stop
```

检查输出目录也必须是新目录；它保存逐命令实际退出码、时间、日志摘要、JUnit、冻结摘要和gate.json。没有-Postgres/-Browser时只验证子集，engineering_passed不会标true。数据库测试只使用既有隔离PG实例内新随机数据库；本机Docker引擎暂不可用，不自动修复系统配置。

pytest结束时JUnit摘要写入该检查记录，复验拒绝混入其他运行的XML。保留证据原路径；已完成检查可只读复验，无需重复运行测试：

```powershell
.venv/Scripts/python -m scripts.d10_gate --freeze release/d10-freeze-01.json --evidence artifacts/d10-check-01
.venv/Scripts/python -m scripts.d10_gate --freeze release/d10-freeze-01.json --evidence artifacts/d10-check-01 --require-release
```

第二条在当前P0缺口存在时实际应exit2。门禁也独立核验资料/双人标签状态，不接受仅把台账手填“完成”。这些记录不是第三方签名；不应在不可信或已被篡改的主机上把本地脚本当作安全证明。

`-RequireRelease`会在完整P0条件未满足时返回非零（Python底层exit2），即使工程检查全绿。不能把此值改成0掩盖缺口；docs/d10-acceptance.json、d10-defects.json列出未完成项。单独资料门禁仍为`python -m eval.freeze --require-ready`，当前应拒绝。

演示操作与诚实表述见d10-demo.md；范围与恢复限制见d10-limitations.md。本候选没有整库+raw备份恢复入口，不将文件复制称为通过TC-036。正式演示前需完成该缺陷，故障时保留原库/归档并停止写入，不重建或清空。
