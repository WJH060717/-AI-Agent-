# D12 运行与复算手册

应用 `0.1.0.dev12`，数据库仍 `0006_d9`。D12 只增加本地运维恢复、离线实验分析和工程验证，不增加 Agent 权限。Python 使用 3.12/3.13（本机 .venv 为 3.13.5）；Node 本机 22.17.0，PostgreSQL 16.16。安装/初始化入口继续见 D10 手册；本机验证不能代替 D13 非作者干净环境验收。

## 完整备份

先暂停新请求，停止 API 和 worker，在服务关闭前让队列排空。使用迁移/运维身份配置 `DATABASE_URL`，指定实际 `RAW_STORE`、`STAGING_STORE`。PostgreSQL 的 `pg_dump` / `pg_restore` 需在 PATH；Windows 可通过 `BACKUP_PG_BIN` 指向 PostgreSQL 16 的 bin 目录，`BACKUP_TIMEOUT_SECONDS` 默认600。

```powershell
.venv/Scripts/python.exe -m scripts.backup create --folder .local-backups/d12-001
.venv/Scripts/python.exe -m scripts.backup verify --folder .local-backups/d12-001
```

目录必须不存在。命令对数据库表持有写排斥锁，遇到 queued/running 作业、锁超时、缺对象、哈希错误、未知迁移或额外数据库表时拒绝。PostgreSQL 使用同一导出快照的 custom dump；SQLite 仅为开发适配。锁覆盖整个复制过程，不能在这一窗口继续使用服务。失败目录保留供检查，缺 manifest 的目录不是可用备份。

运维数据库URL必须显式指定host/user/database；只允许sslmode/sslrootcert/sslcert/sslkey查询参数。dbname/host/port等URL查询覆盖、Unix socket查询参数及继承的PG*环境变量均在访问数据库前拒绝，防止SQLAlchemy检查与libpq工具连接不同目标。仅备份/恢复CLI收紧此边界，不更改线上DATABASE_URL契约。

清单记录28张表的逻辑内容摘要/行数、publication高水位、对象字节摘要、版本和引用验证。原始对象、失败后仍需保留的暂存对象、全部数据库表（含报告/快照/复核/审计/预算/工作区私钥）都在备份内。配置副本仅安全白名单，不复制 `.env`、模型/API明文凭据；锁文件及已有Compose配置随包保存。尚无经过验收的容器镜像，不伪造镜像摘要。

**完整数据库备份本身含工作区HMAC密钥、令牌摘要及授权原始证据，必须保存在受控本地目录；不得放进公开候选、截图、实验报告或上传外部服务。** SHA-256用于检测保存后的改变，不证明来源真实性；只恢复本项目自己创建且保管可信的备份。Windows目录访问继承本机ACL，工具不声称实现了备份加密或跨用户隔离。

## 恢复

在指定的同版本应用下，准备一个**新建的空 PostgreSQL 数据库**和未存在的 raw/staging 目录，环境变量指向这些新目标，保持所有服务停止。数据库名称/角色/口令由部署者在受控环境创建，不在此提供可用密钥。

```powershell
.venv/Scripts/python.exe -m scripts.backup restore --folder .local-backups/d12-001
```

命令先核验所有备份文件、版本和路径，拒绝已有表或已存在的SQLite文件、已有目标目录、路径交叠/链接。PostgreSQL恢复为单事务且不执行clean/drop；所有失败都保留部分目标供诊断，不能启动失败目标或直接重试覆盖，应使用另一新目标。恢复后逐表比对、逐事件/报告核验引用，只有全部一致才打印 `verified:true`。服务配置/角色授权仍由部署者提供：dump不创建服务器角色、不恢复原ACL，须按infra角色策略配置应用与只读角色，禁止让运行中的Agent取得运维数据库账号。旧令牌明文不从备份重新导出。

之后按原生启动手册打开旧报告，检查引用，再新建一次调查；旧报告不可改写。非部署作者应另记录实际机器、操作者、耗时、验证截图和失败情况，不能把本机脚本结果当作该签字。

仅用于本机已有独立 PostgreSQL 沙箱的自动演练：

```powershell
.venv/Scripts/python.exe -m scripts.pg_sandbox start
.venv/Scripts/python.exe -m scripts.recovery_d12 --output artifacts/d12-recovery-new
```

脚本只新建随机源/目标库，使用明确合成夹具，实际backup→restore→旧报告→新调查。私有备份留OS临时目录，定位信息在忽略的`.tools/d12-last-recovery.json`；公开的recovery.json只有统计/摘要，不包含口令、私钥、原始日志。不得把该定位文件打包。

## 实验与分析

工程执行仍用D11冻结的三份同源开发场景、B0–B3与本地协议桩，不读取正式标签进入运行组件：

```powershell
.venv/Scripts/python.exe -m eval.run --config eval/configs/d11-engineering.json --output artifacts/d12-evaluation-new
.venv/Scripts/python.exe -m eval.metrics --input artifacts/d12-evaluation-new --output artifacts/d12-evaluation-new/recomputed.json
.venv/Scripts/python.exe -m eval.analysis_d12 --manifest eval/d12-inputs.json --output artifacts/d12-analysis-new
.venv/Scripts/python.exe -m eval.analysis_d12 --output artifacts/d12-analysis-new --verify
```

目录或输出文件必须新建。`eval/d12-inputs.json`按实际已保存文件sha256固定各轮原始预测/配置/清单/统计、三轮性能样本和历史截图；增加一次执行必须另建清单版本，不能改写旧工件。候选源代码与历史artifacts分开发行；离开工作区复算时，按清单的原相对位置放置随证据包提供的文件。分析输出`summary.json`、`metrics.csv`、`resources.svg`、`index.html`和截图；verify重新读取原始输入并逐字节核对所有输出。

分析保留所有清单所列轮次和失败。调查耗时区分组执行与新记录的单次create→终态观察（含队列/重试）；输出每次值、均值、标准差、p50和nearest-rank p95。未完成率含failed/partial/blocked；超时另列n/N。零分母与缺记录为null。预算token中断仍扣除的部分不是供应商实际账单；`cost_microusd`为保守预留，`actual_cost_microusd`为配置价格下返回usage估计，供应商账单始终另列未知。真实LLM成本与90秒目标未验收。

每个已创建调查在异常路径也读取持久预算并记录；B3按既有Queue恢复/退避观察到终态或观察期限，B2异常终止保持单摘要约束。未观察到终态明确censored，不能计为已测终态耗时；旧版导入失败0ms仅作为未测标记，仍留失败分母，不冒充零耗时。存在未测时全尝试p95为null。

资源曲线包含所有三轮D11原始180点/轮；CPU按相同进程集合的CPU秒差/墙钟差计算为占用核数，进程改变/首点为未知，内存为进程树WorkingSet/PrivateMemory。D11第一轮配置尚未完全固定，第二轮P95未达2秒目标，第三轮达标；版本哈希单列。D12未重跑30分钟，不能宣传D11速度为D12测量。

## 新候选检查

```powershell
.venv/Scripts/python.exe -m scripts.release_manifest freeze --freeze release/d12-freeze-new.json --id d12-candidate-new
.venv/Scripts/python.exe -m scripts.release_manifest package --freeze release/d12-freeze-new.json --target release/d12-candidate-new
.venv/Scripts/python.exe -m scripts.check_d12 --freeze release/d12-freeze-new.json --output artifacts/d12-check-new --candidate release/d12-candidate-new --analysis-input eval/d12-inputs.json --postgres --browser
.venv/Scripts/python.exe -m scripts.d10_gate --freeze release/d12-freeze-new.json --evidence artifacts/d12-check-new --require-release
```

D12检查有19项，包含Python、PG、前端、6个浏览器用例、实际恢复、工程四组执行与分析。工程成功exit0；完整发布仍因正式数据、真实LLM、非作者恢复/部署等缺口返回exit2。所有旧候选不可覆盖。
