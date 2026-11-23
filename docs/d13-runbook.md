# D13 原生部署手册

D13交付是部署/展示套件，内置未改动的D12 candidate-04：应用 **0.1.0.dev12**，迁移 **0006_d9**。页面仍显示D12，属于正确版本。套件不包含Python、数据库运行目录、密钥、依赖wheel或node_modules。默认模型disabled，小型SQLite本地演示；PostgreSQL/Compose独立部署仍按原权限契约验收。新venv不是新机器，自动脚本不是非作者签字。

## 1. 准备与核验

使用可信渠道取得 `d13-kit-*.zip` 及独立发布的SHA-256。先核对ZIP摘要，再解压到新目录；不要信任来源不明且可同时被改写的脚本和manifest。哈希不是签名或来源证明。需Python3.12/3.13，实际验证平台Windows/Python3.13.5；Linux和3.12尚未实测。生产前端已构建，无需Node。

```powershell
Get-FileHash .\d13-kit-02.zip -Algorithm SHA256
Expand-Archive -LiteralPath .\d13-kit-02.zip -DestinationPath .\d13-kit
Set-Location .\d13-kit
python .\deploy.py verify
python .\deploy.py install --target ..\d13-runtime --port 8000
```

这里的 `python` 必须是3.12/3.13；先 `python --version`。安装创建独立venv，用requirements-dev.lock精确版本安装binary wheels、pip check、空库迁移、初始化、只读预检。需要获准访问PyPI；不继承用户的pip配置、代理、PYTHONPATH、DATABASE_URL或模型环境变量。不在此提供企业代理/私有索引配置；依赖不可取得时停下，保留失败目录，用可信wheelhouse另建目标。

可选已准备的同平台wheel目录：`python .\deploy.py install --target ..\d13-runtime-02 --wheelhouse D:\trusted-wheels --port 8001`。该模式传入 `--no-index`，但D13套件不自带离线依赖；D14离线交付尚未验收。锁文件只锁版本，未提供供应链签名/逐wheel批准摘要，wheel来源须由操作者信任。

**初始化只在终端显示一次三个角色令牌。请私下保存；不要录制这一终端、不要重定向安装输出到公开日志。** `installed.json`不含令牌。原库中只有令牌摘要。安装器拒绝已有目标、路径链接、包漂移及额外文件，失败不会删除或覆盖目标，也不会自动重试。不要删除失败目录里的证据；选择另一新目录重试。

## 2. 启动和停止

从套件目录开两个终端，使用同一绝对运行目录：

```powershell
python .\deploy.py run --target ..\d13-runtime --service api
python .\deploy.py run --target ..\d13-runtime --service worker
```

第一条在终端A，第二条在终端B，各保持前台。浏览器打开 `http://127.0.0.1:8000`，输入admin令牌。若改变安装端口，以installed.json为准。安装器每次核对应用文件与固定底座，数据从同一运行目录派生，不能通过环境变量指向旧库或启用外部模型。浏览器令牌仅在内存，刷新重新输入。

第三终端可运行：`python .\deploy.py status --target ..\d13-runtime`。它核查库/迁移/依赖/目录/静态资源，**不证明API监听、worker存活或模型连通**。再打开页面并上传一份合成日志，观察queued→succeeded才证明本次worker实际处理。没有worker时队列不会完成；不要再初始化数据库。

停止：先停止新上传/调查，等待已有作业结束；分别在两服务终端Ctrl+C。再用同样两条run命令重启，原令牌、事件、报告仍在；不要重跑install/init-demo。端口占用时API退出，保留现场；用空闲端口新装或由部署者处理占用进程，不自动杀其他程序。

## 3. 最短验收路径

见 `docs/d13-scenarios.md`：新建synthetic数据集→先配置context→导入network/auth/audit→安全事件→开始调查→打开引用→导出HTML→重启后查看历史。默认disabled应显示 `deterministic_fallback`/partial及真实停止原因；不能期待真实LLM补证。至少用S3验证缺主机日志时未知保留。

非作者请独立执行 `docs/d13-operator-checklist.md`，记录实际失败、开始/结束时间、机器/操作者代号和证据路径。模板尚未签署，工具不会自动填“通过”。不要在模板填令牌、口令或原始账号。

## 4. 备份、恢复与PG

数据目录私有保管，SQLite文件含工作区HMAC和令牌摘要。不能装入公开套件、视频或展示页。D12完整停机备份/空库恢复具体命令见 `app/docs/d12-runbook.md`；先停止服务并排空队列，用同一运行目录/版本设置配置。恢复必须另建目标，不覆盖本安装；恢复不重新生成密钥。安装器不提供“重置”“清理”“卸载库”。

PostgreSQL需独立迁移、应用、只读角色（`app/infra/roles.sql`），仅迁移角色migrate。D13自动安装只支持小型SQLite演示，不将该路径作为PG角色隔离验收。`app/infra/compose.postgres.yaml`只有DB模板；四服务Compose与镜像未构建验收。Docker引擎当前不可连接，禁止照旧规划草案声称运行成功。

恢复失败、哈希不符或版本不符应停止，不重建卷/清库。令牌丢失没有本阶段自动重置入口，由管理员在受控流程处置，不重复初始化假装找回。
