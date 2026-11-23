# 部署边界

D2已有PostgreSQL16模板compose.postgres.yaml和roles.sql。真实数据库行为已用便携PostgreSQL16.16验证；本机未安装Docker，容器模板未实际运行，镜像摘要待容器环境锁定。迁移通过apps.api.manage执行，API启动不自动建库。

D10重新核验：Docker客户端现已存在，但dockerDesktopLinuxEngine不可连接；未将容器运行标为通过。当前交付原生冻结候选，见docs/d10-runbook.md。release-inputs.json仅锁定已核查的合成开发夹具/规则对象，不等同双人人工真值复核。

D13再次核验引擎仍不可连接。当前提供固定D12应用的原生部署套件，见docs/d13-runbook.md；安装只创建新venv/SQLite数据目录，不自动修改Docker/WSL配置，不将本机自动安装当作非作者干净机器验收。

D14提供34个锁定wheel的Windows CPython3.13离线包，实际命令见docs/d14-runbook.md。只支持新目录SQLite工程安装/停机备份/恢复/第三目录回退；原生Python审计限制非回环网络，不更改宿主防火墙。未重新验收Docker、裸机、独立备机或非作者操作。

D15将固定部署包、展示与历史实验整理为本地工程候选，独立verify.py不启动服务/模型/依赖安装。仅完整性通过；strict门禁仍阻断完整P0。见docs/d15-runbook.md，不自动发布或覆盖历史候选。
