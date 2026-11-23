# D14 离线安装、备份与回退手册

应用继续固定D12 candidate-04（0.1.0.dev12，0006_d9），内置D13 kit-02。本包面向**已安装CPython3.13 x64的Windows**：包含34个锁定wheel、生产前端、源码和许可资料；不含Python运行时/操作系统/Docker镜像，不是裸机安装镜像。其他平台拒绝，不能联网补包。无原始私有日志、运行数据库、令牌或HMAC。

## 离线安装

先用外部公布的SHA-256核对ZIP，再解压到新目录。包内manifest只用于完整性检查，不是数字签名。本轮最终包为`d14-offline-02.zip`。

```powershell
Get-FileHash .\d14-offline-02.zip -Algorithm SHA256
Expand-Archive -LiteralPath .\d14-offline-02.zip -DestinationPath .\d14-offline
Set-Location .\d14-offline
python --version
python .\offline.py verify
python .\offline.py install --target ..\d14-primary --port 8000
```

安装新venv后，pip只读取本包wheel：`--no-index --no-cache-dir --require-hashes`，缺包/哈希错误立即停止。应用环境不继承外部DATABASE_URL或模型配置，固定loopback和MODEL_PROVIDER=disabled。Python审计钩子拒绝非回环连接/DNS，**不是物理断网或系统防火墙证明**。失败目录保留，不覆盖重试。

初始化只在终端一次显示角色令牌，必须私下保存，不录屏、不重定向到公开日志。软件包大于10MB是本地离线交付工件，不上传仓库或远程发布。

两个终端分别运行：

```powershell
python .\offline.py run --target ..\d14-primary --service api
python .\offline.py run --target ..\d14-primary --service worker
```

浏览器打开所选loopback端口，按kit/docs/d13-scenarios.md导入合成场景。`python .\offline.py status --target ..\d14-primary`仅预检，worker实际处理以作业终态为准。停机先停止新请求、排空队列，再分别Ctrl+C；不清库，不改密钥。

## 备机准备 / 同机演练

独立备机需同平台Python和同一ZIP；先验证包摘要。**本机另一个目录仅为备用实例演练，不冒充独立硬件。** 从停止写入、API/worker均关闭的主目录创建私有备份：

```powershell
python .\offline.py backup --target ..\d14-primary --backup ..\private-backup-01
python .\offline.py restore --target ..\d14-standby --backup ..\private-backup-01 --port 8001
python .\offline.py run --target ..\d14-standby --service api
python .\offline.py run --target ..\d14-standby --service worker
```

私有备份含完整数据库/HMAC/令牌摘要/原始对象，不能复制进公开包或上传。D12备份工具要求排空队列并持有写排斥锁；恢复目标必须全新且同版。恢复不init、不生成新密钥；继续使用私下保存的原令牌。验证旧报告、逐条引用，再创建新调查。操作系统/数据库角色仍由部署者管理，当前自动入口仅SQLite工程路径。

D14入口会在调用备份子进程前拒绝离线包目录、安装app源码目录及其重叠祖先目标；这不代替操作者将其他备份路径保存在受控私有位置。不要自行把备份移进release或演示材料。

## 回退

不对已升级/已写入的目录原地覆盖或降级schema。先停止当前服务并保留其目录和新写入；将最近核验的停机备份**再次恢复到第三个全新目录**，使用另一个空闲端口检查旧报告/高水位，确认后把浏览器指向该端口。例：

```powershell
python .\offline.py restore --target ..\d14-rollback --backup ..\private-backup-01 --port 8002
python .\offline.py run --target ..\d14-rollback --service api
python .\offline.py run --target ..\d14-rollback --service worker
```

回退恢复的是备份时刻，不自动合并后续写入。备用实例中之后的新调查仍留在原目录；不得将回退称为零数据损失或无缝容灾。不要同时向多个副本继续导入再假定它们一致。真实换机、非作者操作、场地物理断网和真人两次彩排须独立签署。

## 断网、坏引用与讲解

离线模型默认disabled：页面应清楚显示deterministic_fallback/partial。cached必须显示原模式和生成时间，不冒充现场AI。坏引用演练只向一次隔离的本地协议测试桩响应注入不存在的引用，真实Agent校验后拒绝；不修改原始日志、数据库报告或用户证据。工程脚本与结果另见D14验证记录。
