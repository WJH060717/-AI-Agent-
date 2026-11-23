# 项目交接包：先看这里

适用：Windows x64，Docker Desktop已安装，使用Linux容器。应用0.1.0.dev24，模型关闭。启动无需安装Python/Node，也无需下载应用依赖；Docker Desktop/Windows不包含在包中。建议预留4GB磁盘空间。

1. **完整解压**到一个新文件夹，例如 `D:\接手项目`，不要在压缩包预览中直接启动。
2. 打开Docker Desktop，等引擎运行后，双击 **START.cmd**。
3. 等待网页自动打开；访问令牌已复制到剪贴板，粘贴到“访问令牌”后点“连接”。令牌也保存在 `_local\login.txt`。

首次启动会加载本地镜像、创建独立数据库并导入24条合成入门示例。worker完成导入后即可查看候选、生成确定性报告、查询证据及导出。示例不是实测攻击或正式成绩。

默认网址 `http://127.0.0.1:8080`。端口已占用时自动选择8081起的空闲端口，以启动窗口和 `_local\login.txt`显示的网址为准，不关闭占用端口的服务。

**停止：** 双击 `STOP.cmd`。再次双击 `START.cmd`复用原数据、令牌和报告。容器设置了Docker引擎启动后自动恢复；整机登录后还需Docker Desktop自动运行。不要删除Docker数据卷、运行`down -v`或随意删除`_local`。

**完整性检查：** 在该文件夹打开PowerShell，运行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Verify.ps1
```

外部 `.sha256.txt`用于核对收到的ZIP。哈希只用于完整性，不是签名或正式发布批准。

**源码与交接：** 阅读 `HANDOFF.md`；所有开发代码在 `project\`。启动器默认运行包内固定镜像，编辑源码不会自动修改正在运行的版本。

**真实测试样本：** 见 `project\docs\cc-round4-verification.md`。JSONL和原始CTU抓包在 `project\artifacts\`，官方标签只供离线对照，不能输入检测器。首次无需导入这些数据即可体验入门示例。

**遇到问题：** 确认Docker使用Linux容器、引擎已启动；启动失败保留现场后可再次运行。`_local\last-command.log`是本机诊断日志，可能含私有连接信息，勿公开分享。显式指定端口可运行 `powershell -NoProfile -ExecutionPolicy Bypass -File .\Start.ps1 -Port 8090`；已运行时先STOP。

交接ZIP不含原作者的运行库、访问令牌、工作区私钥或模型密钥。首次启动后的整个文件夹包含接手人自己的凭据，若要再次转交，应转发原始ZIP，不能把运行后的目录直接重新压缩。

启动实测结果与平台限制见 `HANDOFF.md`；同机新目录验证不等于另一台干净机器验收。
