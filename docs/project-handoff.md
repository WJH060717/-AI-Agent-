# dev24 项目交接

任务：让下一位开发者快速启动，并继续维护当前竞赛原型。交付目标已确认Windows + Docker，完整源码/文档/可复现实验数据，新建运行库。原作者8080服务及数据保持。

## 先启动

按 `START-HERE.md`执行，双击START、粘贴新令牌即可使用。默认模型disabled，后端内部网络；首次自动创建独立数据库、工作区和24条合成示例。STOP保留数据库、原件和令牌。根目录 `_local`与Docker数据卷是接手人的私有运行状态，不在原交接ZIP内。

启动器/Compose只管理本包随机命名的 `tracehandoff...` 项目，不复用原作者部署名称或卷。DB不映射主机端口，网页只监听回环地址。迁移/初始化使用一次性owner连接，常驻API/worker使用受限trace_app角色；应用不能改写旧证据、报告、冻结上下文等。

## 当前状态，以此为准

- 最新源码和本包镜像：**0.1.0.dev24 / 0006_d9**，含简化网页、R01–R11、导入/回放/调查/图/证据/报告/导出/复核，以及固定ATT&CK知识目录。原作者仍运行dev17后台+新版网页，两者不要混淆。本包启动的是最新dev24。
- 第四轮：官方CTU恶意连接完整上下文覆盖6/26，剩余20；剩余21条单独输入仍0。正常20条Bro记录无新增C&C候选，旧R05仍1候选。R11真实正常PCAP误报率未验证，不能称零误报或控制成功。
- 最近业务回归：824项Python通过，原网页9项流程、4组新真实样本和2组旧HTTP样本通过；这些历史数字属于第四轮，不自动代表本包新增安装工具已验收。
- 模型预算/权限和原付费授权不可沿用。最新真实DeepSeek补证未增加非种子证据，五项P1状态和正式验收限制见 `project/docs/p1-defects.json`、`p1-retrieval-live-verification.md`。本包不配置或调用付费模型。
- 项目是4人、3周竞赛原型；工程完整性通过不代表正式发布批准。身份/因果不确定时必须保留未知，不能把IP、PID、规则分数或官方测试标签当成操作者证据。

## 完整项目范围

`project/`包含后端/前端源码、测试、脚本、契约、规则冻结、数据库迁移、知识目录、依赖锁、设计文档、合成夹具及离线评估代码。保留历史公开候选和Windows CPython3.13离线wheel，以支持既有打包测试；历史包不是本次启动入口。

CTU/Bro/PCAP原件、适配样本、官方离线标签和历轮最终结果保留原相对目录。本轮浏览器调试录制/临时令牌、运行数据库、缓存、机器虚拟环境、node_modules不交付；可再生成的标签SQLite索引不交付。历史公开候选中的演示材料原样保留。`manifest.json`给出实际逐文件清单。历史文档中未收录的临时工件路径不应被当作当前启动依赖。

源码 `README.md`含大量历史阶段说明，开始开发先读本文件、`project/AGENTS.md`、`PROJECT_SPEC.md`，再按以下路径进入。

| 任务 | 主要入口 |
|---|---|
| 页面操作 | `apps/web/src/Intake.tsx`、`Investigation.tsx`、`ReportPanel.tsx` |
| API与配置 | `apps/api/main.py`、`packages/config.py`、`docs/05-api-ui.md` |
| 导入/证据 | `packages/ingest/`、`packages/storage/service.py`、`analysis.py` |
| 检测规则 | `packages/detection/registry.py`、`r01.py`–`r11.py`、`rules/` |
| 新抓包能力 | `packages/ingest/pcap.py`、`http_wire.py`、`scripts/pcap_http_sample.py` |
| 受控Agent | `packages/agent/`、`docs/04-agent.md`、`docs/d7-runbook.md` |
| 契约/数据库 | `packages/contracts/`、`migrations/versions/`、`docs/02-data-contracts.md` |
| 真实数据评估 | `eval/ctu13_cc_round4*.py`，仅离线，不进入运行Agent |
| 本次交接工具 | `infra/handoff/`、`scripts/handoff_bundle.py` |

表中路径相对`project/`。本工作区没有Git历史，已保留原源码及旧候选；接手人可自行初始化版本库，但不要提交 `_local`、运行库、密钥或原始敏感日志。

## 继续开发与测试

启动无需安装开发工具。改Python代码/运行Windows本机测试时，安装CPython3.13 x64；改网页时安装兼容锁文件的Node.js 22开发环境。完整依赖来自两个锁文件，不擅自升级。

```powershell
cd project
py -3.13 -m venv .venv
.venv\Scripts\python -m pip install --no-index --find-links .tools\d13-wheels -r requirements-dev.lock
.venv\Scripts\python -m pytest -q
.venv\Scripts\python -m ruff check packages apps/api apps/worker
# 网页开发首次需网络安装npm锁定依赖；启动交接镜像无需此步骤
cd apps\web
npm ci
npm run typegen
npm run build
npm run lint
```

Windows离线wheel已与既有锁核对；不能在Linux直接使用Windowswheel。浏览器回归另需Playwright浏览器，未包含机器上原有浏览器缓存。新增安装工具的具体实测范围见末尾。

修改后不要误以为START运行的是新源码。标准Docker构建入口为 `project/infra/Dockerfile.app` 和 `Dockerfile.web`；依赖拉取需要网络。用新的镜像标签和独立Compose项目按 `project/docs/p1-compose.md`配置开发环境；该文件的旧验收记录是历史，手工开发部署不等同本包一键启动。本包固定镜像和校验清单不能直接用新代码覆盖。

恢复与备份遵守 `project/docs/d12-runbook.md`、`p1-acceptance-runbook.md`：先停服务、排空队列、写排斥锁，仅恢复到新目录/空库，保留旧数据与密钥。现有原作者数据库没有转移，不能声称与原8080数据同步。

## 真实数据复现与下一步

第四轮完整记录：`project/docs/cc-round4-verification.md`，逐条列出21条补证结果；原始包与样本位于 `project/artifacts/cc-round4-01`。补证保留约4.06秒的跨探针时间差，不自动校准或强连；响应文件魔数不证明正常/恶意。

下一步优先收集可验证的正常完整PCAP，补足R11误报对照；分析剩余20条的响应语义与主机socket证据。不要以放宽连接数/读取标签/硬编码CTU端点来制造命中。TLS/HTTP2、IPv6/VLAN、跨文件重叠去重、大规模新规则性能仍未验证。细节引用现有验证文档，避免重新开始已经完成的轮次。

历史样本manifest含原作者绝对原件路径；原件随包按相对路径保留。复验时用新的输出目录生成当前路径manifest，不改写旧历史结果。旧独立Docker验证脚本会读取原作者生产容器指纹，接手人的机器没有该容器，应使用本包独立启动/导入流程；不得创建假生产容器冒充原环境。

## 本次打包验证

已在本机Windows PowerShell 5.1 / Docker Desktop Linux amd64的新目录和独立Compose项目实测：自动避开占用中的8080，在8081启动；24条合成入门示例导入、207条CTU事件的四类格式导入与重复去重、4份确定性报告、逐条证据校验及HTML/JSON导出通过，模型调用为0。STOP后再START，原令牌、事件和4份报告保持。浏览器完成登录、切换数据集、重复上传、候选、历史报告、证据和导出，未发现页面脚本错误。

三个包内镜像已执行docker load验证；应用镜像128个运行文件与源码一致，未携带模型密钥。后端网络为internal，常驻数据库角色不是超级用户，不能UPDATE/DELETE旧事件和报告。26个历史及嵌套ZIP已检查，未发现运行库/凭据文件；密钥签名扫描未发现命中。首次源码回归因漏收两个历史保护测试脚本出现22个加载错误；补齐后在打包源码目录重新执行，**842项Python测试全部通过**，有1条既有依赖弃用提示。包内`verification/`保存JUnit、测试计数和摘要，首次失败记录保留在原作者本地。

修复了启动身份文件中断写入、封存输出覆盖、STOP切换Docker上下文和Windows PowerShell 5.1原子状态更新问题，均有针对性验证。启动/停止只管理本包新项目；模型授权不随历史脚本转移，`.tools`中两个trial.py只保留源码供保护测试，不附私有输入或重新调用权限。

第一个封存候选的ZIP解压与CRC检查通过，但在混合PowerShell模块路径的Python子进程中，Get-FileHash不可用，完整性检查停止；该候选与失败记录保留，不作为本次交付入口。第二个候选改用.NET SHA256，另对同一包内镜像的索引、Linux/amd64清单与配置摘要分别校验，兼容不同镜像ID表示；这三种摘要均从images.tar读取并核验关联。Docker存储机制背景见[官方文档](https://docs.docker.com/desktop/features/containerd/)。修复后24项交接工具检查通过；842项全量回归来自修复前，业务源码、镜像及原824项业务检查未变，不能把两次测试数量相加称作一轮全量结果。另一种Docker存储模式只完成ID分支验证，未另建真实引擎切换测试。

最终ZIP封存后还会在另一个中文含空格路径解压，进行完整性、启动和持久化复验；最终包哈希和该轮结果记录于ZIP旁的`.verification.json`，以其实际结果为准，不改写已封存包。未在另一台电脑、整机重启、物理断网或真实付费模型下执行；不把同机新目录当作干净机器或非作者签署。Docker镜像已内置全部运行依赖，源码前端开发的npm依赖和浏览器测试工具需另行安装。
