# 网页简化验证记录

后续部署：新版已按用户新增授权接入原8080，并配置登录自启与Docker自动恢复，见8080部署与验证（本地记录）。下文5180是本次界面开发阶段的历史记录；该临时进程现已关闭。

日期：2026-11-16。P2 前端增量，后端版本、迁移0006_d9、规则冻结、模型预算和P1状态不变。没有真实模型调用，没有替换原Docker服务。

## 新操作流程

1. 打开 http://127.0.0.1:5180 ，输入现有访问令牌。
2. 使用已有数据集直接“查看异常”，或选择日志并上传。类型自动识别；不能确定时手选。资产配置、数据集管理、回放、事件查询按需展开。
3. 异常自动显示；明确点击才创建调查。打开历史报告不创建调查。报告分结论、关系与时间线、补证对比、运行记录；证据弹窗可按Escape关闭。

新入口是本机Vite进程，代理现有 http://127.0.0.1:8080 的API。原8080网页继续可用。前端进程信息在 artifacts/ui-workflow-preview-01/pid.txt；它不是安装服务，退出或重启机器后需要重新启动。普通启动方式（终端在apps/web）：先设置 `$env:TRACE_API_TARGET='http://127.0.0.1:8080'`，再执行 `npm.cmd run dev -- --port 5180 --strictPort`。现有后台必须运行；令牌刷新后重新输入。

## 实际检查

`npm.cmd --prefix apps/web run build`：TypeScript与Vite成功，26个模块，生产包位于apps/web/dist。`npm.cmd --prefix apps/web run lint`通过；`ruff check scripts/browser_simple_workflow.py`通过。

` .venv/Scripts/python -m scripts.browser_simple_workflow --artifacts artifacts/ui-workflow-check-03 `：**9 passed，30.4秒**，详细结果在该目录的playwright.log/result.json。8项浏览器流程、1项格式识别检查：

- 连接后自动查询异常，导航/历史阅读不自动发起调查。
- 真实API已创建调查但响应丢失，同键重试得到同一个run；读失败重试不创建新run。
- 真实回放pending/取消/partial，旧会话响应不能覆盖导入会话；viewer创建回放403。
- 真实确定性调查、证据弹窗/Escape、HTML与JSON下载、人工复核、恶意文本安全渲染、缓存与历史阅读；viewer导出403。
- 四类日志五次上传，实际新增26+6+3+1+1，共37事件；唯一传感器自动填入，多传感器人工选择。
- 冲突/未知/非JSON输入不猜测类型；未知文件不能静默上传，保留手选。
- 证据不可验证警告在结论之前；图读取失败仍能阅读报告。
- 导入持续排队时可以断开，离开后旧进度不回写。

使用新建SQLite与本地API/worker、明确MODEL_PROVIDER=disabled，无eval输入。失败与不可验证情景只在浏览器拦截本地响应，未损坏/修改原始对象。首轮失败、选择器修正及审查RED工件保留于ui-workflow-red-01、ui-workflow-check-01、ui-workflow-retry-red-01/02、ui-workflow-review-red-01；通过中间轮次check-02也保留。trace可能包含一次性测试令牌，工件只留本地，不作为公开包。

实际新版入口GET /返回200，代理health/live为ok；1366×768、1920×1080、390×844登录页检查无横向溢出、连接按钮可见、无pageerror，记录于ui-workflow-preview-01/browser-check.json。额外多视口截图命令发生一次30秒超时并终止；随后独立布局检查通过，未将超时截图算作通过。流程截图使用check-03/import.png、anomalies.png、report.png，已实际查看。所有自动检查都不等于零基础真人可用性签署。

## 文件与限制

修改apps/web/src的main、Intake、Investigation、ReportPanel、MissingEvidence、ReplayPanel、client与style；新增EvidenceDialog、importHints；新增浏览器spec和隔离运行脚本；同步05-api-ui、change-log与本设计/计划。改动前文件在artifacts/ui-workflow-before-01。

格式识别只读有界前缀，不能保证整个文件同源，最终由服务端逐条解析；既有数据集的传感器配置没有读取API，自动填入只使用当前页成功提交的配置。专业操作和技术ID仍可在详情找到。没有真实LLM或零基础真人可用性验收；没有重跑未改动后端的全量Python/PostgreSQL测试。旧D3–D11及p1-scale浏览器脚本依赖旧导航，本轮未声称其通过；新版回归用本文件记录的独立脚本。未生成正式发布候选、未远程提交或发布。
