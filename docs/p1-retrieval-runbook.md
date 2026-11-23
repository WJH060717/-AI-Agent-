# dev20 补证策略本地验收

后续真实验证见 dev20 S1 真实 DeepSeek 记录（本地记录）：新增授权的 1 次已使用，流程 completed/live，但两次均 search_events、非种子新增 0；当前服务恢复 dev17 disabled。下方为此前仅本地的实施边界，不代表真实补证已通过。

本轮仅优化模型上下文和查询建议，默认模型仍关闭；没有新增付费调查，没有替换现有网页服务。使用独立 SQLite 数据库和已授权合成夹具，不读取用户私有模型配置。

计划中显示完整种子数量、已实际检索的非种子数量、最多两种有用工具的查询建议与续页索引。建议从已知资产、强进程实体及待补证缺口生成；模型仍可选择其他合法工具或停止。建议不是证据，执行结果才进入after。

`get_process_context` 可找到已知强进程的父子记录；`get_asset_timeline` 可查同资产其他记录；`search_events` 可按类型、资产和白名单条件检索。`get_event_evidence` 用于复核给定记录，不因重复调用计为新证据。路径工具返回候选，知识工具只提供背景。

分页必须保留原参数并传返回的next_cursor；跨调查游标拒绝。分页未完成和无结果不表示没有活动；强制两轮规划及其余预算不变。事实/身份摘要省略及截断有显式标记，服务器证据、工具结果、判断前后和引用保留。

从仓库根目录运行本地测试（不读取私有配置，勿设置真实模型或用户库环境变量）：

```powershell
& ".\.venv\Scripts\python.exe" -m pytest tests/contract/test_p1_retrieval.py tests/integration/test_p1_retrieval.py tests/contract/test_p1_context.py tests/integration/test_p1_context.py -q
```

已有本轮结果见 [验证记录](p1-retrieval-verification.md)。运维验收脚本使用独占新目录，重复运行会拒绝覆盖；不把它当作网页启动脚本。当前网页仍可读取dev19真实报告，本轮本地协议桩报告在独立工件目录中，不在用户数据库内。
