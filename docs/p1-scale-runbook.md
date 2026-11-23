# P1 全量检测与回放操作（dev17）

沿用 README 的本地 API、worker、前端启动方式；数据库 head 仍为 0006_d9，无新迁移。模型默认关闭。本页取代 dev16 手册中“网页尚无回放选择器”和“超过 10000 条必定 partial”的说明。

## 本地使用

1. 在“概览与导入”输入当前工作区令牌，连接并选择已导入的数据集，等待导入结束。
2. 在“已有事件回放”填写 1–1000 的整数 EPS，点击“创建回放”。源是该数据集的默认 import 会话；回放固定源水位，不复制或更改原事件。
3. 页面顶部显示当前输入模式和会话。进度展示已发布 / 总事件、作业状态、检测状态及警告。全部成员发布后才执行全量六规则检测；pending 空目录不能表示无命中。
4. “刷新事件”和“安全事件 → 刷新检测事件”查询当前选定会话；“返回导入会话”切回原数据。已发布报告保持其原快照，不原地改写。
5. 保存显示的作业 ID；刷新网页后重新连接同一数据集，填入 ID 并“打开回放”。取消按钮保留已发布事件，状态为 cancelled/partial；analyst 只能取消自己创建的作业，admin 可取消工作区作业。
6. POST 响应不确定时点击“重试创建（同一请求）”，保留同一参数及幂等键。刷新页面会丢失页面内存，切勿把未知结果直接当成未创建并重复提交。令牌不写入浏览器持久存储。

## 资源和状态

默认 / 最大完整检测会话为 100000 条。六规则冻结配置与语义阈值不变；只有全部检测及目录发布成功才 complete。输入 JSON 默认 256MiB、工作单元 2000000、检测时限 20 秒（且不超过 lease/3）、finding 2000、引用总数 500000；配置范围见 `.env.example` 与 `Settings`。

超出条数：RULE_SCOPE_TOO_LARGE；其他资源预算耗尽：RULE_RESOURCE_LIMIT。两者均 partial，检测 savepoint 回滚、已有原始事件与有效历史目录保留。不能把历史目录当作完整的新检测覆盖。非预期错误继续失败，不转成“无命中”。调查快照仍上限 250，过大的候选会明确拒绝创建调查，完整检测不等于完整调查或完整攻击因果。

本地 SQLite 的最终批量发布可能暂时占用写锁，状态 GET 可返回 503；回放面板会提示并重试，工程测量也记录这些错误。没有为本轮修改用户数据库的 journal 模式。PostgreSQL 已验证同样的正常发布及资源回滚路径。

## 复验命令（开发工作区）

所有输出目录/文件须全新；脚本只创建自己的合成实验库，结束停止自己启动的子进程。私有数据库位于 `.tools/`，不随证据包发布。

```powershell
.venv/Scripts/python.exe -m pytest tests/contract/test_p1_scale.py tests/integration/test_p1_scale.py tests/integration/test_p1_replay.py -q
.venv/Scripts/python.exe -m scripts.benchmark_p1_scale --output artifacts/p1-scale-rules-new.json
.venv/Scripts/python.exe -m scripts.benchmark_p1_replay --output artifacts/p1-scale-http-new --count 100000 --rate 1000 --full-detection
.venv/Scripts/python.exe -m scripts.browser_p1_scale --artifacts artifacts/p1-scale-browser-new
```

`--full-detection` 要求源导入 succeeded、回放 completed/complete、成员集合完全相同及原事件摘要不变。未带该选项保留旧版 10000 范围测量配置；不能用其 partial 结果关闭全量检测缺口。离线六规则规模脚本使用测试夹具，仅开发验证运行，应用/worker 不读取测试标签或 eval。

实际结果见 `p1-scale-verification.md`，当前缺口见 `p1-defects.json`。真实模型账单、33 次独立资料及双人标签、非作者独立恢复/启动、容器启动、物理断网与真人彩排仍需各自真实证据；本地合成测试不可替代。
