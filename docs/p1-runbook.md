# 七项 P1 本地增量运行说明

应用 `0.1.0.dev16`，迁移仍 `0006_d9`。仅新增本地知识与回放能力，并优化批末成员发布；R01–R06 配置、旧事件/报告和 D15 归档保持。D15 是历史 dev12 交付包，不能用它验证本次新代码。

## 精选知识

默认 `KNOWLEDGE_ENABLED=true`。Agent 仍只有原六个只读工具，get_technique_context 精确接受最多五个 ATT&CK 技术 ID。固定 Enterprise ATT&CK 18.1 六条，源对象、24 analytics/10 data components、许可证与冻结摘要位于 `knowledge/attack-18.1/`。目录不是完整 ATT&CK 库；未知 ID 显式提示，关闭/完整性失败不返回伪造知识。

knowledge_refs 与 evidence_refs 分开；前者必须出自本次 run 的已完成工具返回，不能证明 observed 事实。目录变更或开关变更会改变恢复配置/缓存身份；旧运行不可静默套用新知识。源码/目录更新时先让既有调查终止或保持原版本继续，不能改写旧报告。

## 固定水位回放

通过 API/脚本操作；当前网页仍选择默认 import session，尚无回放选择器。

1. 先导入授权数据并等待批次完成。取得 dataset_id 和 default_session_id。
2. analyst/admin 调用 `POST /api/v1/datasets/{dataset_id}/replays`，带 Bearer 令牌及独立 `Idempotency-Key`。JSON：`{"source_session_id":"源会话UUID","rate_eps":50}`。
3. 返回的 session_id 是新 replay session，job_id 用于 `GET /api/v1/replays/{job_id}` 读取进度。queued/running 时检测 pending，空事件目录带 `REPLAY_DETECTION_PENDING`，不能称为无命中。
4. 查询 `/api/v1/events`、`/overview`、`/incidents` 时同时传 dataset_id 和新的 session_id。回放完成后才检测；超过10000条保持 partial/RULE_SCOPE_TOO_LARGE。
5. 取消使用 `POST /api/v1/jobs/{job_id}/cancel`；analyst 只能取消自己创建的任务。worker 中断后保留原水位、开始时间、游标与已发布数量，由有效新租约继续。停机后允许追赶，每次事务最多500条；原事件和原始证据不复制、不修改。

默认源上限100000、批量500，配置为 `REPLAY_EVENT_LIMIT`/`REPLAY_BATCH_SIZE`；请求速率严格整数1–1000。只允许import源，新增源publication不进入既有回放。每次事件分页另绑定目标会话当时的水位。

真实本地测量命令（输出目录必须全新）：

```powershell
.venv/Scripts/python -m scripts.benchmark_p1_replay --output artifacts/p1-replay-new --count 2000 --rate 50
```

该命令建立新私有实验库、启动自己的API/worker、通过HTTP准备合成源并回放，结束仅停止自己启动的进程。公开 samples/summary 不含角色令牌，私有实验库位于 `.tools/`，不要分享。100000/1000 可测规模；它不是新日志吞吐或正式检测效果指标。失败测量保留，不覆盖。

## 验证和剩余验收

配置与容器边界见 `p1-compose.md`，实际结果见 `p1-verification.md`，七项逐项状态见 `p1-defects.json`。真实模型、33次独立资料/双人标签、非作者独立恢复与启动、物理断网及真人彩排需要真实条件和人类记录。本地协议测试、自动操作和合成数据不能代签这些条件。超过10000的完整检测仍是工程缺口；没有通过提高配置上限冒充解决。

只做本地构建，没有远程提交、发布或联系团队成员。
