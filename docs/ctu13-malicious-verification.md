# CTU-13 官方恶意标签样本实测

日期：2026-11-17。对象：原 8080 所用安装镜像，新建独立数据库和数据卷。无付费模型调用。

## 实际结论

**46 条官方 From-Botnet 标签对应的真实 Bro 记录成功导入、去重并可查询，但没有检出任何候选。因此，本轮不能判定真实恶意检测功能通过；调查、快照证据查询、报告与导出均未验证。**

| 检查 | 实际结果 |
| --- | --- |
| 官方选样 | 63 条 From-Botnet 中，46 条唯一精确对应 Bro 原记录；17 条无法一一对应，保留未纳入清单 |
| 首次导入 | 46 条接受、0 条隔离 |
| 同文件重复导入 | 0 条新增、46 条重复去重 |
| 事件查询与原文比对 | 46/46 条字段及来源映射检查通过 |
| 检测任务 | `complete`，0 个候选；没有任务失败或资源超限记录 |
| 网页检查 | 事件详情、分页、真实“无命中”显示通过；共 1 项通过、2 项跳过 |
| 调查、快照证据、报告及导出 | 无候选可启动调查，本轮未执行、未验证 |
| 相关单元测试 | 52 项通过；新增选样工具的 7 项包含在内；Ruff 通过 |
| 8080 数据 | 28 张表指纹一致，仍为 37 条事件、5 份报告；5 个原始对象哈希全部匹配 |

运行工件中的 `status=passed` 表示已执行的工程断言通过，不代表恶意检测通过或全部功能验收通过。`report_test_available=false`、`incident_count=0`、`reports=[]` 与这一边界一致。

## 样本依据

本轮复用已固定哈希的 CTU-13 场景 7 完整 Bro 文件，以及 [官方详细双向流标签](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/detailed-bidirectional-flow-labels/capture20110816-2.binetflow)。没有下载或运行恶意程序，没有连接样本中的地址。

- [Bro conn.log 官方地址](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/bro/conn.log)；17,912,559 字节，SHA-256 `37af6042144c5590603b5f986202914e4d78f5c74ef96e2aa88052c57e04639d`。
- 官方标签文件 SHA-256 `df0b5338190b967bd340a0d6c1bb3c34d1bbfb4b7ffa764c2dd26f77f1a26680`。
- [场景说明](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/README.md)明确区分 From-Botnet 和 To-Botnet。本轮只枚举 From-Botnet，不用目标 IP 或 To-Botnet 推断恶意。
- 来源署名：Garcia, Sebastian. Malware Capture Facility Project. Retrieved from https://stratosphereips.org。

离线选样采用协议、源/目的 IP、源/目的端口完整五元组，以及官方 CEST 转 UTC 后的精确起始时间；允许双向流端点互换但保留原方向。全部满足唯一匹配的记录都选入，不按是否能命中当前规则挑选连接组，没有删除内部记录来制造周期。

| 官方标签类别 | 本次匹配记录数 |
| --- | ---: |
| TCP-CC108-Plain-HTTP | 19 |
| TCP-CC77-HTTP-Not-Encrypted | 7 |
| TCP-WEB-Established | 8 |
| TCP-Attempt | 3 |
| TCP-Established-HTTP-Binary-Download-12 | 1 |
| TCP-Established-HTTP-Ad-4 | 1 |
| TCP-HTTP-Google-Net-Established-6 / -7 | 2 |
| UDP-DNS | 4 |
| UDP-Attempt | 1 |
| 合计 | **46** |

标签共同前缀为 `flow=From-Botnet-V48-`，完整原标签见 `official-selection.json`。其中有 26 条官方 C&C 标签、1 条二进制下载标签；这些是官方分类，不是应用自行推断的结果。From-Botnet 集合也包含 DNS 等辅助流量，不能将每条记录都解释为独立攻击动作。

样本共 41 条 TCP、5 条 UDP；时间范围为 2011-08-16 **11:53:16.575831—12:00:22.621874 UTC**。17 条未匹配的官方记录均为 UDP-DNS；没有用近似时间或 IP 归属补齐。20 条已选原记录的 `missed_bytes > 0`，这一采集质量限制保存在清单中，不能宣称完整包级观测。

上传 JSONL SHA-256：`0bcff6413545e3f42f2ba81fcc72d22e14477730b61310fde81f72ecab9ad54c`。UID、时间、连接字段及原始源行不修改；完整源字节和物理行映射保留。官方标签仅用于离线选样和验真，没有出现在上传 JSONL、运行上下文、检测或 Agent 输入中。

## 为什么没有检出候选

实际安装镜像中的 R01、R05、R06 配置及 `rules/freeze.json` 哈希均与工作区冻结配置一致，运行前后未调整。

- **R01 扫描**：本样本对每个目的地址最多只涉及 1 个不同端口，未达到 20 端口阈值；所有目的地址均不在当前配置的三个私有网段中，不能触发内部多主机扫描条件。
- **R05 周期连接**：按同一来源到同一目的地址/端口/协议分组，要求至少 8 条且跨度至少 300 秒。`123.126.51.33:80` 的 19 条 C&C 连接跨度仅 **198.805727 秒**；`61.135.188.210:80` 的 7 条跨度 **233.983679 秒**。其他组也不能同时满足条数和跨度的必要条件。整个样本覆盖 7 分钟，不等于某个相同连接组满足 5 分钟条件。
- **R06 出站量**：全部样本 `orig_bytes` 合计仅 **28,645 字节**，任何 5 分钟子集都无法达到 10,000,000 字节阈值。
- **R02/R03/R04**：该样本只有网络连接，没有这些规则所需的认证、进程或主机关联证据。

因此，观察结果符合当前规则的执行条件，但暴露出当前规则对这批官方恶意流量的检测覆盖缺口。没有把“任务完成”当成“攻击检出”，也没有依据这次测试标签降低阈值、添加目标 IP 特判或伪造候选来生成报告。本轮未修改应用业务代码、规则冻结或数据库迁移。

## 隔离与保全

首次尝试时 Docker 引擎未启动，尚未进行样本导入；用户启动 Docker 后恢复测试。原四服务正常运行，恢复后的生产指纹与上一轮最终状态一致。

真实运行使用与 8080 相同的安装镜像，完整标识记录在 `artifacts/ctu13-malicious-check-01/environment.json`：后端 dev17 `92ea169ca1a95…`、新版前端 `21f6b34d4ba9…`，无镜像替换。

测试单独创建 PG/API/worker/web、网络和两个数据卷；API/worker/db 内部网络，模型 `disabled`。标签文件未挂载到服务。测试容器/网络已清理，两个独立测试数据卷保留；没有操作 8080 的数据卷。

最终只读检查确认：

- 生产 28 表内容指纹与本轮开始及上一轮最终状态一致。
- 37 条事件、5 份报告未变，5 个原始证据对象哈希匹配，原服务模型仍 disabled。
- 前两轮完整性清单的 142 个文件项、本轮 6 个冻结输入均保持不变。
- 独立逐行复算确认 46 个真实记录与官方标签对应；新上下文只读复核得到同样的 63/46/17 结果。
- 付费模型调用 **0 次**。本轮不涉及真实模型推理验证。

## 工件与复现

- [实际运行结果](../artifacts/ctu13-malicious-check-01/result.json)
- [检测完成状态](../artifacts/ctu13-malicious-check-01/overview.json)
- [全部官方选样与未匹配项](../artifacts/ctu13-malicious-01/sample-01/official-selection.json)
- [可导入的无标签样本](../artifacts/ctu13-malicious-01/sample-01/adapted/conn.jsonl)
- [固定规则条件诊断](../artifacts/ctu13-malicious-01/rule-scope-diagnosis.json)
- [独立核验](../artifacts/ctu13-malicious-01/independent-verification.json)
- [数据保全记录](../artifacts/ctu13-malicious-01/preservation.json)
- [52 项测试 JUnit](../artifacts/ctu13-malicious-01/related-tests.xml)
- [完整性清单](../artifacts/ctu13-malicious-01/artifact-manifest.json)

新增文件为 `eval/ctu13_malicious_sample.py`、`tests/unit/test_ctu13_malicious_sample.py`、本记录及相应计划/工件。既有适配器与真实应用验证器保持原样。

复现命令结构如下；输出目录必须不存在，示例 `check-02` 尚未执行。只在独立测试库导入，不向 8080 写入：

```powershell
& .venv/Scripts/python -m scripts.verify_ctu13 --source artifacts/ctu13-malicious-01/sample-01/adapted --artifacts artifacts/ctu13-malicious-check-02
```

本次是按官方标签选样的定向功能测试，不是盲测；17 条无法对应的标签、背景上下文、完整 CTU-13、多源攻击链及真实 LLM 均不在已验证范围。未计算整体准确率、召回率、误报率，也未以工程断言通过代替恶意检测验收。
