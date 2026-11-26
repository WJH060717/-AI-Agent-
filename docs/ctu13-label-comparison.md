# CTU-13：18 个既有候选的官方标签对照

日期：2026-11-16。受测对象固定为 `artifacts/ctu13-check-05/incident-details.json` 中的 18 个 R05 周期连接候选，未重新选择样本、运行检测或调整规则。

## 结果

| 官方标签支持的判断 | 候选数 | 对应证据数 |
| --- | ---: | ---: |
| 恶意标签命中（From-Botnet） | **0** | **0** |
| 明确正常（From-Normal） | **1** | **20** |
| 背景流量，正常/恶意未知（Background） | **17** | **196** |
| 未找到或匹配歧义 | **0** | **0** |

如果把周期候选视作“恶意告警”，明确正常的 1 个候选属于误报。R05 本身只声明周期行为，并未认定 C2，所以该结果不表示周期计算出错。其余 17 个候选只能记为未知，不能把 Background 等同正常而算成 17 个误报。

**此前用来跑通报告的 20 条连接，就是这次确认正常的候选。**它证明真实日志能完成导入、检测、证据和报告管线，不能证明系统成功识别了恶意行为。此前的“定向工程正例”指功能测试正例，不是恶意真值正例。

## 逐候选结果

下表编号沿用冻结候选文件顺序；所有连接协议都是 TCP。标签列省略共同前缀 `flow=`。

| 编号 | 候选 ID 前缀 | 源地址 → 目的地址:端口 | 证据数 | 官方标签 | 判定 |
| --- | --- | --- | ---: | --- | --- |
| 1 | bc806ee6 | 147.32.84.170 → 195.24.233.55:80 | 20 | From-Normal-V48-Stribrek ×20 | 明确正常；按恶意告警口径为误报 |
| 2 | 46ebd51a | 147.32.86.89 → 90.183.101.168:80 | 39 | Background-TCP-Established ×39 | 未知 |
| 3 | 371d9f11 | 147.32.86.151 → 209.85.149.189:443 | 15 | Background ×1；Background-TCP-Established ×14 | 未知 |
| 4 | 96350bde | 147.32.85.8 → 209.85.149.189:443 | 10 | Background-TCP-Established ×10 | 未知 |
| 5 | 73cfc769 | 147.32.84.59 → 184.73.252.84:80 | 10 | Background-Established-cmpgw-CVUT ×10 | 未知 |
| 6 | 87d4c8c6 | 147.32.86.74 → 147.32.30.4:80 | 10 | Background ×1；Background-TCP-Established ×9 | 未知 |
| 7 | 428842ff | 147.32.84.59 → 184.73.176.145:80 | 10 | Background-Established-cmpgw-CVUT ×10 | 未知 |
| 8 | 8c1c0e62 | 147.32.86.53 → 91.203.96.252:443 | 9 | Background-TCP-Established ×9 | 未知 |
| 9 | f8b97dd9 | 147.32.84.59 → 209.85.149.189:443 | 10 | Background-Established-cmpgw-CVUT ×10 | 未知 |
| 10 | 60e1087b | 147.32.84.59 → 69.171.229.24:443 | 9 | Background-Established-cmpgw-CVUT ×9 | 未知 |
| 11 | 7e273ad9 | 147.32.84.59 → 174.129.22.181:80 | 10 | Background-Established-cmpgw-CVUT ×10 | 未知 |
| 12 | 5c93a44d | 147.32.85.117 → 62.168.44.115:80 | 9 | Background-TCP-Established ×9 | 未知 |
| 13 | 4ebb4e57 | 147.32.86.172 → 69.171.228.20:443 | 9 | Background-TCP-Established ×9 | 未知 |
| 14 | 89d67b92 | 147.32.86.77 → 174.129.28.81:80 | 10 | Background-TCP-Established ×10 | 未知 |
| 15 | 56f78db7 | 147.32.86.77 → 174.129.30.226:80 | 10 | Background-TCP-Established ×10 | 未知 |
| 16 | 4a1fe282 | 147.32.84.59 → 199.59.148.201:80 | 9 | Background-Established-cmpgw-CVUT ×9 | 未知 |
| 17 | 1f05a51d | 147.32.86.77 → 184.73.218.104:80 | 9 | Background-TCP-Established ×9 | 未知 |
| 18 | 3145f24a | 147.32.86.111 → 62.44.29.44:110 | 8 | Background-TCP-Established ×8 | 未知 |

## 来源与匹配方法

使用 [CTU-13 官方推荐的双向流标签](https://www.stratosphereips.org/datasets-ctu13)，场景 7 的 [capture20110816-2.binetflow](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/detailed-bidirectional-flow-labels/capture20110816-2.binetflow)。没有使用旧单向标签或第三方重标版本。

- 官方标签文件：15,630,512 字节，114,077 条流记录；SHA-256 `df0b5338190b967bd340a0d6c1bb3c34d1bbfb4b7ffa764c2dd26f77f1a26680`。
- HTTPS 下载证书校验保持开启，32 MiB 上限；原文件、下载元数据、官方 README 保存在 `artifacts/ctu13-labels-01/source/`。
- 来源署名：Garcia, Sebastian. Malware Capture Facility Project. Retrieved from https://stratosphereips.org。
- [官方场景说明](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/README.md)说明 `From-Botnet` 与 `To-Botnet` 不等价，后者本身不能认定恶意；`From-Normal` 与 `To-Normal` 也分开处理。

匹配只使用原始连接字段，不依据 IP 属于哪台主机直接赋标签：

1. 根据既有事件 ID 契约（工作区、数据集、传感器、文件 SHA-256、物理行号）从原 JSONL 恢复恰好 216 个冻结证据事件；核对原 Bro TSV 的 UID、时间、完整连接元组及源行哈希。
2. 官方 CSV 的起始时间按 README 中 **2011-08-16 的 CEST 记录**解释为 UTC+02:00，再转 UTC；原日志时间不改写。没有根据标签类别拟合时间偏移。
3. 采用协议、源/目的 IP、源/目的端口完整五元组及起始时间（容差 1 微秒）；允许双向流端点互换，但保留原始标签方向。
4. 必须唯一匹配；同一官方流被多个不同事件复用、多个候选标签行、时间超界或无法匹配，都不能默认为命中。
5. 实际 **216/216 唯一对应 216 个不同官方行，时间差均为 0 微秒**；214 条同向、2 条反向。反向记录是官方第 1165、2658 行，均为 `flow=Background`，不影响未知分类。

官方文件中另有 36 条 TCP 流缺少可用端口，原行保留在离线索引中并计数，未强行匹配；它们没有造成这 216 条证据的缺口。没有为提高匹配率退化到只按 IP 或任意相邻时间匹配，也没有靠删点规避歧义。

正常候选的 20 个官方物理行号为：19、5307、9234、12285、15576、18070、20847、23366、25926、28759、31481、34150、36836、39666、42626、45524、47903、50735、53394、56696（第 1 行为表头）。这些行均为 `flow=From-Normal-V48-Stribrek`。

## 隔离、验证与工件

标签仅进入新建的离线 SQLite 索引 `artifacts/ctu13-labels-01/comparison-02/offline-labels.sqlite`；没有启动调查、调用模型或向应用导入标签。既有独立测试库/候选没有改写，8080 没有业务写操作。

- 新增 `eval/ctu13_label_compare.py`，纯标准库离线匹配；应用、检测、Agent 不导入该模块。
- 新增匹配测试 23 项，涵盖完整元组、时间边界、双向方向、冲突/重复、未知标签、缺端口、不完整证据。连同已有适配/溯源测试，**45 项通过**；Ruff 通过。
- 独立原始行复算再次验证全部 216 条和 18 个候选成员；离线 SQLite `integrity_check=ok`。
- 新上下文只读复核独立重建索引，确认相同结果，未发现影响本轮结论的正确性问题。
- 8080 的 **28 张表指纹与本轮开始及上一轮最终状态一致**，仍为 37 条事件、5 份报告；5 个原始证据对象哈希全部匹配，模型仍 disabled。
- 上一轮完整性清单中 **111 个文件未改变**，本轮冻结的 6 个输入未改变。新增付费模型调用 **0 次**。

初次探查发现官方 TCP 行存在空端口，现以无法构造完整键处理并保留；没有因此丢掉目标证据。`comparison-01` 保留首次运行结果；最终依据 `comparison-02`，两次结果相同，第二次绑定最终静态检查通过的代码哈希。测试初始失败与静态检查输出保留，未覆盖旧运行工件。

主要交付：

- 完整候选结果 JSON（本地归档 `../artifacts/ctu13-labels-01/comparison-02/comparison.json`）
- 逐事件匹配、官方行号及行哈希（本地归档 `../artifacts/ctu13-labels-01/comparison-02/evidence-matches.jsonl`）
- 独立复算结果（本地归档 `../artifacts/ctu13-labels-01/independent-verification.json`）
- 8080 数据保全结果（本地归档 `../artifacts/ctu13-labels-01/preservation.json`）
- 相关测试 JUnit（本地归档 `../artifacts/ctu13-labels-01/related-tests.xml`）
- 工件完整性清单（本地归档 `../artifacts/ctu13-labels-01/artifact-manifest.json`）

## 结论边界

本次只回答固定 18 个候选是否有官方标签支持。没有对未被选中的流进行漏报评估，因此不计算召回率、整体准确率或 FPR；17 个 Background 也使恶意告警精确率无法从这组结果可靠确定。0 个恶意标签命中不等于整个 10,000 条样本没有恶意流量。

官方标签不是 R05“周期性是否存在”的行为级真值，不能据此计算该行为检测规则的正式 TP/FP 分数。本次没有将标签或正常 IP 加入运行基线/白名单，没有调参后宣称盲测通过；标签仍只用于事后离线核验。真实 LLM、完整攻击因果和真实操作者均未验证。

复现命令如下。输出必须是全新目录，示例 `comparison-03` 尚未运行；命令不会连接应用或模型：

```powershell
& .venv/Scripts/python -m eval.ctu13_label_compare --audit artifacts/ctu13-labels-01 --output artifacts/ctu13-labels-01/comparison-03
& .venv/Scripts/python -m pytest tests/unit/test_ctu13_label_compare.py tests/unit/test_ctu13_sample.py tests/unit/test_ctu13_focus.py -q
```
