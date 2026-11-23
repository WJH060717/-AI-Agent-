# 第 13.9 节行为检测验收（dev41）

固定集实测 **2/16**，行为门禁退出码 **2**。检测结论与溯源结果显示在报告结论、JSON 和 HTML 导出中。规约内的类型身份、权限、快照、校验和回放继续沿用既有约束。行为验收原始结果（本地 ../artifacts/p2-behavior-dev41-01/behavior.json）

| 固定结果 | 本轮实测 |
| --- | --- |
| 行为通过，溯源未成功 | `Recon-HostDiscovery` 的 R26 支持疑似主机发现。 `Mirai-udpplain` 的 R20 支持直接 UDP 洪泛，Mirai 家族未知。 |
| 四项未检测到目标行为 | PortScan 固定前缀端口覆盖不足。OSScan 和 VulnerabilityScan 固定前缀只支持端口扫描。GRE Ethernet 固定前缀缺 GRE 封装记录。 |
| 一项采集失败 | GRE IP 首份原件第 268 条物理记录长度超限。 |
| 九项未验证 | DNS 欺骗、ARP 欺骗缺已冻结的场景原始记录；暴力破解缺固定认证事务；六类 Web 与终端任务仍缺固定的专项告警、应用或终端记录。 |
| 补充片段单列 | PortScan、OSScan、GRE 直接 IP 封装洪泛及 GRE 以太网封装洪泛通过相应行为验收。OSScan 补充片段同时保留 PortScan 候选；移除已登记的配对应答后，OSScan 行为消失。 |
| 合成工程测试 | R28、R29 正例及疑似暴力破解的报告分支通过工程测试。R02 复用既有“失败后成功”判据，仅覆盖此形态。目标认证会话与两个进程均有可核实的观测关联，报告明确发起侧溯源未成功。 |

10 份已冻结正常对照完成验收，其间没有出现本轮计分映射中的行为告警。对照主要覆盖抓包场景，审计类输入仍待独立固定对照。既有精确评分仍是 1/17，PingSweep 精确通过。独立 DoS/DDoS 固定集 v2 实测 11/12，原始记录对账和回放 12/12，通过其门禁，SlowLoris 仍为未知。独立固定集结果（本地 ../artifacts/p2-behavior-dev41-01/fixed-v2.json）

报告按已复现 finding 生成 `behavior_assessments`。导出及网页均逐条显示检测依据、时间和范围、原始引用、溯源断点与原因。新报告无命中时明确显示，旧报告字段可省略。规则冻结、历史报告和数据库迁移 0006_d9 保持。8080 仍为 dev31 草稿修复版，本轮验证在隔离运行中完成，未调用付费模型。

## 复验

此命令需要另行准备已获授权、与冻结摘要匹配的输入。运行时选择新的结果路径。退出 2 表示仍有固定行为项未通过。

```powershell
.\.venv\Scripts\python.exe -X utf8 -m eval.ciciot_behavior --result artifacts/p2-behavior-dev41-02/behavior.json
```

562 项相关 Python 回归及另 7 项算分契约通过，浏览器实测 2 项通过，后端契约生成、前端类型检查、lint 和生产构建通过。Python 回归（本地 ../artifacts/p2-behavior-dev41-01/regression.xml） · 算分契约（本地 ../artifacts/p2-behavior-dev41-01/score-contract.xml） · 浏览器结果（本地 ../artifacts/p2-behavior-dev41-01/browser-behavior-dev41-01/playwright.log）
