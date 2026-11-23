# 10｜参考资料与技术核对记录

核对日期：2026-11-14。下列为官方资料；技术选型、阈值、排期、评分公式、任务工时和性能门槛是本方案提出的设计，不是这些来源给出的保证。网页会更新，实施时需记录本地选用版本和来源快照。

| 来源 | 用于本方案的事实 | 实施注意 |
|---|---|---|
| [Zeek conn.log](https://docs.zeek.org/en/current/reference/logs/conn.html) | 连接日志包括连接标识、端点、时间、协议及流量字段 | originator不等同攻击者；字段按选定版本夹具核验 |
| [Suricata EVE JSON](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html) | EVE通过JSON提供告警和协议/流元数据，可配置Community ID | `latest`页面可能是开发版，本次页面显示9.0.0-dev；安装不能跟随浮动开发版 |
| [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) | Sysmon提供进程和网络等事件，含便于关联的进程信息 | 是P1接入；核实事件过滤/启用配置，不默认全部事件已采集 |
| [ATT&CK Data Sources](https://attack.mitre.org/datasources/) | 旧Data Sources在v18（2025年10月）弃用 | 保留历史兼容，不作为新知识模型唯一主体 |
| [ATT&CK Detection Strategies](https://attack.mitre.org/detectionstrategies/) | 检测策略组织针对特定技术的检测方法与平台分析 | 映射必须锁版本；不把分类当因果证据 |
| [ATT&CK Data Components](https://attack.mitre.org/datacomponents/) | 数据组件描述检测相关的具体数据属性 | 与传感器字段做明确映射，不能只贴技术标签 |
| [LangGraph Persistence](https://docs.langchain.com/oss/python/langgraph/persistence) | 框架提供checkpointer/store等持久化概念 | 本方案P0用明确状态机自行实现所需检查点，避免强依赖框架 |
| [UNB CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) | 提供PCAP及带标签网络流等资源 | 可作网络检测补充，不推定它具有项目所需主机/因果真值 |
| [PostgreSQL 16 SELECT](https://www.postgresql.org/docs/16/sql-select.html) | 支持FOR UPDATE SKIP LOCKED等锁定子句 | 用于短事务领取队列任务，实际幂等和租约由应用实现 |
| [FastAPI Features](https://fastapi.tiangolo.com/features/) | 支持基于类型模型的校验、OpenAPI和自动接口文档 | TypeScript类型生成工具和契约测试需另外落实 |

## 版本清单模板

```text
component / selected_version / image_digest_or_lock_hash
official_source_url / verified_on / verification_command
license / redistribution_notes / owner
```

D1记录操作系统、Docker/Compose、Python、Node、所有依赖、数据库、采集器、规则、知识条目、模型适配与模型标识。D10冻结并归档。引用官方资料不等于所有运行环境已测试，也不等于项目已做完整文献综述。

## 需要后续补充的研究工作

如果竞赛要求研究论文或创新性检索，单独补充攻击溯源/系统溯源图、告警关联、LLM安全分析Agent的相关工作比较：问题、数据、方法、证据模型、评估指标、局限和本项目区别。三周优先完成工程与可复现实验；在完成系统性检索前避免“国内外首创”“首次结合”等表述。
