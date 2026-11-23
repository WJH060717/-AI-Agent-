# 场景、来源与授权边界

全部内置对象来自本项目D6/D7/D9 Python生成器，是**开发合成夹具**，没有执行攻击、采集公网、导入真实受害者日志。IP是实验/文档地址，时间是夹具构造时间，不是采集日期。三场景同属 `legacy-development-regression`，不是三次独立盲测，更不是33次已采集实验。来源与对象SHA见 `app/data/fixtures/d9/*/manifest.json` 和底座freeze.json；构建白名单见infra/release-inputs.json。哈希只证明保存后字节完整性。

每个场景新建一个synthetic数据集，先上传对应context.json，后上传日志。以下路径相对套件app/。

| 场景 | 输入顺序（文件 / 来源 / 传感器） | 实际可演示 | 不能据此证明 |
|---|---|---|---|
| S1 | d9/S1：network / zeek / net-a；auth_a / linux_auth / auth-a；audit / linux_audit / audit-a；auth_b / linux_auth / auth-b；alerts / suricata / alert-a；文件均.jsonl | 37个规范事件；多源、规则解释、进程/会话证据、引用与确定性报告 | 完整攻击因果、真实操作者、无socket的进程流量归属、成功横移或文件内容 |
| S2 | d9/S2：network / zeek / net-a；audit / linux_audit / audit-a | 9网络+2规范审计事件；周期/出站量候选，监控/备份的正常替代上下文 | context_only不证明无攻击或流量属于正常进程；窗口覆盖不是完整攻击链覆盖 |
| S3 | 使用d9/S2 context，只上传network / zeek / net-a，省略audit | 9网络事件；缺主机证据、unknown、partial、预算/模型停止原因 | 不补造主机进程、socket或工具返回；不把fallback说成模型推理 |

路径完整前缀为 `data/fixtures/`。audit物理行数与聚合规范事件数分开；上传UI按规范事件显示。S1同时包含独立后段出站量候选，不强行并成一条攻击链。不能将context、eval标签或预写答案注入Agent补证；Agent只接收运行时白名单工具的实际快照返回。

## 资料状态

eval/runs.json的33项仍planned，3份prepared材料同源，0项双人真值复核。B0规则、B1图、B2单摘要、B3受控工具的工程执行和D11/D12统计均有原始记录；正式F1、正常误报率、真实LLM账单和人的调查准确率均未知。失败轮次不得剔除；D11性能只对相应旧代码和协议成立。

## 许可证与分发清单

本项目代码和合成夹具由项目工作区提供；尚无项目LICENSE文件/权利人最终授权声明，**未宣称开源许可已完成**。比赛前由团队确认源代码/材料分发权利。Zeek/Suricata/audit名称表示输入格式，不含第三方传感器软件、真实流量或其数据集。

套件包含React/Vite构建后的前端及自有源码；Python和Node依赖按锁文件识别。主要直接依赖许可元数据需连同原文核查，D13生成的dependency-notices资料记录本机已安装元数据及可读取许可证原文。该清单不等于法律审查或全部传递依赖授权签署。无模型权重、外部知识库、第三方截图、外部图片/字体或商业音频；录屏无配音。知识工具仍not_loaded，不编造ATT&CK知识引用。

场景和录像只含合成数据与脱敏投影，不展示令牌、HMAC盐、真实账号、原始命令或数据库私有备份。
