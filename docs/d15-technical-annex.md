# D15 技术附件与证据索引

应用版本0.1.0.dev12、数据库0006_d9，底座D12 candidate-04；D15只封装已有公开材料和核验工具。原型为单实验室/单工作区，非生产多租户平台。

## 实际链路与边界

授权本地合成日志→API鉴权/幂等/限流→staging→Queue租约worker→不可变raw对象/规范事件→六规则候选→快照有界图/路径→受控Agent接口原型→引用/有限谓词校验→可回溯报告/人工复核/脱敏导出。

原始对象只读；调查、报告、目录版本不可原地改写。Agent只调用绑定工作区/快照/预算的白名单只读工具；写入经Queue.guard及lease/version，模型调用前持久预留预算。日志/模型文本不能扩大权限，缺socket/可靠身份/严格先后保留断点，真实操作者未知。

真实LLM未验收：D14是本地兼容协议故障桩，连接中断或坏引用导致partial/deterministic_fallback；cached保留原生成时间和source_mode。自由文字、IP/PID、ATT&CK标签不能当作充分身份/因果证据。知识工具当前not_loaded。

## 需求与交付定位

| 需求 | 历史实现/测试定位 | 当前限制 |
|---|---|---|
| REQ-001/002 导入/完整性/身份 | reference/d12-acceptance.json，TC-001–009；应用源码在deployment ZIP的kit/app | 合成工程夹具；不证明真实采集质量 |
| REQ-003 六规则 | TC-010–015，rules/freeze.json；检测与夹具在固定应用内 | 未正式采集33次/双复核，不能称盲测 |
| REQ-004 图/路径 | TC-016–020，有界图、严格时序和证据引用 | 链内覆盖非完整攻击链，超过范围截断 |
| REQ-005 受控Agent接口 | TC-021–027，D14拒绝坏引用/传输失败页面 | TC-021未完整：真实模型/费用与知识未验收 |
| REQ-006 页面/引用/导出 | TC-028–030，materials/rehearsal-01及02实际报告截图 | 模式/partial需明确，人工accepted不改报告事实 |
| REQ-007 权限/恢复 | TC-031–036，materials/verification/d14-standby/rollback-verified.json | TC-036非作者独立恢复仍待验收 |
| REQ-008 评估/部署/演示 | TC-037–040，evaluation原始历史材料，materials两轮录像 | 正式数据、回放/全量检测、干净环境/Compose、真人/物理断网仍缺失 |

reference/d12-acceptance.json保留40项原映射与测试路径，不把历史implemented误称本轮全量重跑。source-catalog.json提供归档来源、摘要、版本及文件位置；D15检查记录只覆盖封装、打开和复算，不替换应用历史测试结果。

## 实验解释

33项仍planned，prepared同源开发材料不算独立运行；S3是S2省略主机证据，不能算新采集。evaluation保留所有三轮D11性能：第一轮配置缺口、第二轮P95失败、第三轮通过均保留；资源曲线以原始样本重算。D12/D14没有新跑这项30分钟基准。

预算预留、返回usage按配置估算、真实供应商账单分别处理；没有账单是未知。失败、partial、censored和零分母不能排除后宣传高准确率。本候选不宣称完整攻击因果、真实攻击者身份、完整攻击链覆盖或研究首创。
