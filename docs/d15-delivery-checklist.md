# D15 提交素材、分工与最终清单

状态：本地工程候选；未对外提交、未发布、未联系成员。实际包号/摘要/打开结果以外部freeze和D15验证记录为准。以下人类项目保持空白，不把自动构建身份当成真实负责人或复核人。

| 角色 | 按规约承担的交付内容 | 姓名 / 人工复核 | 状态 |
|---|---|---|---|
| A 后端/部署 | 离线部署包、安装/恢复/回退、版本清单与摘要 | 待填写 / 待填写 | 工程材料已准备；独立部署验收待签 |
| B 数据/检测 | 合成来源与对象hash、实验/数据归档、失败解释 | 待填写 / 待填写 | 历史工程资料已归档；正式采集/双标签待完成 |
| C 图/Agent | 技术附件、权限/证据边界、模式与已知限制 | 待填写 / 待填写 | 附件已准备；真实LLM/知识验收待完成 |
| D 前端/验证 | 展示页、截图、两轮预录/字幕、问答与提交清单 | 待填写 / 待填写 | 自动材料已准备；真人彩排/问答待签 |

## 素材对应

| 素材 | 候选内位置 | 验收性质 |
|---|---|---|
| 应用源码/生产前端/34wheel | deployment/d14-offline-02.zip → kit/app、wheels | 固定D12应用；Windows CPython3.13 |
| 部署/回退手册 | docs/d15-runbook.md、materials/docs/d14-runbook.md | 实际CLI；默认disabled；只新目标 |
| 技术说明/架构/证据约束 | docs/d15-technical-annex.md、materials/docs/d13-defense.md | 原型机制与限制 |
| 场景/来源/许可资料 | materials/docs/d13-scenarios.md；部署ZIP内kit/dependency-notices | 合成来源；最终权利确认待签 |
| 原始实验/数据清单 | evaluation/；部署ZIP内kit/app/data/fixtures/d9 | 保留失败及历史版本；非正式盲测 |
| 界面截图/报告 | materials/rehearsal-01、rehearsal-02 | 实际脱敏导出与页面 |
| 两轮预录/中文字幕 | materials/media | 自动操作/合成/本地故障桩/无配音 |
| 限制/未完整用例 | docs/d15-limitations.md、reference/d12-acceptance.json | 七P1、六项用例未完整 |
| 核验工具/版本/摘要 | verify.py、release-manifest.json、SHA256SUMS、外部freeze | 完整性不等于正式发布批准 |

## 必须由团队填写的提交记录

- 比赛名称/组别/提交入口/截止时间：待提供。
- 真实提交人/技术复核人/数据与许可复核人：待填写。
- 项目与第三方材料分发权利确认：未签署。
- 非作者独立部署/恢复、独立备机、现场断网、真人两次彩排：未签署，使用materials/docs/d14-rehearsal-checklist.md。
- 最终提交文件名/SHA、实际上传时间/平台回执：未提交。
- 完整P0发布批准：未通过，不得把普通verify的exit0当批准。
