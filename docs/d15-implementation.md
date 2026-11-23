# D15 Implementation Plan / 实施台账

> 使用superpowers:executing-plans在当前工作区执行；一个最终独立只读审查，不逐任务派发。规约与用户连续构建授权提供范围，不重复申请方案许可。

**Goal:** 将已核验应用、离线部署、展示材料、原始实验和限制汇总为可本地打开、可核验、不可覆盖的D15工程交付候选。
**Architecture:** 固定D14 offline-02 ZIP和materials ZIP、D12 analysis-evidence ZIP。构建器仅选定源文件，前者原字节分发，后两者安全解压后可直接打开；独立标准库verify.py验证文件集/哈希/路径/固定应用，--strict持续阻断完整P0。外部freeze绑定manifest和ZIP摘要。
**Tech Stack:** Python3.13、标准库ZIP/SHA/HTML、构建时Pydantic契约、pytest；既有Playwright仅打开交付文件，不运行模型。
**Spec:** PROJECT_SPEC.md；docs/06-execution-plan.md D15/T-30；docs/08-deployment-demo.md；docs/d14-verification.md。

## Global Constraints / Rulings

- Ruling: D15输出为engineering_candidate，p0_release_ready=false；七项P1/六个未完整用例保持 — 现有证据不支持正式发布 — 不能作为比赛最终验收签字。
- Ruling: 只构建本地提交素材，不上传或联系成员；A/B/C/D是规约角色，姓名/复核人/提交回执保持待填 — 未提供真实提交信息 — 需要团队最后填写。
- Ruling: 无Git仓库，沿用原工作区与哈希封存，不新建仓库/分支，不删除旧工件；根文档变动前保存D14原字节 — 保护历史证据 — 版本追踪依赖清单而非commit。
- 应用仍0.1.0.dev12、0006_d9；无业务/规则/Agent/契约迁移；运行时不读eval。
- 离线包仅已有Windows CPython3.13 x64；非作者、独立硬件、物理断网、真人彩排、真实LLM、许可最终确认均不代签。
- 仅导入固定公开材料，不扫描.tools运行库或私有备份。>10MB为本地授权离线交付，不提交二进制至仓库/远端。

## Task1：封装与独立核验

Files: scripts/build_d15.py、verify_d15.py；tests/unit/test_delivery_d15.py。
Interfaces: build(root: Path, target: Path) -> dict；verify(bundle: Path, expected_manifest: str | None = None) -> dict；safe_zip(path: Path) -> list[ZipInfo]；verify.py [--bundle PATH] [--expected-manifest-sha256 HASH] [--strict]。

- [x] 先写失败测试：固定来源、缺失/篡改/多余文件、已存在目标、重叠/链接、ZIP越界/重复/大小写冲突、错误外部摘要、清单伪造P0/固定部署包、strict退出2。
- [x] 实现最小构建与核验；manifest类型严格、文件白名单；输出先验后写，失败保留；相对链接安全转义。
- [x] pytest/Ruff/format通过；失败与成功日志留artifacts/d15-*。

## Task2：技术附件、实验归档与待签清单

Files: docs/d15-runbook.md、technical-annex.md、limitations.md、delivery-checklist.md、acceptance.json、source-catalog.json。
Consumes: 固定三个来源ZIP、D12用例/缺陷、D14最终146项记录；输出材料、证据位置与角色职责。

- [x] 记录REQ-001–008/TC-001–040的历史实现范围及未完整项；实验失败轮次保留，正式成绩未知；展示录像明确预录。
- [x] 角色职责、提交素材、许可/真人/非作者签署空白；不编姓名、时间或回执。
- [x] 原文档保存后更新README/执行计划/变更记录；旧D14/D13/D12摘要仍可定位原字节。

## Task3：实际解压打开、审查与封存

Consumes: Task1候选+Task2附件；Outputs: release/d15-candidate-NN.zip、外部freeze、artifacts/d15-check-NN证据与最终build manifest。

- [x] 新目录实际解压，独立python -I verify.py通过；--strict实际exit2且保留七P1；固定部署ZIP再次核验。
- [x] 浏览器离线打开入口、展示页、两轮视频、报告、历史分析页和图；验证JSON/XML/PNG/VTT等格式及链接；历史输入复算结果绑定其旧版本。
- [x] 一位新审查代理整体只读审查，必要问题一轮RED→GREEN修复；最终候选不能覆盖旧目录。
- [x] 全文件/ZIP/外部freeze摘要、公开令牌扫描、历史保护核验；完成记录明确实际结果与未签项。

## Review Focus

1. 包内manifest可编辑不能把旧部署包替换或把P0改true；外部摘要才是可信定位。
2. ZIP目录穿越/Windows别名/链接/重复或压缩炸弹在解压前拒绝。
3. 新输出不能位于源文档/历史候选/私有运行目录内，已有目标不可覆盖。
4. 文档入口可点击，实验归档保留失败与历史版本，不能给出正式成绩。
5. 本地候选封存不等于真实人员签署/正式提交；无私有库和令牌外泄。

## Ledger

- Pre-flight: Task1输出manifest/候选路径供Task3验证；Task2仅消费固定公开输入。候选首次构建在文档齐备后；实际验收另存外部check目录，避免自引用哈希。
- 基线：D14 146文件全部核验通过；无Git，D12/D13旧记录不修改。
- Task1: 首次25项运行24通过/1失败。系统诊断发现Windows zipfile会规范化反斜线；测试用原始ZipInfo文件名复现后，核验改为同时拒绝orig_filename与filename差异。格式化发生在首轮运行期间，最终只采用格式稳定后的新一轮测试为结论。
- Task1: complete — 25 passed in 32.38s（d15-tests-02.xml/log），Ruff通过；独立CLI普通exit0/strict exit2正反路径已覆盖。
- Task2: 技术附件、七P1限制、40用例历史索引、角色与提交待签表已准备。最终check记录在包外创建并绑定候选摘要，避免封存内容自引用。

- Task3: complete — 实际解压/独立verify、strict阻断、格式/浏览器/历史复算及最终审查完成；见d15-verification.md与外部check记录。
- Final: 人工/正式发布/比赛提交不代签；原始失败工件及旧候选保留；没有仓库，不执行合入/推送。
- Final: Ruling: 最终公开扫描与文档封存 — 由主代理实际完成并另写最终摘要证据；不是跳过验收 — 限制：公开候选完整性或隐私声明不能成立。
- Final: Ruling: D12应用全量重跑/真实性能 — 本次不改应用，保留原版本测试与性能边界，仅增量封装测试与历史复算 — 限制：无法宣称D15重新验收全部应用或性能。
- Final: Ruling: 真实LLM/账单、正式数据/标签、知识、完整检测回放 — 保留七P1及六项未完整用例，strict继续exit2 — 限制：不能批准完整P0或给出正式指标。
- Final: Ruling: 干净机器/Compose/独立硬件/非作者/物理断网/真人彩排 — 保持pending，自动化证据不替代人类或设备验收 — 限制：不能代表场地部署可用性。
- Final: Ruling: 许可、人员签署与比赛提交回执 — 姓名/签字/入口/回执留空，只准备本地素材，不对外提交 — 限制：仍需真实团队最终核查并执行提交。
- Final: independent review clean；无Critical/Important/Minor；无延期小项。
