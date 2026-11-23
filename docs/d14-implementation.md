# D14 Implementation Plan / 实施台账

> 按 superpowers:executing-plans 原地执行。已批准规约D14提供范围，不重开产品设计。无Git，不提交/发布；旧候选和证据不可覆盖。

**Goal:** 提供Windows x64/Python3.13的依赖离线包、空目标恢复/切换/回退路径，以及断网/坏引用和两轮自动计时演练证据。
**Architecture:** 固定D13 kit-02与其D12应用底座。D14仅增加运维工具；34个wheel逐字节锁定，pip no-index/no-cache/require-hashes。停机备份使用D12工具；恢复到全新目录，不降级数据库、不删除旧环境。故障只作用于本地协议测试桩，原始证据不改。
**Tech Stack:** Python标准库bootstrap，既有Pydantic备份契约，Windows CPython3.13，SQLite工程路径，Playwright。
**Spec:** PROJECT_SPEC.md；docs/06-execution-plan.md D14；docs/08-deployment-demo.md；docs/d13-verification.md。

## 全局约束与裁定

- 应用仍0.1.0.dev12，迁移0006_d9。离线包不是全新操作系统镜像，目标须已有CPython3.13 x64；不分发Anaconda、不改宿主网络或Docker。
- 备机演练为同机隔离目录，不等于独立硬件。回退使用停机时刻备份新恢复目录，不覆盖主库；切换后的新写入留在原目录，不自动合并/丢弃。
- Python审计钩子拒绝非回环connect/DNS，浏览器阻断外部请求；这是进程级故障演练，不是物理拔网或系统防火墙验收。
- 离线公开包不含运行库、令牌、HMAC、私有备份。备份/恢复保留原密钥；不重新init。
- 模型不可达与坏引用通过本地明确标注的协议桩/回环故障验证，不声称真实LLM。两轮自动计时不代替真人问答/彩排。

## 接口与任务

Task1提供offline.py verify/install/restore/run/status及固定tools/deploy_d13.py、network_guard.py；Task2使用这些入口准备主/备/回退环境；Task3消费实际运行记录出材料/清单。预检固定源码与wheel哈希，私有备份不进入包清单。

### Task1：离线包与恢复入口
- [x] tests/unit/test_offline_d14.py先RED：依赖篡改/遗漏/多余项、平台不符、已有/链接/重叠目标、子进程失败、只允许回环。
- [x] scripts/offline_d14.py、build_d14.py、network_guard_d14.py；先验证再写，只新建；bootstrap不需要预装Pydantic。
- [x] GREEN、静态检查，实际从解压后的离线包新建venv，无索引/缓存安装。

### Task2：故障、备份与回退演练
- [x] 同机新主目录实际导入/报告；停机排空→备份→全新备目录恢复→旧报告/令牌一致→新调查。
- [x] 回退另一个新目录，核对备份高水位与旧报告；原主/备目录及新调查保留。
- [x] 非回环网络调用在发出前拒绝；回环模型不可达实际partial/fallback；坏引用由原Agent校验拒绝，合法引用仍可回溯。
- [x] 三场景对象hash、报告引用/模式/完整性复核，结果由脚本产生。

### Task3：两次计时与交付
- [x] 同一冻结版本两轮自动计时演练，不加速，记录开始/结束/步骤/失败；每轮≤480秒只表示该自动流程。
- [x] 操作/断网/回退手册、问答排练表、待签署真人验收、限制与旧证据保护。
- [x] 一位新审查代理整体只读审查，单轮必要修复；最终包/工件逐项hash核验。

## Review Focus

1. 可变清单不能批准固定底座里的额外代码/.env；已知D13字节必须保持。
2. pip只能消费本包锁定wheel；缺包/错平台/哈希不符不得联网补取。
3. 备份恢复/回退不能覆盖已有库或改变主环境；失败不能写成功标记。
4. 故障桩/网络护栏不能变为运行时Agent权限；凭据/原始记录不能进公开包。
5. 同机目录、自动化和协议桩不得冒充备机、人类验收、物理断网或真实模型。

## 进度

- D13最终134项证据逐项核验通过；拟修改的6份历史源文档已保存原字节。

- 26项测试与静态检查通过；同机备用/第三目录回退、两轮自动计时及实际报告核验完成，详见d14-verification.md。
- 人工、独立硬件、物理断网和真实LLM项按验收JSON保持pending/partial，不由任务复选框代签。
