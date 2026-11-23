# D14 验证与交付记录

执行日期2026-11-15。D14是离线部署与演练增量；应用固定D12 candidate-04（0.1.0.dev12，0006_d9）、内置D13 kit-02。未改规则、Agent、API或数据库迁移，没有远程提交/发布。工程交付完成，完整P0和真人验收仍未完成。

## 实际通过

| 验证 | 结果与证据 |
|---|---|
| 新工具正反测试 | **26 passed，55.70秒**；d14-final-tests.xml / d14-review-green.log。包括篡改/缺包/多包、平台/目标边界、失败保留、网络护栏与故障控制；公开备份路径另有3项RED→GREEN回归 |
| 静态检查 | 8个Python源/测试文件Ruff与format通过；录屏JS node --check通过。未将旧D12全套测试当作D14新跑结果 |
| 最终离线包 | d14-offline-02.zip，23087757字节，545文件+manifest=546ZIP条目，34个wheel；实际解压核验。仅Windows x64 CPython3.13，不含Python运行时 |
| 实际离线安装 | 主目录新venv用包01创建；最终包02实际解压后又在备/回退新目录离线安装依赖并恢复，no-index/no-cache/require-hashes；包02修复仅备份路径边界 |
| 停机备份与备用恢复 | 备份2.806秒，恢复78.211秒；28表、92事件、4报告一致，原令牌/HMAC表保持；同机隔离目录 |
| 回退 | 第三新目录恢复67.095秒；随后实际启动包内API并用原admin令牌读取旧报告，启动+读取4.594秒，报告逐字段一致。回退92事件/4报告，备用目录138事件/6报告仍保留 |
| 数据/报告最终复核 | S1/S2 manifest中14个对象逐字节SHA一致，S3仅复用S2 network/context；三目录原始对象及报告引用均核对快照；两轮4份实际报告为partial/fallback，坏引用未留在claims |
| 断网/坏引用 | 非回环connect在OS发送前被Python审计拒绝；回环模型实际断开→MODEL_UNAVAILABLE_OR_TIMEOUT；另一响应坏引用被拒绝两次→DRAFT_VALIDATION_FAILED。实际UI有DRAFT_REFERENCE_OUT_OF_SCOPE |
| 两轮自动计时 | 第1轮 **479.015秒**，第2轮 **479.012秒**；各成片479.2秒（7:59.2）、1280×800、10fps、无配音。没有加速或拼接调查；只去掉编码关闭重复尾帧，完整原片保留 |
| 反向CLI | 公开包中备份退出2且目标未创建；向已有主目录恢复退出2且未覆盖。见d14-negative-cli.json |

包SHA-256：`73a57b1ee6a6a3039c7608e97aef9a8b26e690623314f0d119eb0c8e1e1b7b01`。包内hash是完整性记录，不是数字签名；核验应使用外部可信摘要。源码/输出逐项最终绑定于artifacts/d14-build-manifest.json；视频元数据见d14-media-verified.json。

## 文件与行为

- scripts/offline_d14.py、build_d14.py、network_guard_d14.py：平台/固定底座/依赖哈希校验、离线新目录安装、私有备份/恢复与进程网络护栏。
- scripts/fault_stub_d14.py、rehearse_d14.py、verify_runtime_d14.py：明确标注的回环故障桩、真实UI操作/计时和只读数据/报告核验。
- tests/unit/test_offline_d14.py、test_fault_d14.py：边界和正反回归。
- docs/d14-runbook.md、d14-showcase.html、d14-record.mjs、d14-rehearsal-checklist.md、d14-acceptance.json：实际命令、展示/录屏、问答口径和待签署边界；README/执行计划/变更记录同步。

操作见[离线手册](d14-runbook.md)，人工事项见[真人彩排与问答表](d14-rehearsal-checklist.md)。release/d14-materials.zip提供展示页、两轮视频/字幕、截图、真实导出报告、工具和验证资料；离线部署ZIP独立交付。私有初始化日志、运行数据库、HMAC和整库备份仅留.tools受控路径，不入公开包。

## 版本与证据解释

第一轮使用包01；第二轮使用实际解压的最终包02。两轮应用底座、故障桩和录屏脚本相同；第一轮结束后只修复展示页4个文档链接，旧HTML另存d14-rehearsal-01-showcase-source.html，两个source清单均保留。包01不作为最终交付包，但保留历史；未覆盖原冻结。

主目录先跑过一次46事件/2报告的smoke，再跑第一轮得到92/4；停机备份恢复到备用目录后，第二轮另添46/2得到138/6。这是同源合成工程运行，不是独立实验样本或正式33次采集。恢复/回退时长是本机所述操作计时，不能推广成容灾SLA；回退不合并备用目录后续调查，不宣称零RPO。

单轮外部代理审查提出备份路径边界和展示链接两个问题，已一轮修复，记录见d14-review-resolution.json。D13原134项证据通过d13-preservation-d14-final.json找到原字节；D12原250项继续使用原保存索引。最终ZIP条目、公开精确令牌扫描和证据摘要另由封装脚本核验，失败/原始工件不删除。

## 未验证与未关闭

进程审计钩子/浏览器外链阻断不是物理断网，本地兼容协议故障桩不是真实LLM。同机新目录不等于独立备机/干净机器，两次自动操作不是两次真人配合彩排；实际问答和非作者签署仍空白。Compose、操作系统镜像、独立设备、最终分发许可审查未完成。未新跑正式P0门禁，七项P1（D10-001/002/003/004/005/006/009）继续阻断，TC-021/036/037/038/039/040仍不完整。

正式资料/双人真值、真实LLM与账单、完整检测/回放、知识库not_loaded、真人现场≤8分钟仍待验收。没有正式F1、真实操作者、完整攻击因果或完整攻击链覆盖声明。D15发布封存/提交不在本次范围。
