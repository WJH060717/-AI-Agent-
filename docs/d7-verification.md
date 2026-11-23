# D7验证记录｜2026-11-14

本次实现REQ-003/004/005/006/007在D7的纵向子集，对应T-10、T-14～16/18/23及TC-014/015/021/026等相关门禁。当前编码助手实施，一次独立最终代码审查，三个Important均先失败回归后一次修复；无团队人工签字或Git提交（当前目录不是Git仓库），不宣称完整P0/发布验收。

## 最终实际执行

完整命令：`./scripts/check-d7.ps1 -Postgres -Browser`，退出码0。

| 检查 | 实际输出 |
|---|---|
| 全量Python | 228 passed，100.44s |
| PostgreSQL16.16受限角色集成 | 81 passed，92.42s；随机独立测试库，D2→现有0005_d6迁移保留原workspace |
| Ruff/lint格式 | All checks passed；161 files already formatted |
| Python依赖 | No broken requirements found |
| 前端typegen/typecheck/lint/build | 全部成功；Vite8.3.8、20模块构建 |
| D3浏览器 | 1 passed，7.3s |
| D4浏览器 | 1 passed，9.5s |
| D5浏览器 | 1 passed，12.2s |
| D6浏览器 | 1 passed，16.7s |
| D7浏览器 | 1 passed，11.8s |

81项集成属于228项全量用例的子集，不能相加冒充309个不同用例。耗时是本机运行记录，不是性能基准。全量测试出现一条pytest缓存目录写入权限警告，用例全部通过；未修改业务文件或权限来消除缓存提示。

## 覆盖与可追溯产物

| 门禁 | 正向 | 反例/故障 |
|---|---|---|
| R05 / TC-014 | 8次、420秒、CV/误差上界、乱序/去重、跨桶；冻结配置复现 | 少于8次/短跨度/抖动/高时间误差、跨通道/域/资产/端点、歧义映射；前置噪声或同刻记录不遮蔽有效连续段，不能删除内部不规则点 |
| R05滑窗合并 | 90条20秒周期合为1finding/1判断，2个覆盖全段的达标窗口；复现稳定 | 原实现30重复finding被失败测试捕获；合并整体CV可>0.15，明确不代表单窗阈值 |
| R06 / TC-015 | 10MB、充分30历史窗、nearest-rank p95、严格三倍整数边界、baseline_hash绑定ID | 不足30窗/未来或异作用域参考仅固定信号；高正常备份基线不报异常；响应方向/未知资产/分桶/通道拆分不凑数；超过JS浮点精度的整数边界仍正确 |
| 正常参考契约 | 不可变DatasetContext、已知资产/Zeek通道、对齐300秒历史正常开发参考 | 重复/重叠/时长/负数/bool/非法hash/未知绑定拒绝；空基线保持旧context规范化字节 |
| 补证 / TC-021 | 实际HTTP桩→get_asset_timeline→get_event_evidence→成稿；before9→after11，两个open→weakened及引用/行动序号 | 异资产/域/时间、弱PID、无关可执行文件和注入文本不削弱判断；空查询不否定活动 |
| 关系与反证 | R02补回同Host/boot/账号/session进程，旧R04 attempt补回匹配成功认证 | session不符、真实失败认证不能支持成功；正常程序只有context_only，仍留socket/授权/内容/基线缺口 |
| 停止/恢复 / TC-026/034/035 | 无新增两次、两轮上限、主动draft、缺口已补四类停止；检查点冻结before/判断配置，缓存不重复变化 | 零工具预算partial且不执行工具；D6取消/租约/超时/断进程保守预留回归保留；晚到导入不改写既有比较 |
| API/证据 / TC-023/024/028/031/032 | viewer读取typed comparison并点击哈希证据，安全executable/PID/出生标记可见 | 跨工作区404、行动明细权限不放宽；伪引用/反向事实校验保留；原始命令/账号/扩展均不进投影，EOE不伪造process |

主要测试：tests/contract/test_d7_rules.py、test_d7_baseline.py、test_d7_assessment.py；tests/integration/test_d7_agent.py、test_d7_rules_pipeline.py、test_d7_api.py；apps/web/tests/d7.spec.ts。旧D3–D6全量及浏览器也参与最终复验。

输入：data/fixtures/d7/manifest.json，provenance_type=synthetic、split=development。context SHA-256为`c4a54c25ffb229854bf6256dc8e00da18e0fdfdfce9dd5f9bd16427a37edb3f1`；network9行+audit4行→11规范事件；8次周期、首5分钟桶12,005,000字节；没有执行攻击或生成真实网络流量。正常备份参考和不规则连接反例另建数据集；运行时不读取真值。

浏览器产物：artifacts/d7-browser/closed-loop.png、playwright.log、services.log、results/.last-run.json。页面检查了同快照9→11、两条变化、ACTIONABLE_GAPS_RESOLVED、两个真实工具、可点击process证据及“本地协议测试桩（非真实LLM）”标签。后台集成检查持久行动、前后集合、版本与权限，截图不能独立替代这些记录。

## 最终审查处理

1. Important：最长1200秒窗口的CV不单调，前置噪声压掉后续达标段。先复现无finding，再改为有界连续子窗检验；前置噪声/同刻记录恢复命中，内部不规则记录仍不能删除。
2. Important：窗口滚动后互不包含的命中没有合并，90条变30finding并挤满20判断。先复现30≠1，再改为确定性连续合并、达标窗口覆盖证据及<1800秒候选段；整体统计与单窗统计分开，不能伪称全部记录同属1200秒窗。
3. Important：正常进程反向线索在证据抽屉看不到executable/生命周期。先复现process字段缺失，再增加严格安全投影；真实导入的正反例证明关键字段可查且PRIVATE命令/账号/扩展均隐藏。D7浏览器也断言抽屉可见node_exporter或rsync路径。

三项均RED→GREEN，针对性43项通过后运行上述完整228/81及D3–D7浏览器，未再请求复审。边界和每项Ruling记录于[d7-implementation](d7-implementation.md)。

Minor暂留：没有R02时的通用模板建议仍部分沿用扫描措辞，后续按R05/R06细化。该文案不改变规则事实、结构化反向线索、对比或引用；没有把此项隐称为已修复。

真实LLM/供应商费用、知识条目、正常基线来源独立核验、Linux/socket实际采集、独立检测/路径指标及发布部署仍未验收。context_only不证明无攻击；连接起始计数不是逐秒速率；Agent已核查集合变化不表示全快照图事后新增因果。

验收结束已执行scripts.pg_sandbox stop，输出server stopped；保留测试库/角色和数据目录，没有删除业务数据。浏览器脚本已退出自行启动的API/worker/Vite及协议桩。
