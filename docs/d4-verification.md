# D4验收记录｜2026-11-14

范围：Linux collector结构化JSONL、身份/时间约束、R02和D3回归。实现与规约调整见CHG-004及d4-implementation.md，演示步骤见d4-runbook.md。

复验记录时间：2026-11-14 19:13（Asia/Shanghai）。开发manifest SHA-256：`c8f1de4beba2736bb8c2ab276d2f9e693291810361e40304c654f6b765308225`。

## 最终执行结果

| 验证命令 / 对象 | 实际结果 |
|---|---|
| `./scripts/check-d4.ps1` | 76项pytest全部通过；Ruff检查及105文件格式通过；pip check通过；Schema/OpenAPI导出、typegen、typecheck、ESLint、Vite build通过 |
| `python -m scripts.test_postgres`（使用.venv） | PostgreSQL16.16独立随机库，D2→D4迁移保留既有workspace；受限app账号27项集成测试全部通过 |
| 数据库权限 | app不能DDL；reader不能写events、读role_tokens或workspace_private_keys；两张新表应用禁止UPDATE/DELETE |
| `python -m scripts.browser_d3` | Chromium真实点击R01旧闭环通过，结果文件status=passed |
| `python -m scripts.browser_d3 --day4` | Chromium真实点击配置上下文→三源上传→R02→快照/图/模板→脱敏原始行，通过，结果文件status=passed |
| 合成三源输入 | 6网络+6认证+3audit物理行→13规范事件；图23节点、14边，其中通信6、authenticated1、associated_process1、corresponds_to推断6 |
| 重复摄取 | 同audit文件重导不增加session事件；原报告/事件保持不可变 |
| audit恢复 | 502物理行，SYSCALL第1行、EXECVE第501行、EOE第502行；500行检查点后租约接管；最终1事件/3聚合记录/499隔离，精确引用[1,501,502] |
| audit完整性 | EOF缺EOE/EXECVE保留弱partial；257组非exec跨500行完整归一；原生ID内容冲突逐行隔离，不计duplicate、不覆盖原事件 |
| R02 | 正例及乱序通过；不同账号/来源IP/服务/目标/boot/realm、4失败、成功先于失败/超过120秒、弱账号、时间不确定、多传感器重复观测反例通过 |
| 身份/时间/图 | PID复用、boot复用、后续exec不抹去出生证据；重叠时间不造父子边；IP半开区间/校时/歧义；五元组/域/资产/有界时间正反例通过 |
| 证据分页/权限 | 22片段按20+2返回，篡改游标拒绝；原始用户名/命令不复制到派生记录；context无配置拒绝、不可变/幂等、viewer越权403 |

浏览器输出在artifacts/d3-browser及artifacts/d4-browser，各含closed-loop.png、playwright.log、services.log、results/.last-run.json。D4截图已实际查看，验证分辨率1440×1000；更多分辨率/复杂大图未做完整视觉验收。便携PostgreSQL测试实例最终已停止；随机测试数据库未用作业务库。

输入版本：data/fixtures/d4/manifest.json记录每个开发JSONL的SHA-256及context哈希；schema1.0/1.1、linux_auth-json@1.0.0及linux_audit-json@1.0.0（派生校正后附identity版本）、R02@1.0.0、evidence_graph@1.0.0、template@1.1.0。没有Git仓库，故无提交ID、分支或远程合并记录；自动审查不代替团队人工签字。

## 测试先行与独立审查

初始适配器/规则测试因实现缺失失败，再逐项实现。证据分页先复现22行未限制为20行，修复后20+2与篡改游标用例通过。

独立只读审查发现三项Important，全部先加入失败测试，再修复并运行全量：

| 问题 | 失败证据 | 修复与覆盖 |
|---|---|---|
| 独立传感器观测凑足R02 | 1失败×5传感器+1成功错误触发 | 分组加入sensor_id/instance_id；test_r02_independent_sensors_do_not_multiply_one_failure |
| 非exec组一直pending | 257组create只接收256组，2行被隔离 | 按action判断完成条件，检查点只增加安全布尔元数据；test_complete_non_exec_audit_groups_release_pending_capacity |
| 同nativeID内容变化被计重复 | pid42与999共用ID，accepted1/duplicate1 | 比较去除ingested_at/source_locators后的规范语义，冲突片段NATIVE_ID_CONTENT_CONFLICT隔离；test_native_audit_identity_collision_is_quarantined_not_counted_duplicate |

修复后相关19项通过，再执行最终76项全量、27项PG及R02浏览器验证。浏览器前两轮测试定位分别受导航序号和宽泛正则影响，已根据实际可访问名称改为准确角色/候选列表定位，未通过屏蔽后端错误解决。

## 边界与待续

- 本日交付明确的collector JSONL协议，不是任意发行版原生auth.log/audit.log解析。HTTP跨旋转文件manifest和跨批次未闭合audit合并留T-07；底层显式多对象片段能解析，不宣称HTTP自动拼接。
- 不完整audit只保留弱候选；缺可靠出生标记/boot不造强进程；session缺失不造会话边。真实collector提供的身份/出生声明仍需采集侧可信度验证。
- 当前调查上限250事件，服务层验证全部事件；底层图入口超过500的独立扩容未做。没有吞吐量、准确率或真实攻击成绩声明。
- Agent、因果攻击路径、R03–R06、任意命令执行、在线采集、Docker集成未在此日验收。
- Minor deferred：R02报告recommendations字段仍有“核查扫描授权”通用建议文案，后续按认证场景细化；R02规则事实、摘要、替代解释与证据引用正确，页面当前不展示该字段。
