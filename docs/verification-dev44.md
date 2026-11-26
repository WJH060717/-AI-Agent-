# dev44 验证记录

日期 2026-11-26。应用 `0.1.0.dev44`，数据库迁移 `0006_d9`。本轮覆盖用户列出的跨源快照、socket 证据、策略、实验台账、纯失败认证规则、知识/图、工作台、容量、CI、README 与许可清单。

## 改变的行为

1. **调查快照跨源**：调查保留 incident 全部 finding 的种子，并在同工作区/数据集/会话/时间窗、可信资产映射和允许观测域内纳入网络、认证、进程、告警上下文。`InvestigationScope.selection` 记录来源/类型/原因计数、逐事件原因、覆盖状态和限制；超种子/扫描上限显式 422，上下文超限按优先级取舍并标 `partial`。
2. **主机 socket 证据**：新增 `linux_socket` 来源和 `host.process` 的 `socket` 绑定。强 boot/出生标记/身份才形成 `opened` 边；PID 复用、重启、弱身份、端口/域不匹配不连边；删除 socket 记录保留 `missing_socket_binding` 断点。
3. **逐类策略**：新增 `scan_activity@1.0.0`、`dns_answer_conflict@1.0.0`、`arp_mapping_conflict@1.0.0`，输出支持/反证/空结果/缺失字段/工具/停止条件和有限状态校验；建议只来自种子与已完成工具返回。
4. **纯失败认证**：新增独立 R31，按服务/资产/脱敏账号/来源/事务去重，区分单账号高频与多账号喷洒；有成功记录时不抢 R02 语义；输出不证明字典使用或登录成功。
5. **知识/图**：知识目录改为 manifest 驱动，允许非六条并显式列出未映射规则；新增 DNS 事务、ARP 声明冲突、TCP SYN 端口三类包级关系投影，边带域、时间范围、方法和限制。
6. **容量**：新增 `scripts/measure_capacity.py`，分别测 1k/10k/100k 检测，不等同调查规模。
7. **工程化**：公开/私有测试分组、CI、可重复 demo 准备、README/能力索引、许可与第三方清单。

## 实际验证

- Python 全量公开回归：**998 passed，93 skipped，0 failed，615.01 秒**（`tests/contract tests/unit tests/integration`）。跳过项全部是缺失私有归档/历史发布材料的模块，原因由 `tests/conftest.py` 写成 `PRIVATE_MATERIAL_MISSING`，不是收集错误。
- 新增测试：socket 3、策略 4、R31 3、跨源快照 1、知识 manifest 1；另有 R31 freeze、旧路径/规则回归通过。
- 前端：`npm run typegen`、`npm run typecheck`、`npm run lint`、`npm run build` 全部通过；构建产物 27 modules，285.29 kB JS（gzip 87.81 kB）。
- 容量：1,000 / 10,000 / 100,000 条合成检测分别 0.103s / 0.734s / 9.817s，峰值 0.24 / 2.08 / 23.46 MB；见 `docs/capacity-dev44.json`。
- 演示准备：`python -m scripts.demo_prepare --root <new>` 在临时新目录成功创建 SQLite、上下文、4 个来源导入和一次性令牌；未启用模型。
- 台账：`python -m scripts.validate_ledger` 返回 `{"valid": true, "runs": {"planned": 33, "prepared": 3}}`。
- 许可/第三方：`LICENSE`、`LICENSE-STATUS.md`、`THIRD_PARTY_NOTICES.md` 已建立；整体许可仍待权利人确认。

## 限制与未验证

- 没有独立授权多源活动链、双人标签、真实模型费用和正式 B0–B3 预测；`eval/current-ledger.json` 不把 33 planned/3 prepared 当作已运行。
- socket 适配器只在合成 JSONL 上验证，未接真实 Linux collector；设备时钟/身份可信度仍需采集侧验收。
- DNS/ARP/SYN 图投影是有界启发式；不证明 DNS 欺骗成功、ARP 中间人转发或扫描恶意。
- 前端只做类型/lint/生产构建；未在本轮重跑隔离 Playwright 报告流程，20/100 节点交互需浏览器人工复核。
- 未在干净非作者机器、物理断网、Docker Compose 或现场 8 分钟彩排验收。
- CI 工作流已提交但尚未在 GitHub Actions 实际运行；首次运行结果另行记录。
