# D1验收记录｜2026-11-14

状态：软件骨架与结构契约已验证；D1外部条件检查未全部完成，见environment-baseline.md。

## 实际执行与结果

| 检查 | 结果 |
|---|---|
| `.venv/Scripts/python -m pytest -q` | 23 passed，含API、配置、事件/证据/图边/结论/预算、稳定ID和夹具哈希 |
| `python -m ruff check .` | All checks passed |
| `python -m ruff format --check .` | 使用最终检查入口验证 |
| `python -m pip check` | No broken requirements found |
| `python -m apps.worker` | 输出d1/preflight_only、model_provider=disabled、queue_implemented=false后退出 |
| `npm run typegen` | 从Pydantic导出的JSON Schema生成TypeScript成功 |
| `npm run typecheck` | tsc无错误 |
| `npm run lint` | ESLint无错误 |
| `npm run build` | Vite生产构建成功，15模块，JS约223KB（gzip约70KB） |
| 安装后npm审计 | found 0 vulnerabilities；覆盖minimatch 11.0.1后 |

Python命令均使用本项目.venv，不使用全局包。锁文件记录实际安装版本；前端build产物在被忽略的dist目录。当前无Git提交标识（目录尚未初始化仓库），不伪造提交与团队签字。

## 测试先行及审查修复

初次pytest因apps/packages尚不存在失败；实现后21项通过。夹具测试先因manifest缺失失败，生成后22项通过。独立审查指出process_guid跨来源绕过和会话原文缺证两项；新增测试分别出现DID NOT RAISE及session不一致，修复后全套23项通过。

结构校验已证明无时区时间、非法IP/端口、未知字段、缺必需payload、弱PID伪强身份、无证据观察边/事实、非法工具名、超预算配置等会被拒绝。没有证明现实攻击检测或Agent推理准确性。

## 未执行或待团队条件

- 真实Linux进程生命周期采集与三源真实日志联动。
- 获准模型接口的JSON/工具决策连通性与成本测试。
- Docker/PostgreSQL、数据库迁移、上传封存、规则、路径、报告语义验证、权限与恢复。
- Linux/WSL2、Python3.12、浏览器交互端到端和目标分辨率人工视觉验收。
- 具体竞赛规则、真实数据授权、人员领取任务与团队契约复核。

复验入口：项目根目录执行`./scripts/check-d1.ps1`。该入口失败立即停止，不会因最后一个命令成功掩盖前面检查失败。
