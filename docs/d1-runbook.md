# D1运行说明

当前已实现：可安装Python骨架、类型化配置、API存活接口、worker配置预检、事件/证据/关系边/报告/Agent决策与预算契约、24条合成样例及哈希manifest、Schema和TypeScript生成、四页前端导航。

当前阶段：开发骨架。没有数据库、上传解析、检测引擎、图搜索、真实Agent工具调用或生成报告。页面不读取合成数据伪装成真实调查；卡片中的24条为夹具文件清单。

## Windows PowerShell

在项目根目录执行（当前机器的依赖已安装）：

```powershell
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements-dev.lock
Copy-Item .env.example .env
.venv/Scripts/python -m scripts.build_d1_fixture
.venv/Scripts/python -m scripts.export_contracts
.venv/Scripts/python -m pytest
.venv/Scripts/python -m ruff check .
.venv/Scripts/python -m ruff format --check .
.venv/Scripts/python -m apps.worker
.venv/Scripts/python -m apps.api.main
```

API启动后访问 http://127.0.0.1:8000/docs 查看实际OpenAPI。存活接口为`/api/v1/health/live`，不代表数据库或模型就绪。worker只打印预检结果并退出，不会消费队列。

已安装依赖后，一次性复验可在根目录运行`./scripts/check-d1.ps1`，任何步骤失败即停止。

另一个终端进入`apps/web`：

```powershell
npm ci
npm run typegen
npm run typecheck
npm run lint
npm run build
npm run dev
```

打开Vite输出的本地地址，通常为 http://127.0.0.1:5173 。API必须另行启动，否则页面显示API未连接。Linux/WSL2使用`.venv/bin/python`替代Windows路径；当前尚未验证Linux和Python3.12运行。

## 契约入口

- 唯一来源：`packages/contracts/models.py`。
- 生成物：`packages/contracts/generated/contracts.schema.json`、`contracts.ts`和`openapi.json`。
- Schema只校验结构；EvidenceRef在当前工作区是否存在、谓词是否与事件一致，必须由后续服务验证，不能仅凭`model_validate`判定报告可信。
- 用`NormalizedEvent.model_validate_json(line)`验证事件。先构造SourceLocator，再用stable_event_id生成ID。原生ID需同时给instance_id。
- 改契约后重新export、typegen，再运行前后端检查；生成文件不要手工编辑。

## 最小样例

`data/fixtures/d1/manifest.json`记录来源、条数和SHA-256；四个原始JSONL分别模拟Zeek、auth、audit、Suricata，总24条。`events.jsonl`为预制规范事件，**不是生产解析器的输出**；生成器仅用于D1测试。强进程身份也是合成的，没有证明真实Linux采集已满足要求。

夹具仅用于开发，不作测试集或竞赛实测成绩。真实采集、模型连通与竞赛规则核查仍需团队提供授权环境/条件后落实。

## D2入口

先建PostgreSQL迁移与repositories，确认dataset/session作用域；实现staging上传与worker封存；从Zeek小样例开始写真实解析器，验证事件→原始位置→哈希回溯。前端复用生成类型，按实际API替换空态。
