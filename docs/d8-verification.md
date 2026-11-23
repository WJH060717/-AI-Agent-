# D8 验收记录

日期：2026-11-15；环境：Windows，项目D:/挑杯，无Git提交标识。Python3.13.5，PostgreSQL16.16，Node22.17，Vite8.3.8；沿用锁定依赖，未新增包。

## 审查前已完成检查

- `./scripts/check-d8.ps1`：274 Python测试通过（110.48s），Ruff检查/格式、pip check、契约生成、前端typegen/typecheck/lint/build均通过。日志artifacts/d8-check.log。
- `.venv/Scripts/python -m scripts.test_postgres`：89集成测试通过（102.88s），迁移保留既有workspace，应用DDL/只读写入/凭据读取被拒；随机独立测试数据库，未操作业务库。日志artifacts/d8-postgres.log。超时测试桩有一条连接关闭时的HTTP服务线程堆栈，pytest结果仍通过，未当作零噪声执行。
- `.venv/Scripts/python -m scripts.browser_d3 --day8`：1通过（14.4s）；缺证9→9、零模型调用降级、新调查9→11、仍保留未知。
- 独立最终审查已完成：2项Important已通过RED→GREEN修复，无Critical或Minor。最终结果见末节，本节保留预审历史。

## 需求与用例映射

| 要求 | 验证 |
|---|---|
| REQ-003 六规则/冻结 | test_d8_rule_matrix 12场景；test_d8_evaluation语义漂移/格式不变；保留各规则已有边界反例 |
| REQ-005 有限谓词/引用 | test_d8_validation六谓词正反、bool/float/缺字段、原始定位、自由注入文字；D6伪路径/反向事实/未检索ID |
| REQ-005 修复/降级 | test_d8_agent本地HTTP：假ID、真实ID相反事实、scope注入、一次修复成功和两次拒绝；D6预算/超时/取消/恢复回归 |
| REQ-006 缺证/校验页面 | d8.spec.ts真实API/worker/浏览器，截图missing-evidence.png与closed-loop.png |
| REQ-007 限流/安全错误 | test_d8_api并发额度、读写/身份隔离、429无业务写入、窗口恢复/容量、401/404/422/413/500信封 |
| REQ-008 划分/输入核验 | test_d8_evaluation父子/同组/同哈希跨split、循环/缺父/重复ID、路径逃逸、原始哈希损坏 |

## 数据与声明

冻结配置SHA-256：b87ec82958653f65e745deb82107ae9ee0ef08377838c8e2aa7e8d97a6bdb6ab。eval/runs.json包含33项planned（12/6/12/3），3个prepared开发输入包、1个已准备开发组；没有正式test执行、独立统计或采集完成声明。清单各原始输入哈希可由eval.inventory复核。

本日全部模型流程为明确标记的回环协议桩或deterministic，不是实际LLM。API额度只单进程；报告有限校验不是完整攻击因果证明；正常进程仍不证明流量归属。真实数据/知识库/完整发布门禁待后续。

## 最终审查修复

1. `auth_outcome`缺失资产可能被字符串None匹配：新增合法资产/缺资产正反例，先复现失败，再加真实asset_id非空条件。六谓词正反矩阵均保留。
2. 原始证据读取时损坏后，缺证面板仍称校验完成：真实MissingEvidence组件SSR+浏览器断言先复现失败；现优先按当前report.validation警告，历史生成摘要不改写。集成测试验证原始内容恢复后可重新核验、数据库中报告始终不变。

独立审查仅一次；修复由主执行者测试确认，不声称独立重复测试背书。所有边界裁定在d8-implementation.md。

## 最终版本已完成检查

- Python全套277 passed（107.96s），日志artifacts/d8-final-check.log；这次组合命令随后停在新增测试的一处导入排序。仅修正导入空行后，Ruff/格式检查均通过，未修改产品逻辑。
- 剩余门禁日志artifacts/d8-final-remaining.log：Ruff、格式、pip check、前端typegen/typecheck/lint/build通过。新增SSR回归的Report夹具曾因空数组类型推断未通过tsc，改为使用生成Report类型后通过；没有放宽产品契约。
- PostgreSQL16.16最终90 passed（101.60s）；迁移保留既有workspace、应用DDL/只读写入/凭据读取拒绝检查通过。最终这一轮未出现预审连接关闭堆栈。
- 最终浏览器：D3 1 passed（7.0s）、D4 1（9.6s）、D5 1（12.4s）、D6 1（16.7s）、D7 1（11.8s）、D8 2（14.7s）。总计六条端到端闭环加一项真实组件SSR/浏览器回归，不把组件回归算作第二条D8端到端场景。
- `scripts.pg_sandbox stop`退出0，显示server stopped；浏览器脚本各自清理所属子进程。随机测试数据库/角色保留，未删除业务数据。
- Node报告NO_COLOR与FORCE_COLOR同时设置的颜色提示，不影响断言。最终剩余门禁进程退出0。

组合命令首次在Ruff处停止，随后在未修改产品逻辑的情况下修正测试导入排序/夹具类型，并从静态检查继续完成全部剩余门禁；本记录不把首次命令伪报为一次性全绿。最终代码的所有门禁均有实际通过记录。

D8工程实现已完成；独立审查两项Important均修复，无遗留Minor。完整三周P0发布门禁与33次实际采集/正式评估未提前宣称完成。
