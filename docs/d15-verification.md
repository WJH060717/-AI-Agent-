# D15 验证与本地封存记录

执行日期2026-11-15。D15已完成本地工程交付构建；应用保持0.1.0.dev12、0006_d9。候选为`d15-candidate-01`，不等于完整P0发布批准或真实比赛提交。未修改旧应用、证据、数据库或密钥；无Git仓库，版本以内容摘要定位。

## 实际结果

| 检查 | 实际结果 |
|---|---|
| 新工具正反测试 | **25 passed**，0错误/失败；命令`.venv/Scripts/python.exe -m pytest tests/unit/test_delivery_d15.py -q --junitxml=artifacts/d15-final-tests.xml`，输出artifacts/d15-final-tests.log/xml |
| 静态检查 | build_d15.py、verify_d15.py、test_delivery_d15.py Ruff/format通过；docs/d15-open.mjs node --check通过 |
| 候选/外部freeze | 154文件/ZIP条目，31583121字节；固定D14部署ZIP含546条目；所有文件摘要及ZIP CRC实际通过 |
| 独立解压核验 | 全新.tools/d15-extracted-01实际解压；python -I verify.py使用外部manifest摘要，exit0；--strict实际exit2、p0_release_ready=false，保留七P1 |
| 文件可打开 | JSON/JSONL/XML/SVG/Python源码/UTF-8文字解析通过；112个HTML本地链接/锚点核对通过 |
| 浏览器实际打开 | 入口、展示页、两份脱敏报告、历史分析页；26张PNG全部解码；两个479.2秒视频实际解码/播放/跳转；pageerror为0，外部请求阻断 |
| 历史分析复算 | 从交付包提取固定应用源码和历史输入，在新目录复算；9个输出（含manifest）与归档逐字节相同；未重跑性能基准、未启动Agent、无正式指标 |
| 来源与隐私 | 固定三个公开来源SHA；候选文件及部署ZIP成员未发现私有角色令牌；私有库/备份/HMAC未打包 |
| 历史保护 | D14的146项、D13的134项、D12的250项仍可核对原字节；六份根文档D14原版另存artifacts/d14-source-preserved-for-d15 |
| 独立审查 | 一次只读代理审查；结果及处理见artifacts/d15-review-resolution.json；未解决Critical/Important为0 |

ZIP SHA-256：`f704e5dee641963d2cdd7b626dd338d6dc8da1519f6193662df5070d412ce6fd`。

release-manifest SHA-256：`3057527224805a39987524db7fc7c7a69ae0e3fb42475a677424b6a218f0a969`。

外部freeze：`release/d15-candidate-01-freeze.json`。它与ZIP要从可信来源接收；hash不是数字签名。实际检查位于`artifacts/d15-check-01/`，绑定同一候选摘要，失败/旧候选保留。

## 文件、行为与交付

新增scripts/build_d15.py与verify_d15.py：明确公开输入、固定旧部署包、构建Pydantic清单、完整文件集/摘要/Windows ZIP路径检查、只读普通与strict两种核验。新增tests/unit/test_delivery_d15.py和docs/d15-open.mjs。D15文档提供实际命令、技术附件/REQ与TC定位、七P1限制、A/B/C/D角色职责及待签提交表；README、执行计划、部署说明、AGENTS与变更记录同步。

主包`release/d15-candidate-01.zip`内打开START-HERE.html，部署ZIP保持原字节，materials和evaluation保持原归档条目字节。source-catalog.json记录来源/哈希/模式。`release/d15-verification-evidence.zip`另收集实际测试、浏览器截图、复算、外部freeze和本说明；候选封存后不为塞入自己的验证结果而改写。

本轮检查是封装与可追溯性验收，没有重新运行D12全部应用测试，也没有把D11/D12历史统计改称D15实测。Windows反斜线路径问题先复现失败再修复；历史失败日志保留。

## 未验收与工作方式

完整P0仍被D10-001/002/003/004/005/006/009七项P1阻断，TC-021/036/037/038/039/040未完整。正式33次数据/双人标签、真实LLM/账单、精选知识、独立机器/非作者/Compose、物理断网与真人彩排仍待完成。角色姓名、复核签署、分发许可确认、比赛提交入口/时间/回执保持待填。没有向任何外部平台提交或联系团队。

沿用现有目录和固定应用，以内容摘要封存；不新建Git仓库、不重做应用版本；只准备本地engineering_candidate和角色待签表。所有新输出只建新路径，旧历史和私有运行副本保留。这些选择的限制是不能自动完成正式人类验收、提交及Git合入记录。
