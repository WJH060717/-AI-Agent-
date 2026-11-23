# D13 验证与交付记录

执行日期2026-11-15。D13是部署/展示增量，应用固定为D12 candidate-04（0.1.0.dev12，迁移0006_d9），没有更改运行时、规则、Agent或API。无Git仓库，版本定位用不可变文件摘要；未远程提交/发布/联系团队。

## 实际通过

| 验证 | 实际结果 / 证据 |
|---|---|
| 安装边界正反测试 | **22 passed，87.50秒**；artifacts/d13-final-tests.xml、d13-review-green.log |
| 静态检查 | 四个新增Python工具与测试Ruff/format通过；录屏JS的node --check通过 |
| 固定底座与打包 | 325个原D12源码文件保持；D13套件505文件+manifest=506ZIP条目；943016字节；实际解压核验通过 |
| 新环境 | 两次同机新目录安装；最终kit-02创建全新venv（不继承system-site-packages）、新SQLite、锁定34依赖、空库迁移、pip check与preflight成功 |
| 配置隔离 | 实际注入DATABASE_URL/模型变量后status仍使用自身库、disabled；原哨兵字节未变 |
| 浏览器真实流程 | 最终全新库S1为37事件、S3为9事件，两次调查；**41次API响应，0个HTTP错误**；引用查看、JSON/HTML导出、cached/原时间显示；无外部模型调用 |
| 重启与持久化 | 录屏服务结束后，通过包内deploy.py run重启API；原令牌有效、旧报告逐字段一致；库仍46事件/2调查 |
| 视频 | **479.2秒（7:59.2），2,588,582字节，1280×800/10fps**；无配音，中文字幕，自动预录/合成/disabled常驻标注 |
| 展示/许可资料 | HTML 8个本地链接检查通过；截图与成片图谱/结尾逐帧目检；198依赖条目、166份可取得许可原文，38条无文本（包含未装平台可选项），不等于法律审核 |
| 敏感信息与旧证据 | 公开D13工件逐文件扫描初始化令牌的精确字节，未发现；截图另做视觉核查。D12原250项证据可按原hash找回，源文档变动的旧字节留存 |

底座D12的422 Python/123 PostgreSQL/6浏览器结果是历史验证，本轮没有重新计为D13成绩。D11历史性能同样没有冒充本轮新测。真实LLM、正式F1、真实账单均未知。

## 可交付工件

- `release/d13-kit-02.zip`：部署套件，SHA-256 `9d33ff185d2b38a684988b700ff62bbc8fc976266ed690c0ff22e822dfb99e57`。
- `release/d13-demo-8min.webm`：成片，SHA-256 `5c4780a011aed4d64e3b1afc773aa723e4f3a2cea16fa25aee7929ebd32b28b3`。
- `release/d13-kit-02/showcase.html`：本地展示页；六份手册/场景/答辩/演示/限制/待签署表及dependency-notices随套件。
- `release/d13-materials.zip`：部署ZIP、成片/字幕、截图/脱敏报告、D13工具/测试源码、手册、验证证据与独立D12历史分析包。
- `artifacts/d13-build-manifest.json`：本轮文件/摘要、验证与剩余状态索引；包摘要不是数字签名。

底座freeze规范化摘要：`9110dae9674ddedb75f08e538466df68ec9ff6e4b38eac5720f64fcd8ca11673`。它与D13套件版本分开，不将展示资料变更伪装成应用版本更新。

## 验证命令

```powershell
.venv/Scripts/python -m pytest tests/unit/test_deploy_d13.py -q --tb=short
.venv/Scripts/python -m ruff check scripts/deploy_d13.py scripts/build_d13.py scripts/notices_d13.py scripts/record_d13.py tests/unit/test_deploy_d13.py
.venv/Scripts/python release/d13-kit-02/deploy.py verify
.venv/Scripts/python release/d13-kit-02/deploy.py status --target .tools/d13-runtime-02
```

独立安装、服务启动和停机手册见d13-runbook.md。开发者重录需要本机Playwright与私有初始化日志，命令为 `python -m scripts.record_d13 --target <已安装私有目录> --private-install-log <私有初始化日志> --output <新的工件目录>`；不要为了重录把令牌写进公开参数或日志。最终轮原始视频和services.json/recording.json在artifacts/d13-record-full-02。

## 失败与修正记录

最初测试缺模块RED；14项实现后GREEN。独立审查发现：可变清单批准额外代码、打包路径检查过晚、录屏可能连接旧服务；8个新增反例实际失败，再一次修复，最终22项通过。未复审冒充第二签字。

录屏试跑01因错误health路由404失败，修为真实/api/v1/health/live；试跑02发现字幕受aside全局样式影响，03修正并视觉验证。审查前full-01保留，最终采用修复后的full-02。编码器关闭时追加重复尾帧，原片保留；成片只取前479.2秒、原速转码10fps，无加速/拼接调查，无替换报告。实际操作计时479.016秒，结尾帧包含最终限制字幕。保留编码命令与日志。

首次收尾只读检查误用内部变量名runs作为表名，失败保留在d13-finish-checks.log；核对实际schema后改查investigation_runs，第二次包内CLI重启/旧报告/46事件/2调查验证通过。此前已生成的成片不重写。

## 尚未验收

**D13集成目标“非部署作者独立按手册启动”仍pending。** 本机新venv不是干净机器；自动化不是非作者。Docker引擎不可连接，Compose未运行；Linux/Python3.12未实测。真人配音/计时彩排、现场断网、备机/回滚待后续；许可证最终权利人确认仍待完成。

沿用七项未关闭P1：D10-001/002/003/004/005/006/009。TC-021/036/037/038/039/040仍不完整，**完整P0发布未就绪**。本轮没有手填strict通过或代签，也没有将旧D12 strict exit2说成本轮新执行。
