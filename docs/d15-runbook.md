# D15 本地交付与核验手册

D15交付是固定D12应用/D14离线环境的工程候选，正式P0发布仍阻断。只做本地封存；没有上传比赛系统、发布网站或联系成员。本轮候选号以外部freeze和最终验证记录为准。

## 接收与打开

1. 从独立可信来源取得同名ZIP与外部`d15-candidate-NN-freeze.json`；对照其中zip_sha256计算ZIP摘要。freeze不是数字签名，攻击者若能一起替换ZIP/摘要，单纯hash不能证明来源。
2. 解压到全新目录，先打开`START-HERE.html`，可直接进入展示页、两段预录、真实报告和历史分析页。不要把私有备份或运行目录放入候选。
3. 在已安装Python的终端进入解压目录运行下面的独立校验器。读取外部freeze中的manifest_sha256，不从待校验包自行生成期望值。

```powershell
Get-FileHash .\d15-candidate-01.zip -Algorithm SHA256
Expand-Archive -LiteralPath .\d15-candidate-01.zip -DestinationPath .\d15-candidate
Set-Location .\d15-candidate
python -I .\verify.py --expected-manifest-sha256 <外部freeze的manifest_sha256>
python -I .\verify.py --strict
```

普通校验exit0仅表示交付内容完整。`--strict`在完整性通过后仍打印七项未关闭P1、p0_release_ready=false并exit2；不是程序故障，不可为了提交而改成true。无效文件/摘要也exit2，但integrity_verified=false，必须先区分。

`SHA256SUMS`覆盖所有payload文件及release-manifest.json，外部freeze同时绑定候选ZIP和manifest；清单本身不是签名。verify.py只读，不启动数据库、模型或pip，不修改包内容。

## 安装与恢复

部署入口是`deployment/d14-offline-02.zip`，解压到另一新目录再按其README-offline.md运行offline.py。目标须已有**Windows x64 CPython3.13**；34个锁定wheel随包，无Python/OS/Docker镜像。默认模型disabled。安装初始化令牌只保存在私下，不录屏或加入交付包。

实际备份、空目录恢复、第三目录回退命令见`materials/docs/d14-runbook.md`；私有整库含HMAC和令牌摘要，不能公开。回退只能回到备份高水位，备用目录后续新调查需保留，不自动合并。D14同机自动演练不替代独立备机、非作者和物理断网。

## 实验归档与复算

`evaluation/`包含D12证据ZIP的原字节内容：所有清单列出的工程执行/失败、三轮D11性能原始样本、输入清单及分析输出。`evaluation/artifacts/d12-check-04/analysis/index.html`可直接打开。历史版本范围、正式标签/账单缺失不可抹掉。

需要复算时，在另一新工作目录解压部署包，使用其中kit/app作为源码根，将evaluation中的artifacts、eval/d12-inputs.json和release/d11-freeze-03.json按原相对位置放置。不要覆盖现有工作区；不要把eval目录挂到运行Agent。用已核验环境执行：

```powershell
python -m eval.analysis_d12 --manifest eval/d12-inputs.json --output artifacts/d15-recomputed
python -m eval.analysis_d12 --output artifacts/d15-recomputed --verify
```

D15实际复算的目标与结果见外部验证记录；不重跑30分钟基准、不把历史D11速度当作当前测量，也不生成正式F1或真实LLM账单。

## 本地重建

在当前完整工作区使用`.venv/Scripts/python.exe -m scripts.build_d15 --output release/d15-candidate-new`。输入固定三个已归档ZIP及明确白名单文档；已有输出/ZIP/freeze拒绝覆盖，失败目标保留。修改工具或文档后必须换候选名并重新验证，不编辑已封存文件。
