# 离线评估边界

仅离线评估程序可读取本目录。API、检测器、图与Agent不得导入eval或读取标签。

D8提供`runs.json`及`.venv/Scripts/python -m eval.inventory --output artifacts/d8-inventory.json`。这是分组、谱系、文件完整性和配置冻结预检，不运行正式test或计算检测效果。

33项planned预约：dev12、val6、test12、demo3，尚待采集/标注/双人复核。额外3个prepared是既有D3/D6/D7开发输入包，同属一个legacy回归组；prepared不表示运行完成、独立样本或标签质量验收。

新增原始运行先指定activity_group/split；派生或回放声明parent_run_id且保持同组同split；prepared需要相对项目根目录的文件路径及实际SHA-256。拒绝跨split原始哈希复用、谱系循环、路径逃逸、文件损坏。语义近重复和未声明谱系仍需人工复核。

D8后六规则阈值冻结于rules/freeze.json。正式test只评一次冻结版本；查看test定位问题后，该集不能再称完全未见。完整任务和边界见docs/d8-runbook.md、docs/07-evaluation.md。
