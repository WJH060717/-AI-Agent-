# 知识边界

精选ATT&CK条目后续在此版本化。每条记录来源URL、实际版本、对象ID和内容哈希；知识引用不能代替本次事件证据。
# P1 已加载精选知识

`attack-18.1/` 固定官方 MITRE Enterprise ATT&CK 18.1（不是“最新”）。来源提交 `b4eb2b84c02b84bb4cceb71c97ae05cb2f33ab38`，下载时间、原始文件 URL/SHA256 见 source.json；版权许可见 LICENSE.txt。

catalog.json 包含 R01–R06 对应 T1046、T1110、T1059.004、T1021.004、T1071、T1041。source-objects.json 保留对应 Technique、Detection Strategy、Analytics、Data Component 及 detects 关系原对象；freeze.json 绑定字节摘要。技术与检测映射源于固定官方资料，中文适用观测/正常替代为本项目的谨慎摘要，不能当作现场事实。

运行时只读取 catalog 的白名单字段，精确 ID 去重匹配最多 5 条；无匹配、关闭、完整性错误分别返回显式 warning。未实现任意全文检索或外网获取。knowledge_ref 绑定整个目录内容，报告引用必须来自同 run 已完成工具返回；知识不会加入 event evidence/retrieved/before。修改目录或开关会改变缓存及恢复身份。

离线检查：`.venv/Scripts/python -c "from packages.knowledge.catalog import verify_sources; print(verify_sources())"`。重建工具 `scripts.build_p1_knowledge` 只接受固定源摘要并写新目录，禁止原地覆盖。正式版本升级应另建版本、更新源依据并回归。

以下为早期规划记录：

