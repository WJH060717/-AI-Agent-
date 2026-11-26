# 知识边界

`attack-18.1/` 固定官方 MITRE Enterprise ATT&CK 18.1（不是“最新”），来源、版本、许可、对象摘要和文件哈希均在目录内冻结。知识引用不能代替本次事件证据，也不能证明真实操作者或意图。

## 当前 manifest

`manifest.json` 是 `knowledge-manifest@1.0.0`，绑定：

- `catalog.json` 的 SHA-256 与 `knowledge_version`；
- 现有 R01/R02/R03/R04/R05/R06 的技术映射；
- 显式 `unmapped_rules`（R07–R31 中尚未可靠映射的规则），不再要求目录恰好六条；
- 许可、来源和限制说明。

`packages/knowledge/catalog.py` 只读取白名单字段，最多返回 5 条；未知技术 ID 返回空，不强行映射。manifest、catalog 或 freeze 漂移会使完整性检查失败。

## 运行边界

运行时只读本地目录，不联网、不读取 eval/ground_truth，不把知识条目加入事件证据。`knowledge_refs` 必须来自同一 run 已完成的工具返回；目录/开关影响缓存与恢复身份。知识解释与现场证据分开显示。

## 离线检查

```powershell
py -3.12 -c "from packages.knowledge.catalog import verify_sources; print(verify_sources())"
```

重建工具 `scripts.build_p1_knowledge` 只接受固定源摘要并写新目录，禁止原地覆盖。历史 `attack-18.1` 保持不变；升级另建版本并更新 manifest。
