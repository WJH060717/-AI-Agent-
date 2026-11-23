# D2验收记录｜2026-11-14

## 实际验证

| 检查 | 观察结果 |
|---|---|
| 全套pytest | 33 passed（23项D1回归+10项D2集成） |
| PostgreSQL16.16 | 10项集成测试通过；使用新建隔离测试库的受限应用账号 |
| PostgreSQL角色边界 | app建表、reader写events、reader读role_tokens均拒绝 |
| Alembic | 空库升级0001_d2、重复upgrade无重建；JSONB用于PostgreSQL |
| 导入主线 | 上传Zeek8条+1坏行→queued→worker→accepted8/quarantined1→查询8条 |
| 重传 | 同键返回原batch，同键变内容409；新键重传→accepted0/duplicate8/quarantined1 |
| EVE | 原生signature_id/severity映射；带offset时间归一化；大flow_id转字符串 |
| 数据安全 | viewer上传403；其他工作区查不到事件/批次；token仅摘要入库 |
| 原始完整性 | 引用匹配真实原文哈希；手工改归档后核验失败 |
| 有界查询 | 游标分页无重漏；坏签名/跨scope游标拒绝；不把前100条当全量 |
| HTTP大小 | 无Content-Length的超大multipart也返回413 |
| 前端 | typegen、tsc、ESLint、Vite构建通过；实际HTTP流程由集成测试验证 |

## 测试先行与审查

最初集成测试因create_app/存储包未实现失败；实现后权限反例发现422先于角色检查，改为依赖级admin验证后通过。实际分块上传测试证明旧实现仅看Content-Length不足，加入ASGI字节计数后通过。图与工具测试先因模块不存在失败，随后用实际解析事件验证观测边与原始片段。

独立审查指出EVE畸形嵌套字段会触发AttributeError、只读工具仅查前100条可能误报空结果。已增加三项畸形混合好坏行测试并先观察失败，再在解析器校验类型；工具遇后续分页明确拒绝。审查者独立运行33项测试通过。归档后续改为.partial→fsync→哈希→rename，不在复制完成前发布。

## 限制与未执行项

没有浏览器人工视觉/E2E验收，没有运行Docker模板；本机没有Git仓库，故无提交ID或团队签字。真实Linux采集、主机解析、持续作业恢复、冻结快照、检测与Agent仍为后续任务。D2不报攻击检测准确率或性能达标。

初次PostgreSQL初始化因受限令牌及中文路径失败，改用用户临时目录的ASCII路径后成功。第一次测试遇pytest缓存ACL警告，隔离PG入口禁用cacheprovider；后续10项运行无该警告。一次文件哈希重构遗漏Path导入，检查及时发现并修复，最终结果以完整复验入口为准。
