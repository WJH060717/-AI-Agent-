# 迁移边界

已实现0001_d2，冻结表定义在packages/storage/schema_v1.py；空库升级和重复升级已在SQLite/PostgreSQL验证。后续变更必须新建revision，不修改冻结定义。禁止直接重建用户数据库，禁止生产用app角色执行DDL。

D3新增0002_d3与schema_v2冻结定义，升级保留D2工作区。新表授权参考infra/roles.sql；app对快照/报告/事实表仅追加与读取，不给覆盖权限。
