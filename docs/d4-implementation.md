# D4实施计划

目标：Linux auth/audit结构化JSONL最小适配、身份/时间关联约束、R02失败后成功，以及R01回归。

- [x] 测试先行：账号/主机/boot/PID复用、时间乱序/偏移/不确定性、audit交错多记录/500行恢复。
- [x] 0003迁移：不可变数据集上下文、工作区HMAC密钥、audit pending检查点、物理记录/聚合事件计数。
- [x] 资产/IP有效区间及传感器时钟绑定；不得从hostname或IP直接生成强主机身份。
- [x] auth稳定账号脱敏，audit保留每个原始片段；exec时间不当出生时间。
- [x] R02及identity/time安全图关系，接现有候选/快照/模板报告；保持R01旧版本可复现。
- [x] API/前端来源与上下文导入，合成样例、SQLite/PostgreSQL/浏览器回归、独立审查与文档。

Ruling：D4最小输入为明确JSONL导出协议，不宣称已支持任意发行版原生auth.log文本或所有audit syscall。
Ruling：audit按SYSCALL/EXECVE/CWD/PATH/EOE聚合，支持单上传文件内交错和跨500行检查点；底层多片段解析可跨对象，HTTP旋转文件manifest导入仍留T-07后续，不擅自合并不同批次的已封存事件。
Ruling：不完整audit在EOF保留弱候选并标partial_audit；没有可靠出生标记不赋强进程ID，不画spawned边。命令行不复制到派生记录。
Ruling：R02需强目标资产/账号/来源，严格按不确定时间区间确认先后；session缺失仍可检测认证模式，但不造会话关联边。

实现记录：原始输入新模块/规则测试先失败，逐项转绿；证据分页先复现22行超过20限制，再加入绑定游标。73项全量/25项PostgreSQL首次通过后执行独立只读审查。

Final review：三项Important均已失败复现并修复，相关19项通过：R02加入主传感器实例；audit按动作封存；nativeID语义冲突保留原始对象并逐行隔离，不覆盖已存事件。最终全量/PG/浏览器结果见d4-verification.md。

Final: minor (deferred)：R02模板recommendations沿用“核查扫描授权”通用文案，后续按认证场景细化；事实、R02摘要、正常解释与原始引用不受影响。

Final: Ruling：审查列出的原生日志/HTTP轮转manifest、Agent/因果路径继续按既定范围留后续；强身份取决于collector声明的可靠出生依据，合成数据不能证明真实采集可信度；超过500事件的底层图入口不单独扩容，当前调查上限250并在服务层验证全量。浏览器/PostgreSQL由实施者执行并记录实际结果。若将这些边界用于更大规模或真实采集，须补采集验证、清单和容量门禁。

最终完成记录：check-d4.ps1 → 76项通过、Ruff105文件、依赖与前端生成/类型/lint/build通过；PostgreSQL27项通过；R01及R02 Chromium均passed；截图已查看；测试实例已停止。保留本计划作为无Git环境的实施台账，不删除用户工作区。
