# D10冻结演示稿

版本d10-demo@1.0.0。以下是冻结的操作顺序与目标时长，不是已完成的8分钟计时记录。无正式评估时展示未完成清单，不填造性能或准确率。

1. 开场（目标45秒）：输入为授权开发合成材料；系统分析观测关系与可复核证据，不识别真实操作者。当前模型默认关闭；自动化验收的“live”来自明确标记的回环协议桩，非真实LLM。
2. S1（目标2分钟）：新建synthetic数据集，先导入data/fixtures/d9/S1/context.json；再上传network/zeek/net-a、auth_a/linux_auth/auth-a、audit/linux_audit/audit-a、auth_b/linux_auth/auth-b、alerts/suricata/alert-a。规范事件37条，物理audit记录另计。打开候选、调查、时间线及证据。后段R06保持独立候选；缺socket时不声称成功横移、测试文件内容或完整攻击因果。
3. S2（目标1分30秒）：新数据集，先导入d9/S2/context.json，再导入network/zeek/net-a与audit/linux_audit/audit-a。显示周期/出站量与监控、备份替代上下文。默认模型disabled只能演示规则/图和确定性报告；工具补证前后对比仅在已有真实执行轨迹中展示，并标清来源模式。context_only不能证明流量归属或无攻击。
4. S3（目标1分钟）：新数据集使用S2 context，仅network，省略audit。尝试live并将模型调用上限设0，查看partial、预算停止与主机缺证；未知不补造。环境模型disabled时停止原因可能是MODEL_DISABLED，按页面真实值讲述。
5. 报告（目标1分钟）：点逐条引用→追加needs_more_evidence复核→下载JSON/HTML→离线打开引用目录；复核不改变原报告。读取匹配缓存，明确cached、原生成时间和source_mode。刷新后重新输入viewer令牌，从“查看历史报告”载入已有版本，不创建新调查。
6. 收尾（目标1分45秒）：展示实际工程门禁和缺陷表；33项仍planned、0双人人工复核、真实模型与正式指标未验收。说明冻结范围和剩余验证。演示稿各段合计只是8分钟预算，实际完成时间须另行测量记录。

禁止将模板报告称为模型推理、协议桩称为真实LLM、cached/录像称为现场实时执行、prepared称为独立实验。模型/网络异常时保留规则与证据，历史结果清楚标记；录屏必须标“预录演示”。不执行攻击、扫描或访问第三方目标。
