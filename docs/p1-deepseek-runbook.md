# DeepSeek 官方一次试运行增量（dev18）

新增可选 MODEL_THINKING=disabled；默认省略 thinking 参数，兼容既有请求。参数进入模型配置哈希，影响缓存与未完成调查恢复身份。数据库 0006_d9、规则冻结、依赖锁文件不变。

原候选/镜像/报告保留。当前用户授权仅一次 S1 合成脱敏调查、USD 0.10 预留上限；不授权持续联网调用或真实敏感日志外发。供应商默认思考模式与原 20 秒硬超时存在兼容风险，本次关闭思考而不放宽硬超时。

价格按 2026-11-16 官方美元高峰未命中输入0.30/百万、输出1.20/百万保守估算；真实账单另核。模型名 deepseek-flash 是可变别名，官方当日记为 DeepSeek-V4.1-Flash-1017，不称不可变版本锁定。

官方依据：https://api-docs.deepseek.com/zh-cn/guides/thinking_mode/ 、 https://api-docs.deepseek.com/quick_start/pricing/ 。

本地兼容测试不等于真实调查通过；实际结果另存 artifacts/p1-deepseek-01。D10-001 及其他四项 P1 不自动关闭。
