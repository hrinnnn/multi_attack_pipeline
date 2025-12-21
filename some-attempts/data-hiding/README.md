# data-hiding — 攻击样本（模拟）与说明文档

目的：为“隐写/隐蔽信道”相关的安全检测、审计与培训提供**非可执行**的模拟样本。

## 目录结构
- `attack/`：模拟攻击载体文件（覆盖多种文件类型）。
- `explain/`：每种载体/技术对应的说明文档（威胁模型、检测线索、缓解建议）。

## 样本索引
- `attack/01_zero_width_SIMULATED.txt` ↔ `explain/01_zero_width.md`
- `attack/02_whitespace_channel_SIMULATED.md` ↔ `explain/02_whitespace.md`
- `attack/03_metadata_carrier_SIMULATED.json` ↔ `explain/03_metadata.md`
- `attack/04_source_comment_carrier_SIMULATED.cpp` ↔ `explain/04_source_comments.md`
- `attack/05_svg_noise_SIMULATED.svg` ↔ `explain/05_svg.md`
- `attack/06_archive_structure_SIMULATED.txt` ↔ `explain/06_archive.md`
- `attack/07_http_headers_SIMULATED.http` ↔ `explain/07_network.md`

## 安全说明（重要）
- 本目录不提供可直接用于隐写/外传的可执行实现、编码步骤或真实隐藏载荷。
- 所有样本都使用可见占位符（例如 `[ZWSP]`）或描述性内容，便于训练检测逻辑。

## 建议用法
- 用于编写检测规则（YARA/正则/解析器）、演练告警解释（why/what）、制定处置流程。
- 将样本作为“单元测试夹具”（fixtures）输入到你的扫描器或网关检测模块中。
