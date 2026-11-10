# 脱敏 Phase 5：本地 PII 模型

Phase 1–4 的规则层无法可靠识别人名和地址。Phase 5 引入可选的本地模型，
补齐这两类信息；默认关闭，用户显式下载并启用后才运行。

## 模型

| 项目 | 值 |
|---|---|
| 名称 | AstrLink Guard（QuantumNous/astrlink-guard） |
| 版本 | 0.1.3，int8 ONNX |
| 许可 | Apache-2.0 |
| 架构 | BertForTokenClassification，12 层，hidden 384，36.9M 参数 |
| 分词器 | XLM-R SentencePiece Unigram（40,003 词表） |
| 文件 | `model_int8.onnx`（323 KB）、`model_int8.onnx_data`（35.4 MB）、`tokenizer.json`（1.4 MB） |
| 固定版本 | Hugging Face 提交 `7216b6a3b897ef903d4b1ba367ae6fb95b0fa5e4` |
| 校验 | 每个文件按模型仓库公布的 SHA-256 校验 |

标签映射：

| 模型标签 | 脱敏类型 |
|---|---|
| `private_person` | PERSON |
| `private_address` | ADDRESS |
| `email` / `phone` | EMAIL / PHONE |
| `account` / `payment_card` | ACCOUNT |
| `common_secret` | SECRET |
| `ip_address` / `url` / `private_date` | 不处理（公开信息或日期） |

## 运行时

ONNX Runtime 1.22.0 由 `ort` crate 动态加载（`load-dynamic`），不参与编译链接，
下载后放在模型目录里：

| 平台 | 来源 | 下载大小 |
|---|---|---|
| Linux x86_64 | 官方 GitHub Release tgz | 7.4 MB |
| Windows x86_64 | 官方 PyPI wheel（只取 `onnxruntime.dll`） | 12.1 MB |
| macOS arm64 | 官方 GitHub Release tgz | 24.7 MB |
| macOS x86_64 | 官方 GitHub Release tgz | 26.6 MB |

Windows 没有使用 GitHub 的 zip，因为其中包含三百多 MB 的调试符号，会把下载量放大十倍。

## 推理策略

- 窗口 512 token（含起止特殊 token），相邻窗口重叠 128 token。
- 每次请求默认最多推理 4096 token，**从最新内容往前**计算；超出预算的部分只用规则层。
  预算可在设置页调整（512–32768）。
- 推理结果按文本缓存（SHA-256 键，128 条），重复出现的系统提示和历史不重复计算。
- 置信度阈值默认 0.8（模型发布方推荐值），可在设置页调整。
- 推理放在阻塞线程池里执行，不占用异步运行时。

本机实测（WSL，CPU）：64 token 约 8 ms，256 token 约 35 ms，512 token 约 141 ms；
短的预览和单轮消息几乎没有感知延迟，长会话首次请求约 1–1.5 秒，之后靠缓存。

## 分发与失败策略

- 模型和运行时都不打包进安装包：首次启用时按需下载，逐个校验 SHA-256 后保存到
  `~/.cc-switch/models/astrlink-guard-0.1.3/`。
- 下载进度写入全局状态，设置页每秒轮询一次。
- 开启 `failClosed` 时，模型启用但文件不可用会拒绝请求，而不是只做规则脱敏后放行；
  关闭 `failClosed` 时退回规则层并记录告警。
- 删除模型前需要先关闭模型开关，避免请求被静默降级。

## 隐私说明

- 推理完全在本机完成，模型不会联网上报任何内容。
- 下载只发生在用户点击「下载模型」或首次打开开关时，来源固定在上表，并做哈希校验。
- 模型文件里不含用户数据；占位符映射只存在于内存。

## 限制

- 仅支持 Linux x86_64、Windows x86_64、macOS arm64/x86_64。
- 超出每次请求预算的内容只使用规则层，早期历史中的人名/地址可能漏掉。
- macOS 正式签名构建若启用 Hardened Runtime，加载用户目录下的 dylib 需要额外授权；
  当前 fork 的未签名构建不受影响。
- 模型只识别中文与英文。

## 许可与归属

- AstrLink Guard 0.1.3：Apache-2.0，许可证全文见 `LICENSE.astrlink-guard`。
- 基础模型 `microsoft/Multilingual-MiniLM-L12-H384`：Apache-2.0。
- ONNX Runtime：MIT，仅在用户主动下载后由 `ort` 动态加载，不随本项目分发。
- Rust crate：`ort`（MIT/Apache-2.0）、`tokenizers`（Apache-2.0）。

## 验证

- `redact` 模块单测覆盖窗口切分、标签映射、区间合并与跨线程共享。
- 端到端验证：中文示例中的姓名、电话、邮箱、地址均被正确识别，置信度 ≥ 0.99。
- 模型文件与四个平台的运行时包均按公布的 SHA-256 校验通过。
