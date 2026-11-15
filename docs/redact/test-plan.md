# 脱敏过滤效果与误判测试计划

本文档记录脱敏功能（规则层）的测试分层、语料格式、当前指标与已知问题。
评估基线语料的来源与判定口径见 [`eval-baseline.md`](./eval-baseline.md)，
功能范围见 [`scope.md`](./scope.md)。

## 1. 目标

两个方向分开度量，避免「多脱一点更安全」掩盖过度脱敏：

- **过滤效果（漏检）**：必须脱敏的值是否被真正替换，且周边文本未被破坏；
- **误判（过脱敏）**：必须保留的值是否被改写；顺带约束「无敏感内容的字符串不被改动」。

## 2. 测试分层

| 层 | 内容 | 位置 | 运行 |
|---|---|---|---|
| L0 单元 | 各检测器、占位符、JSON、SSE | `src-tauri/src/redact/**` 的 `#[cfg(test)]` | `cargo test --lib` |
| L1 语料回归 | magpie 基线（85 用例） | `tests/fixtures/redact/eval-cases.json` + `tests/redact_engine.rs`、`tests/redact_baseline.rs` | `cargo test --test redact_engine --test redact_baseline` |
| L1 误判回归 | 65 条负样本，8 类成因（每类 ≥8 条） | `tests/fixtures/redact/negative-cases.json` + `tests/redact_negative.rs` | `cargo test --test redact_negative` |
| L1 召回回归 | 26 条各供应商密钥假值 | `tests/fixtures/redact/secrets-by-provider.json` + `tests/redact_secrets.rs` | `cargo test --test redact_secrets` |
| L2 结构化往返 | JSON 往返、SSE 逐字节切分、占位符稳定性 | `tests/redact_streaming.rs` | `cargo test --test redact_streaming` |
| L2 长文本 | 64K / 256K / 512K：纯散文、稀疏敏感、密集敏感、JSON 体、单行 SSE | `tests/redact_long_text.rs` | `cargo test --test redact_long_text` |
| L4 模型评估 | 0.8 / 0.5 / 0.3 阈值下的召回与误改、预算耗尽行为 | `tests/redact_model_eval.rs` | `cargo test --test redact_model_eval -- --ignored --nocapture`（需模型文件） |

## 3. 语料格式

### 3.1 负样本 `negative-cases.json`

```json
{
  "id": "epoch-seconds",
  "category": "number-lookalike",
  "text": "created_at 1731628800 finished_at 1731629400",
  "keep": ["1731628800", "1731629400"],
  "reason": "Unix 时间戳是数字串"
}
```

- `keep`：脱敏后必须逐字保留的值；
- 整段文本还必须**不产生任何占位符**（比只查 keep 更严格）；
- `category` 用于统计分组成因，当前 8 类：
  `secret-lookalike`、`email-lookalike`、`number-lookalike`、`ip-lookalike`、
  `account-lookalike`、`identifier`、`code-context`、`prose`。

### 3.2 密钥正样本 `secrets-by-provider.json`

```json
{
  "id": "github-classic-token",
  "provider": "GitHub",
  "text": "GITHUB_TOKEN=ghp_AbC123xYz456QwE789RtY012UiO345PqR6789",
  "secret": "ghp_AbC123xYz456QwE789RtY012UiO345PqR6789"
}
```

- `secret`：必须消失的假密钥；
- 必须出现 `{{SECRET_…}}` 占位符；
- 可选 `keep`：显式声明必须保留的上下文；缺省时按 `secret` 切分自动推导。
  PEM 私钥这类整块替换的样本用整段文本作为 `secret`、`keep` 置空。

### 3.3 已知问题标记

个别用例当前会稳定复现误判/漏检。为避免 CI 长期红着、又不想把它们藏起来，
语料里用 `known_issue` 标注原因：

```json
"known_issue": "高熵兜底把 SSH 公钥的 base64 主体当密钥"
```

测试的运行规则：

- 未标记的用例必须通过；
- 标记 `known_issue` 的用例**必须仍然复现**——一旦被修好，测试会失败并提示
  「请移除 known_issue 标记」，防止问题悄悄消失或修复被遗忘。

## 4. 当前语料规模

| 语料 | 用例 | 覆盖 |
|---|---|---|
| magpie 基线 | 85（47 个 mask / 144 个 keep） | SECRET/EMAIL/PHONE/ACCOUNT 为规则层承诺范围 |
| 负样本 | 65 | 8 类误判成因，每类 ≥8 条 |
| 密钥正样本 | 26 | 19 个供应商 |
| 结构化往返 | 6 | JSON 往返、SSE 跨块、同盐稳定性、整包字节一致 |
| 长文本 | 6 | 64K / 256K / 512K，三种内容形态 + JSON 体 + 单行 SSE + 跨请求稳定性 |
| 模型评估 | 2 | 三个阈值；默认 `#[ignore]` |

## 5. 语料暴露并已修复的问题

首轮语料暴露 8 个问题，现已全部修复，对应用例重新转绿、`known_issue` 标记已移除：

| # | 用例 | 现象 | 修复 |
|---|---|---|---|
| 1 | `ssh-public-key` | SSH 公钥的 base64 主体被当密钥 | 高熵兜底按 OpenSSH 公钥前缀（ed25519 / rsa / dss / ecdsa）排除 |
| 2 | `aws-docs-example-key` | `AKIAIOSFODNN7EXAMPLE` 被脱敏 | 内置规则与 gitleaks 都跳过该文档示例值 |
| 3 | `luhn-invalid-card` | `4111 1111 1111 1112` 被当电话 | 电话规则只跳过「4-4-4 分组 + 后续完整第四段」，有效卡号交给 ACCOUNT |
| 4 | `luhn-invalid-random` | `1234 5678 9012 3456` 同上 | 同上 |
| 5 | `token-is-stored` | `The token is stored…` 的 `stored` 被当口令 | 自然语言口令的值形态过滤：全小写纯字母且 ≤12 字符视为普通单词 |
| 6 | `secret-was-rotated` | `rotated` 被当口令 | 同上 |
| 7 | `password-is-required` | `required` 被当口令 | 同上 |
| 8 | `discord-webhook` | Discord webhook URL 未被脱敏 | 新增内置规则，整段 URL 作为 SECRET |

同时修掉一处标点过捕获：中文口令规则把全角冒号并入捕获组
（`数据库密码是：xxx` → `数据库密码是{{SECRET_…}}`），现在冒号保留。

配套改动：

- 启动时若已启用的脱敏配置缺少盐值，补一个并写回设置，避免占位符每轮随机导致上游缓存失效；
- 新增整包稳定性测试：同一请求体两次脱敏的序列化结果必须逐字节相同；
- CI 的 clippy 改为 `--all-targets`，测试代码也受 lint 约束。

## 6. 验收门限

| 级别 | 指标 | 门限 |
|---|---|---|
| P0 | 规则层承诺类型（SECRET/EMAIL/PHONE/ACCOUNT）召回 | 100% |
| P0 | magpie 语料 keep 误改 | 0 |
| P0 | 负样本误判 | 0（当前无 `known_issue`） |
| P0 | JSON 往返、SSE 跨块还原、整包两次结果一致 | 100% |
| P1 | 密钥正样本召回 | 100% |
| P1 | 模型层 keep 误改（0.8 阈值） | ≤1%（当前 1.4%，见第 8 节） |

## 7. 尚未覆盖

- **1M 以上文本**：用例覆盖到 512K；1M 未设门限也未测量。
- **内存峰值**：只有临时探针的数字，未进自动化测试。
- **代理端到端**：四协议（Anthropic / OpenAI Chat / Codex Responses / Gemini）、
  fail-closed 行为尚未有集成用例。
- **多语言扩充**：仅覆盖中英日少量句子。
- **自定义规则**：只有单元测试，没有语料级回归。

## 8. 当前测量结果

规则层在 512K 文本上的耗时（同一台机器，内容见 `redact_long_text.rs`）：

| 形态 | 64 KB | 256 KB | 512 KB |
|---|---|---|---|
| 纯散文（debug / release） | 35 ms / 1.8 ms | 126 ms / 6.9 ms | 221 ms / 12.0 ms |
| 稀疏敏感（debug / release） | 34 ms / 1.9 ms | 121 ms / 6.1 ms | 256 ms / 12.1 ms |
| 密集密钥 3049 命中（debug / release） | — | 168 ms / 10.7 ms | 343 ms / 19.8 ms |
| JSON 请求体 472 KB（release） | — | — | 13.5 ms |
| SSE 还原 11 KB / 500 占位符（release） | 0.08 ms | — | — |

结论：512K 单次处理在 release 下为 12–20 ms，复杂度线性，没有病态开销；
因此「只处理新增文本」的增量优化在当前场景下没有必要。

模型评估（85 用例，默认语料）：

| 阈值 | mask 覆盖 | keep 误改 |
|---|---|---|
| 0.8（默认） | 44/47（93.6%） | 2/144（1.4%） |
| 0.5 | 45/47 | 9/144 |
| 0.3 | 45/47 | 11/144 |

按类型看，0.8 阈值下 PERSON 20/20、ADDRESS 2/2 且零误改，这正是模型相对规则层的
增量价值；SECRET 8/10、ACCOUNT 2/3 说明密钥与账号仍应依赖规则层。

## 9. 维护流程

1. 新增用例：直接改对应 JSON，测试会自动纳入；负样本优先补「真实出现过的误判」。
2. 修复已知问题：先确认对应 `known_issue` 用例转绿，再删除标记（测试会提示）。
3. 调整规则或阈值后，至少跑 `redact_engine`、`redact_negative`、`redact_secrets`、
   `redact_streaming` 与 `redact_long_text` 五组；动模型时再加
   `redact_model_eval -- --ignored`。
4. 语料中的值必须是虚构数据；真实敏感值不得入库。
