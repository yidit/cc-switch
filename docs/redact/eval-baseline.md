# 脱敏评估基线

## 来源

- 仓库：<https://github.com/yetone/magpie>
- 文件：`internal/redact/eval_cases_test.go`
- 提交：`03a800ac698445234c2a996bf0298fd6677d3ba0`（main，2026-11-10）
- 许可：MIT，原文见 `src-tauri/tests/fixtures/redact/LICENSE.magpie`

语料全部是虚构数据（`From: "true"` 或用户反馈的 issue 编号），不含真实个人信息。

## 转换结果

`src-tauri/tests/fixtures/redact/eval-cases.json`：

| 指标 | 数量 |
|---|---|
| 用例 | 85 |
| 待脱敏值（`mask`） | 47 |
| 必须保留值（`keep`） | 144 |

按类型分布：

| 类型 | `mask` | `keep` |
|---|---|---|
| SECRET | 10 | 40 |
| PERSON | 20 | 66 |
| PHONE | 7 | 13 |
| EMAIL | 5 | 12 |
| ACCOUNT | 3 | 11 |
| ADDRESS | 2 | 2 |

## 规则层的适用范围

- **25 / 47** 个 `mask` 值属于 SECRET/EMAIL/PHONE/ACCOUNT，是规则层的承诺范围。
- **22 / 47** 个 `mask` 值属于 PERSON/ADDRESS，规则层无法可靠识别；`scope.md` 明确把这些留给可选的模型阶段。
- **全部 144 个 `keep` 值**都是规则层的硬约束：任何误报都会导致测试失败。

评估时不要简单追求"全部通过"：PERSON/ADDRESS 的 `mask` 在纯规则实现下预期不通过，应单独统计，不纳入 Phase 1 的通过标准。

## 判定方式（与 magpie 一致）

magpie 的评估判定很直接：

- 对每个 `mask` 值：脱敏后的文本中不得再出现该值原文，除非它只作为占位符的一部分出现；
- 对每个 `keep` 值：脱敏后的文本必须原样包含它；
- 判定前先去掉占位符（`\{\{[A-Z_]+_[a-z2-7]{8}\}\}`），避免占位符后缀偶然拼出原值。

Rust 测试可按同样逻辑实现：

```rust
fn gone(out: &str, value: &str) -> bool {
    // 先移除占位符，再判断 value 是否仍出现
}
```

## 测试基线（Phase 0）

`src-tauri/tests/redact_baseline.rs` 目前只校验语料本身：

- 85 个用例、47 个 `mask`、144 个 `keep`；
- ID 唯一、文本非空；
- 每个 `mask`/`keep` 值都出现在对应文本中；
- 类型名在允许集合内；
- 中文文本编码正确。

Phase 1 会在同一份 fixture 上增加引擎断言，并按上述判定方式统计 SECRET/EMAIL/PHONE/ACCOUNT 的通过率与全部 `keep` 的误报数。

## 维护

上游语料会继续变化。更新步骤：

1. 记录新的 upstream commit；
2. 按 `scope.md` 的格式转换 `eval_cases_test.go`；
3. 更新本文件的统计数字；
4. 在 `redact_baseline.rs` 中同步常量。

新增用例时优先补充：
- 用户实际反馈的误报（`keep`）；
- 新的密钥/账户格式（`mask`）；
- 中文文本与代码、日志混合场景。
