//! 密钥与凭据检测器。
//!
//! 只识别有明确前缀或赋值结构的模式，刻意不做通用的「高熵字符串」判断：
//! 提交哈希、UUID、工具调用 ID、模型名等高熵文本必须保持原样（评估语料的
//! `keep` 列表对此有硬约束）。

use std::sync::OnceLock;

use regex::Regex;

use crate::redact::{Action, Detector, Hit, Kind, RedactConfig};

/// 识别 API key、私钥、JWT、连接串密码等。
pub struct SecretDetector;

impl Detector for SecretDetector {
    fn detect(&self, text: &str, config: &RedactConfig) -> Vec<Hit> {
        if !config.secrets {
            return Vec::new();
        }

        let mut hits = Vec::new();
        for rule in rules() {
            for captures in rule.regex.captures_iter(text) {
                let Some(found) = captures.get(rule.group) else {
                    continue;
                };
                let value = found.as_str();
                if !acceptable(value) || !(rule.validate)(value) {
                    continue;
                }
                hits.push(Hit {
                    start: found.start(),
                    end: found.end(),
                    kind: Kind::Secret,
                    action: Action::Placeholder,
                });
            }
        }
        // 同一条 token 可能同时命中「Bearer」与「JWT」等规则，去重后再交给 Engine。
        hits.sort_by(|a, b| a.start.cmp(&b.start).then(a.end.cmp(&b.end)));
        hits.dedup();
        hits
    }
}

struct Rule {
    regex: Regex,
    /// 需要标记的捕获组；0 表示整个匹配。
    group: usize,
    /// 额外的值校验，用于压低误报。
    validate: fn(&str) -> bool,
}

impl Rule {
    fn new(pattern: &str, group: usize, validate: fn(&str) -> bool) -> Self {
        Self {
            regex: Regex::new(pattern).expect("内置脱敏正则应始终合法"),
            group,
            validate,
        }
    }
}

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        vec![
            // PEM 私钥块。
            Rule::new(
                r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]+?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----",
                0,
                always,
            ),
            // OpenAI / Anthropic / OpenRouter 等 `sk-` 前缀的 key。
            Rule::new(
                r"\bsk-(?:ant-|proj-|or-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}",
                0,
                looks_like_key,
            ),
            // Google API key（前缀后至少 35 位，实际长度可能更长）。
            Rule::new(r"AIza[0-9A-Za-z_-]{35,}", 0, always),
            // Slack token。
            Rule::new(r"xox[abposr]-[0-9A-Za-z-]{10,}", 0, always),
            // AWS access key id。
            Rule::new(r"(?:AKIA|ASIA)[0-9A-Z]{16}", 0, always),
            // GitHub classic / fine-grained token。
            Rule::new(r"gh[pousr]_[A-Za-z0-9]{20,}", 0, always),
            Rule::new(r"github_pat_[A-Za-z0-9_]{20,}", 0, always),
            // JWT：三段 base64url。
            Rule::new(
                r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
                0,
                always,
            ),
            // Authorization: Bearer <token>
            Rule::new(
                r"(?i)\bauthorization\s*:\s*bearer\s+([A-Za-z0-9._~+/=-]{8,})",
                1,
                always,
            ),
            // 连接串里的密码：scheme://user:password@host
            Rule::new(
                r"(?i)\b[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s@/]{4,})@",
                1,
                always,
            ),
            // KEY=value / KEY: value 形态，键名必须按分隔符组成敏感词。
            //
            // 键名用「分隔符分段」而不是任意子串：`tokenizers::Tokenizer`、
            // `max_tokens_per_request: ...` 这类普通代码不应命中。
            Rule::new(
                r#"(?i)\b(?:[A-Za-z0-9]+[_.-])*(?:api[_-]?key|apikey|secret|token|password|passwd|private[_-]?key|access[_-]?key)(?:[_.-][A-Za-z0-9]+)*\s*[:=]\s*["']?([^\s"'`,;，。]{8,})"#,
                1,
                is_plausible_secret_value,
            ),
            // 自然语言：password is … / password: …
            //
            // 关键词两侧都要有词边界，避免从 `tokenizers` 里截出 `token`。
            Rule::new(
                r#"(?i)\b(?:password|passwd|secret|token|api[ _-]?key)\b\s*(?:is|was|are|[:=])\s*["']?([^\s"',，。;；]{6,})"#,
                1,
                is_plausible_secret_value,
            ),
            // 中文：密码/口令/密钥 + 是/为/:/=
            Rule::new(
                r"(?:密码|口令|密钥|秘钥)\s*(?:是|为|[:=])\s*([^\s，。;；、]{6,})",
                1,
                always,
            ),
        ]
    })
}

fn always(_value: &str) -> bool {
    true
}

/// `sk-` 前缀的值还需要像密钥：含数字、不含点（排除 `sk-hynix-...html` 这类 slug）。
fn looks_like_key(value: &str) -> bool {
    value.len() >= 24 && !value.contains('.') && value.bytes().any(|b| b.is_ascii_digit())
}

/// 通用的值过滤：去掉明显的占位符、变量引用与配置字面量。
fn acceptable(value: &str) -> bool {
    let length = value.chars().count();
    if !(4..=65536).contains(&length) {
        return false;
    }
    if value.contains("{{") || value.starts_with('$') {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    !matches!(
        lower.as_str(),
        "true" | "false" | "null" | "none" | "undefined" | "password"
    )
}

/// 判断上下文规则捕获到的值是否「像凭据」，而不是代码标识符或类型名。
///
/// 上下文规则（`KEY = value`、`password is ...`）只看结构，值必须再过滤一轮，
/// 否则 `use tokenizers::Tokenizer;`、`max_tokens_per_request: default_model_max_tokens()`
/// 这类普通代码会被替换成占位符，发往上游的代码就失真了。
///
/// 过滤只针对「明确的代码形态」，纯单词口令（如 `correcthorsebatterystaple`）
/// 仍然放行，避免把真实口令漏掉。
pub(crate) fn is_plausible_secret_value(value: &str) -> bool {
    let value = value.trim();
    if value.len() < 4 || value.len() > 65536 {
        return false;
    }
    if value.contains("{{") || value.starts_with('$') {
        return false;
    }

    // 代码形态：以标点开头、函数调用、路径/泛型、插值。
    if value.starts_with([':', '{', '(', '.', ',', '<']) {
        return false;
    }
    if value.contains('(')
        || value.contains("::")
        || value.contains("->")
        || value.contains('{')
        || value.contains('}')
        || (value.contains('<') && value.contains('>'))
    {
        return false;
    }

    let lower = value.to_ascii_lowercase();
    if is_language_type_name(&lower) {
        return false;
    }
    // `config.secret` / `user.profile.name` 这类成员访问：只有点号分段，
    // 每段都是标识符且不含数字。真实口令很少是这个形状。
    if value.contains('.')
        && !value.chars().any(|ch| ch.is_ascii_digit())
        && value.split('.').all(is_ascii_identifier)
    {
        return false;
    }

    true
}

/// 单个标识符：字母或下划线开头，其余为字母数字/下划线。
fn is_ascii_identifier(part: &str) -> bool {
    let mut chars = part.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

/// 常见编程语言/数据库类型名与字面量。它们出现在 `KEY = value` 的右侧时
/// 说明这是类型标注或默认值，不是凭据。
fn is_language_type_name(lower: &str) -> bool {
    matches!(
        lower,
        "string"
            | "str"
            | "char"
            | "bool"
            | "boolean"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "usize"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "isize"
            | "f32"
            | "f64"
            | "vec"
            | "option"
            | "result"
            | "hashmap"
            | "hashset"
            | "btreemap"
            | "value"
            | "json"
            | "object"
            | "array"
            | "slice"
            | "bytes"
            | "byte"
            | "unit"
            | "void"
            | "any"
            | "self"
            | "none"
            | "null"
            | "nil"
            | "undefined"
            | "true"
            | "false"
            | "int"
            | "integer"
            | "long"
            | "float"
            | "double"
            | "number"
            | "decimal"
            | "bigint"
            | "text"
            | "varchar"
            | "blob"
            | "datetime"
            | "timestamp"
            | "uuid"
            | "path"
            | "pathbuf"
            | "osstring"
            | "cow"
            | "box"
            | "rc"
            | "arc"
            | "mutex"
            | "rwlock"
            | "refcell"
            | "cell"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(text: &str) -> Vec<&str> {
        let config = RedactConfig {
            enabled: true,
            ..Default::default()
        };
        SecretDetector
            .detect(text, &config)
            .into_iter()
            .map(|hit| &text[hit.start..hit.end])
            .collect()
    }

    #[test]
    fn detects_vendor_keys() {
        assert_eq!(
            detect("OPENAI_API_KEY=sk-proj-Qm7vT2xLk9RbW4nZpE6sJc8YhD3fGa5uKiN1oVr0"),
            vec!["sk-proj-Qm7vT2xLk9RbW4nZpE6sJc8YhD3fGa5uKiN1oVr0"]
        );
        assert_eq!(
            detect("const gh = \"ghp_0123456789abcdefghijABCDEFGHIJ0123\";"),
            vec!["ghp_0123456789abcdefghijABCDEFGHIJ0123"]
        );
        assert_eq!(
            detect("const maps = 'AIzaSyB3xQ9mLk2Vr7TpW4nZs8YhC1dFgJ6uKe0oA';"),
            vec!["AIzaSyB3xQ9mLk2Vr7TpW4nZs8YhC1dFgJ6uKe0oA"]
        );
        assert_eq!(
            detect("key = AKIAIOSFODNN7EXAMPLE"),
            vec!["AKIAIOSFODNN7EXAMPLE"]
        );
    }

    #[test]
    fn detects_jwt_and_bearer() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MjEiLCJuYW1lIjoiTWFyaWEifQ.x7Hq2LmZ9pVb4WnT8sRc1YeKd6gJ3uFa0oNi5vQwE";
        assert_eq!(detect(jwt), vec![jwt]);
        assert_eq!(
            detect(&format!("-H 'Authorization: Bearer {jwt}'")),
            vec![jwt]
        );
    }

    #[test]
    fn detects_only_the_password_in_a_url() {
        assert_eq!(
            detect("DATABASE_URL=postgres://app:hunter2pass@db.acme-corp.cn:5432/orders"),
            vec!["hunter2pass"]
        );
    }

    #[test]
    fn detects_assignment_and_natural_language_forms() {
        assert_eq!(
            detect("the staging db password is hunter2Xq9z, don't commit it"),
            vec!["hunter2Xq9z"]
        );
        assert_eq!(
            detect("服务器密码是 Qw8!zLp3mN，用完记得改掉"),
            vec!["Qw8!zLp3mN"]
        );
        assert_eq!(detect("DB_PASSWORD=Tr0ub4dor&3xyz"), vec!["Tr0ub4dor&3xyz"]);
        assert_eq!(
            detect("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
            vec!["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]
        );
    }

    #[test]
    fn ignores_non_secrets() {
        // 调试开关、grep 模式、UUID、提交哈希、工具 ID 都不应命中。
        assert!(detect("DEBUG=true").is_empty());
        assert!(detect("rg -n 'password|passwd|secret_key|api_token' --glob '*.go'").is_empty());
        assert!(detect("3f2b6c1e-8a4d-4f7e-9b1a-2c3d4e5f6a7b").is_empty());
        assert!(
            detect("sha256: 80efc1803eda7c095a79741d2008c07e2e0a57b01bac8825fbeb448fd097998c")
                .is_empty()
        );
        assert!(detect("toolu_01XkP9qLm2VbT7wZ4nR8sYc3").is_empty());
    }

    #[test]
    fn ignores_slugs_that_merely_start_with_sk() {
        assert!(detect("sk-hynix-third-quarter-profit-report.html").is_empty());
    }

    #[test]
    fn ignores_code_shaped_values() {
        // 字符串用 concat! 拼接：这些片段本身会被「像密钥」地误判，
        // 拼接后既保留用例语义，也避免用例文本被别的过滤层改写。
        let cases = [
            concat!("use token", "izers::Token", "izer;"),
            concat!(
                "max_",
                "tokens_per_request: default_model_max_",
                "tokens(),"
            ),
            concat!(
                "assert_eq!(value, format!(\"",
                "tokens",
                "={",
                "tokens",
                "}\"));"
            ),
            concat!("let api_", "key = String", "::from(\"API_", "KEY\");"),
            concat!("type Token = ", "String", ";"),
            concat!("secret_", "key_name = config.secret,"),
        ];
        for case in cases {
            let hits = detect(case);
            assert!(hits.is_empty(), "{case:?} -> {hits:?}");
        }
    }

    #[test]
    fn keeps_word_like_passwords() {
        // 纯单词口令不能因为「像标识符」被放过。
        assert_eq!(
            detect("password: correcthorsebatterystaple"),
            vec!["correcthorsebatterystaple"]
        );
        assert_eq!(detect("password: hunter2Xq9z"), vec!["hunter2Xq9z"]);
    }

    #[test]
    fn keeps_structured_passwords_with_unusual_characters() {
        // 值形态过滤只作用于两条上下文规则；连接串等结构化规则不受影响，
        // 带花括号的真实密码仍要命中。
        assert_eq!(
            detect("postgres://app:Pss{w0rd}@db.internal:5432/orders"),
            vec!["Pss{w0rd}"]
        );
    }

    #[test]
    fn respects_the_secrets_switch() {
        let config = RedactConfig {
            enabled: true,
            secrets: false,
            ..Default::default()
        };
        assert!(SecretDetector
            .detect("DB_PASSWORD=Tr0ub4dor&3xyz", &config)
            .is_empty());
    }
}
