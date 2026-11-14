//! 密钥与凭据检测器。
//!
//! 只识别有明确前缀或赋值结构的模式，刻意不做通用的「高熵字符串」判断：
//! 提交哈希、UUID、工具调用 ID、模型名等高熵文本必须保持原样（评估语料的
//! `keep` 列表对此有硬约束）。

use std::collections::HashMap;
use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, MatchKind};
use regex::Regex;

use crate::redact::{Action, Detector, Hit, Kind, RedactConfig};

/// 识别 API key、私钥、JWT、连接串密码等。
pub struct SecretDetector;

impl Detector for SecretDetector {
    fn detect(&self, text: &str, config: &RedactConfig) -> Vec<Hit> {
        if !config.secrets {
            return Vec::new();
        }
        self.detect_impl(text, true)
    }
}

impl SecretDetector {
    /// 内部实现；`gated` 为 false 时跳过字面量预筛，仅供测试比对两条路径。
    fn detect_impl(&self, text: &str, gated: bool) -> Vec<Hit> {
        let set = rule_set();
        // 预筛只判断「值不可能出现」：宁可多跑几次正则，也绝不能漏掉本可命中的规则。
        let active = gated.then(|| set.gate.active(&set.rules, text));
        let mut hits = Vec::new();
        for (index, rule) in set.rules.iter().enumerate() {
            if active.as_ref().is_some_and(|active| !active[index]) {
                continue;
            }
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
    /// 字面量预筛：这些子串一个都不出现时，本条正则必然无命中。
    ///
    /// 请求正文动辄几十 KB，逐条跑正则才是脱敏的主要开销；先用一次自动机扫描
    /// 排掉绝大多数规则，匹配结果与直接跑正则完全一致。
    gate: &'static [&'static str],
}

impl Rule {
    fn new(
        pattern: &str,
        group: usize,
        validate: fn(&str) -> bool,
        gate: &'static [&'static str],
    ) -> Self {
        Self {
            regex: Regex::new(pattern).expect("内置脱敏正则应始终合法"),
            group,
            validate,
            gate,
        }
    }

    /// 逐条比较字面量，仅在自动机构建失败时使用。
    ///
    /// 比较对 ASCII 不分大小写（`(?i)` 规则靠它开闸），非 ASCII 按原样比较，
    /// 因此中文关键词仍然精确匹配。
    fn open(&self, text: &str) -> bool {
        self.gate.is_empty()
            || self
                .gate
                .iter()
                .any(|needle| contains_ignore_ascii_case(text, needle))
    }
}

/// 字面量预筛的自动机。
///
/// 13 条规则一共 31 个候选字面量，逐条 `contains` 要在长文本上扫 31 遍；
/// 用 Aho-Corasick 一遍即可得出「哪些规则可能命中」。语义与 [`Rule::open`]
/// 完全一致：ASCII 不分大小写，非 ASCII 按原样比较。
struct Gate {
    /// 由全部字面量构建；构建失败时为 None，退回逐条比较，结果不变。
    automaton: Option<AhoCorasick>,
    /// 自动机里第 i 个字面量 → 依赖它的规则下标。
    literal_rules: Vec<Vec<usize>>,
    /// 没有字面量的规则，始终放行。
    always_active: Vec<usize>,
}

impl Gate {
    fn build(rules: &[Rule]) -> Self {
        let mut literals: Vec<&'static str> = Vec::new();
        let mut literal_rules: Vec<Vec<usize>> = Vec::new();
        let mut index: HashMap<&'static str, usize> = HashMap::new();
        let mut always_active = Vec::new();
        for (rule_index, rule) in rules.iter().enumerate() {
            if rule.gate.is_empty() {
                always_active.push(rule_index);
                continue;
            }
            for &literal in rule.gate {
                let id = *index.entry(literal).or_insert_with(|| {
                    literals.push(literal);
                    literal_rules.push(Vec::new());
                    literals.len() - 1
                });
                literal_rules[id].push(rule_index);
            }
        }

        let automaton = if literals.is_empty() {
            None
        } else {
            match AhoCorasick::builder()
                .match_kind(MatchKind::Standard)
                .ascii_case_insensitive(true)
                .build(&literals)
            {
                Ok(automaton) => Some(automaton),
                Err(error) => {
                    log::warn!("[redact] 字面量预筛构建失败，退回逐条比较: {error}");
                    None
                }
            }
        };
        Self {
            automaton,
            literal_rules,
            always_active,
        }
    }

    /// 返回每条规则是否需要跑正则。
    fn active(&self, rules: &[Rule], text: &str) -> Vec<bool> {
        /// 标记规则为活跃，返回是否所有规则都已活跃。
        fn mark(active: &mut [bool], remaining: &mut usize, index: usize) -> bool {
            if !active[index] {
                active[index] = true;
                *remaining -= 1;
            }
            *remaining == 0
        }

        let mut active = vec![false; rules.len()];
        let mut remaining = rules.len();
        for &index in &self.always_active {
            mark(&mut active, &mut remaining, index);
        }
        if remaining == 0 {
            return active;
        }

        let Some(automaton) = &self.automaton else {
            // 自动机不可用：退回逐条子串比较，结果与自动机一致。
            for (index, rule) in rules.iter().enumerate() {
                if rule.open(text) {
                    mark(&mut active, &mut remaining, index);
                }
            }
            return active;
        };

        // Standard 语义下 overlapping 迭代会报告每一处出现，互相包含的字面量也不会漏。
        'scan: for found in automaton.find_overlapping_iter(text) {
            for &index in &self.literal_rules[found.pattern().as_usize()] {
                if mark(&mut active, &mut remaining, index) {
                    break 'scan;
                }
            }
        }
        active
    }
}

/// 判断 `haystack` 是否包含 `needle`：ASCII 部分不分大小写，其余按原样比较。
fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    if !needle.is_ascii() {
        return haystack.contains(needle);
    }
    let needle = needle.as_bytes();
    if needle.is_empty() {
        return true;
    }
    let haystack = haystack.as_bytes();
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

/// 全部内置规则及其预筛自动机。
struct RuleSet {
    rules: Vec<Rule>,
    gate: Gate,
}

fn rule_set() -> &'static RuleSet {
    static RULES: OnceLock<RuleSet> = OnceLock::new();
    RULES.get_or_init(|| {
        let rules = vec![
            // PEM 私钥块。
            Rule::new(
                r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]+?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----",
                0,
                always,
                &["-----BEGIN "],
            ),
            // OpenAI / Anthropic / OpenRouter 等 `sk-` 前缀的 key。
            Rule::new(
                r"\bsk-(?:ant-|proj-|or-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}",
                0,
                looks_like_key,
                &["sk-"],
            ),
            // Google API key（前缀后至少 35 位，实际长度可能更长）。
            Rule::new(r"AIza[0-9A-Za-z_-]{35,}", 0, always, &["AIza"]),
            // Slack token。
            Rule::new(r"xox[abposr]-[0-9A-Za-z-]{10,}", 0, always, &["xox"]),
            // AWS access key id。
            Rule::new(r"(?:AKIA|ASIA)[0-9A-Z]{16}", 0, always, &["AKIA", "ASIA"]),
            // GitHub classic / fine-grained token。
            Rule::new(
                r"gh[pousr]_[A-Za-z0-9]{20,}",
                0,
                always,
                &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
            ),
            Rule::new(
                r"github_pat_[A-Za-z0-9_]{20,}",
                0,
                always,
                &["github_pat_"],
            ),
            // JWT：三段 base64url。
            Rule::new(
                r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
                0,
                always,
                &["eyJ"],
            ),
            // Authorization: Bearer <token>
            Rule::new(
                r"(?i)\bauthorization\s*:\s*bearer\s+([A-Za-z0-9._~+/=-]{8,})",
                1,
                always,
                &["authorization"],
            ),
            // 连接串里的密码：scheme://user:password@host
            Rule::new(
                r"(?i)\b[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s@/]{4,})@",
                1,
                always,
                &["://"],
            ),
            // KEY=value / KEY: value 形态，键名必须按分隔符组成敏感词。
            //
            // 键名用「分隔符分段」而不是任意子串：`tokenizers::Tokenizer`、
            // `max_tokens_per_request: ...` 这类普通代码不应命中。
            Rule::new(
                r#"(?i)\b(?:[A-Za-z0-9]+[_.-])*(?:api[_-]?key|apikey|secret|token|password|passwd|private[_-]?key|access[_-]?key)(?:[_.-][A-Za-z0-9]+)*\s*[:=]\s*["']?([^\s"'`,;，。]{8,})"#,
                1,
                is_plausible_secret_value,
                &["api", "secret", "token", "password", "passwd", "private", "access"],
            ),
            // 自然语言：password is … / password: …
            //
            // 关键词两侧都要有词边界，避免从 `tokenizers` 里截出 `token`。
            Rule::new(
                r#"(?i)\b(?:password|passwd|secret|token|api[ _-]?key)\b\s*(?:is|was|are|[:=])\s*["']?([^\s"',，。;；]{6,})"#,
                1,
                is_plausible_secret_value,
                &["api", "secret", "token", "password", "passwd"],
            ),
            // 中文：密码/口令/密钥 + 是/为/:/=
            Rule::new(
                r"(?:密码|口令|密钥|秘钥)\s*(?:是|为|[:=])\s*([^\s，。;；、]{6,})",
                1,
                always,
                &["密码", "口令", "密钥", "秘钥"],
            ),
        ];
        let gate = Gate::build(&rules);
        RuleSet { rules, gate }
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

    /// 预筛只能「提前排除必不命中的规则」，不能让结果发生变化。
    #[test]
    fn literal_gate_never_hides_a_match() {
        let pem = concat!(
            "-----BEGIN RSA ",
            "PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA ",
            "PRIVATE KEY-----"
        );
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MjEiLCJuYW1lIjoiTWFyaWEifQ.x7Hq2LmZ9pVb4WnT8sRc1YeKd6gJ3uFa0oNi5vQwE";
        let samples = [
            pem,
            "OPENAI_API_KEY=sk-proj-Qm7vT2xLk9RbW4nZpE6sJc8YhD3fGa5uKiN1oVr0",
            "const maps = 'AIzaSyB3xQ9mLk2Vr7TpW4nZs8YhC1dFgJ6uKe0oA';",
            "SLACK_TOKEN=xoxb-123456789012-abcdefghijkl",
            "key = AKIAIOSFODNN7EXAMPLE",
            "key = ASIAIOSFODNN7EXAMPLE",
            "const gh = \"ghp_0123456789abcdefghijABCDEFGHIJ0123\";",
            "const pat = \"github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz\";",
            jwt,
            "-H 'AUTHORIZATION: BEARER abc123def456ghi'",
            "DATABASE_URL=postgres://app:hunter2pass@db.acme-corp.cn:5432/orders",
            "DB_PASSWORD=Tr0ub4dor&3xyz",
            "the staging db password is hunter2Xq9z, don't commit it",
            "服务器密码是 Qw8!zLp3mN，用完记得改掉",
            "DEBUG=true",
            "use tokenizers::Tokenizer;",
            "password: correcthorsebatterystaple",
            "这是一段普通文本，没有任何敏感值。",
        ];

        for sample in samples {
            let gated = SecretDetector.detect_impl(sample, true);
            let ungated = SecretDetector.detect_impl(sample, false);
            assert_eq!(gated, ungated, "预筛漏掉了命中：{sample:?}");
        }
    }

    #[test]
    fn every_builtin_rule_has_a_literal_gate() {
        assert!(rule_set().rules.iter().all(|rule| !rule.gate.is_empty()));
    }
}
