//! 密钥与凭据检测器。
//!
//! 只识别有明确前缀或赋值结构的模式，刻意不做通用的「高熵字符串」判断：
//! 提交哈希、UUID、工具调用 ID、模型名等高熵文本必须保持原样（评估语料的
//! `keep` 列表对此有硬约束）。

use std::sync::OnceLock;

use regex::Regex;

use crate::redact::{Detector, Hit, Kind, RedactConfig};

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
            // Google API key。
            Rule::new(r"AIza[0-9A-Za-z_-]{35}", 0, always),
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
            // KEY=value / KEY: value 形态，键名必须含敏感词。
            Rule::new(
                r#"(?i)\b[A-Za-z0-9_.-]*(?:api_key|apikey|secret|token|password|passwd|private_key|access_key)[A-Za-z0-9_.-]*\s*[:=]\s*["']?([^\s"'`,;，。]{8,})"#,
                1,
                always,
            ),
            // 自然语言：password is … / password: …
            Rule::new(
                r#"(?i)\b(?:password|passwd|secret|token|api[ _-]?key)\s*(?:is|was|are|[:=])\s*["']?([^\s"',，。;；]{6,})"#,
                1,
                always,
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
    value.len() >= 24
        && !value.contains('.')
        && value.bytes().any(|b| b.is_ascii_digit())
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
        assert_eq!(
            detect("DB_PASSWORD=Tr0ub4dor&3xyz"),
            vec!["Tr0ub4dor&3xyz"]
        );
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
        assert!(detect("sha256: 80efc1803eda7c095a79741d2008c07e2e0a57b01bac8825fbeb448fd097998c")
            .is_empty());
        assert!(detect("toolu_01XkP9qLm2VbT7wZ4nR8sYc3").is_empty());
    }

    #[test]
    fn ignores_slugs_that_merely_start_with_sk() {
        assert!(detect("sk-hynix-third-quarter-profit-report.html").is_empty());
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
