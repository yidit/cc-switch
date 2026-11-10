//! 请求/响应脱敏引擎。
//!
//! 设计参考 magpie（MIT）的 `internal/redact`，但按 CC Switch 的需要重写。
//! 第一阶段只实现规则层，不引入本地 PII 模型。范围见 `docs/redact/scope.md`。
//!
//! 数据流：
//! - 请求：在最终发送上游前把文本字段中的敏感值替换为占位符；
//! - 响应：把回复中的占位符还原为原值（流式 SSE 在 Phase 2 接入）。

pub mod detectors;
pub mod placeholder;
pub mod types;

use detectors::{
    AccountDetector, CustomRuleDetector, EmailDetector, PhoneDetector, SecretDetector,
    WordDetector,
};

pub use placeholder::PlaceholderTable;
pub use types::{Action, CustomRule, Hit, Kind, MaskOutcome, RedactConfig};

/// 检测器：在文本中找出需要脱敏的字节区间。
///
/// 实现必须保证返回的区间落在 UTF-8 字符边界上，且 `start < end`。
pub trait Detector: Send + Sync {
    fn detect(&self, text: &str, config: &RedactConfig) -> Vec<Hit>;
}

/// 脱敏引擎。
///
/// 检测器在构造时注册；Phase 1 的后续步骤会把密钥、邮箱、手机号等检测器
/// 加入 [`Engine::with_builtin`]。
pub struct Engine {
    detectors: Vec<Box<dyn Detector>>,
}

impl Engine {
    /// 按配置构建内置检测器。
    ///
    /// `secrets` / `personal` 控制内置规则；自定义词与自定义规则由用户
    /// 显式配置，只要总开关打开就生效。
    pub fn with_builtin(config: &RedactConfig) -> Self {
        let mut detectors: Vec<Box<dyn Detector>> = Vec::new();
        if config.secrets {
            detectors.push(Box::new(SecretDetector));
        }
        if config.personal {
            detectors.push(Box::new(EmailDetector));
            detectors.push(Box::new(PhoneDetector));
            detectors.push(Box::new(AccountDetector));
        }
        if !config.words.is_empty() {
            detectors.push(Box::new(WordDetector::new(
                &config.words,
                config.words_any_case,
                config.words_whole,
            )));
        }
        if !config.rules.is_empty() {
            detectors.push(Box::new(CustomRuleDetector::new(&config.rules)));
        }
        Self { detectors }
    }

    /// 追加一个检测器（测试与后续扩展使用）。
    pub fn with_detector(mut self, detector: Box<dyn Detector>) -> Self {
        self.detectors.push(detector);
        self
    }

    /// 对一段文本做脱敏。
    ///
    /// 相同原值复用同一个占位符；返回的 `hits` 已按位置排序且互不重叠。
    pub fn mask_text(
        &self,
        text: &str,
        config: &RedactConfig,
        table: &mut PlaceholderTable,
    ) -> MaskOutcome {
        if !config.enabled {
            return MaskOutcome {
                text: text.to_string(),
                hits: Vec::new(),
                placeholders: 0,
            };
        }

        let hits = self.collect_hits(text, config);
        if hits.is_empty() {
            return MaskOutcome {
                text: text.to_string(),
                hits,
                placeholders: 0,
            };
        }

        let mut out = String::with_capacity(text.len());
        let mut cursor = 0;
        let mut placeholders = 0;
        for hit in &hits {
            out.push_str(&text[cursor..hit.start]);
            let value = &text[hit.start..hit.end];
            match hit.action {
                Action::Placeholder => {
                    out.push_str(&table.placeholder_for(value, hit.kind));
                    placeholders += 1;
                }
                Action::Mask => out.push_str("[REDACTED]"),
                Action::Drop => {}
            }
            cursor = hit.end;
        }
        out.push_str(&text[cursor..]);

        MaskOutcome {
            text: out,
            hits,
            placeholders,
        }
    }

    /// 收集所有检测器的结果，排序并丢弃重叠区间。
    ///
    /// 重叠时保留起点更早（同起点则更长）的区间；被它覆盖的短区间会被丢弃。
    fn collect_hits(&self, text: &str, config: &RedactConfig) -> Vec<Hit> {
        let mut all = Vec::new();
        for detector in &self.detectors {
            all.extend(detector.detect(text, config));
        }

        all.retain(|hit| hit.start < hit.end && hit.end <= text.len());
        // 白名单按原值精确匹配，对内置检测器与自定义词/规则一律生效。
        all.retain(|hit| {
            let value = &text[hit.start..hit.end];
            !config
                .allow
                .iter()
                .any(|allowed| allowed.as_str() == value)
        });
        debug_assert!(
            all.iter()
                .all(|hit| text.is_char_boundary(hit.start) && text.is_char_boundary(hit.end)),
            "检测器返回了非 UTF-8 字符边界的区间"
        );

        all.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));

        let mut merged: Vec<Hit> = Vec::with_capacity(all.len());
        for hit in all {
            match merged.last() {
                Some(last) if hit.start < last.end => continue,
                _ => merged.push(hit),
            }
        }
        merged
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试用的字面量检测器：把配置里的每个词当作 PERSON 命中。
    struct LiteralDetector {
        words: Vec<String>,
    }

    impl Detector for LiteralDetector {
        fn detect(&self, text: &str, _config: &RedactConfig) -> Vec<Hit> {
            let mut hits = Vec::new();
            for word in &self.words {
                if word.is_empty() {
                    continue;
                }
                let mut from = 0;
                while let Some(pos) = text[from..].find(word.as_str()) {
                    let start = from + pos;
                    hits.push(Hit {
                        start,
                        end: start + word.len(),
                        kind: Kind::Person,
                        action: Action::Placeholder,
                    });
                    from = start + word.len();
                }
            }
            hits
        }
    }

    fn enabled_config() -> RedactConfig {
        RedactConfig {
            enabled: true,
            ..Default::default()
        }
    }

    fn engine(words: &[&str]) -> Engine {
        // 直接构造，不注册内置检测器：这一组测试只验证掩码与映射流程。
        Engine {
            detectors: vec![Box::new(LiteralDetector {
                words: words.iter().map(|w| w.to_string()).collect(),
            })],
        }
    }

    #[test]
    fn disabled_engine_returns_text_unchanged() {
        let mut table = PlaceholderTable::with_seed(7);
        let config = RedactConfig::default();
        let outcome = engine(&["secret"]).mask_text("a secret value", &config, &mut table);
        assert_eq!(outcome.text, "a secret value");
        assert!(outcome.hits.is_empty());
    }

    #[test]
    fn masks_and_restores_a_simple_value() {
        let mut table = PlaceholderTable::with_seed(7);
        let outcome = engine(&["secret"]).mask_text("a secret value", &enabled_config(), &mut table);

        assert_eq!(outcome.placeholders, 1);
        assert!(!outcome.text.contains("secret"));
        assert!(outcome.text.starts_with("a {{PERSON_"));

        let restored = table.restore(&outcome.text);
        assert_eq!(restored, "a secret value");
    }

    #[test]
    fn same_value_reuses_the_same_placeholder() {
        let mut table = PlaceholderTable::with_seed(7);
        let outcome = engine(&["secret"]).mask_text("secret and secret", &enabled_config(), &mut table);
        let mut parts = outcome.text.split(" and ");
        assert_eq!(parts.next().unwrap(), parts.next().unwrap());
    }

    #[test]
    fn keeps_utf8_boundaries() {
        let mut table = PlaceholderTable::with_seed(7);
        let input = "密码是 secret，请勿泄露";
        let outcome = engine(&["secret"]).mask_text(input, &enabled_config(), &mut table);

        assert!(outcome.text.starts_with("密码是 {{PERSON_"));
        assert!(outcome.text.ends_with("，请勿泄露"));
        assert_eq!(table.restore(&outcome.text), input);
    }

    #[test]
    fn drops_overlapping_hits_in_favor_of_the_first() {
        let mut table = PlaceholderTable::with_seed(7);
        let outcome = engine(&["abcd", "bc"]).mask_text("abcd", &enabled_config(), &mut table);
        assert_eq!(outcome.placeholders, 1);
        assert_eq!(table.restore(&outcome.text), "abcd");
    }

    #[test]
    fn builtin_engine_masks_secrets_when_enabled() {
        let mut table = PlaceholderTable::with_seed(7);
        let config = enabled_config();
        let outcome = Engine::with_builtin(&config).mask_text(
            "OPENAI_API_KEY=sk-proj-Qm7vT2xLk9RbW4nZpE6sJc8YhD3fGa5uKiN1oVr0",
            &config,
            &mut table,
        );
        assert!(outcome.text.contains("{{SECRET_"));
        assert!(!outcome.text.contains("sk-proj-"));
    }

    #[test]
    fn builtin_engine_leaves_secrets_when_switched_off() {
        let mut table = PlaceholderTable::with_seed(7);
        let config = RedactConfig {
            enabled: true,
            secrets: false,
            ..Default::default()
        };
        let text = "DB_PASSWORD=Tr0ub4dor&3xyz";
        let outcome = Engine::with_builtin(&config).mask_text(text, &config, &mut table);
        assert_eq!(outcome.text, text);
    }

    #[test]
    fn builtin_engine_masks_personal_data() {
        let mut table = PlaceholderTable::with_seed(7);
        let config = enabled_config();
        let outcome = Engine::with_builtin(&config).mask_text(
            "mail jane.smith@gmail.com or call 415-555-0132",
            &config,
            &mut table,
        );
        assert!(outcome.text.contains("{{EMAIL_"));
        assert!(outcome.text.contains("{{PHONE_"));
        assert!(!outcome.text.contains("jane.smith@gmail.com"));
        assert!(!outcome.text.contains("415-555-0132"));
    }

    #[test]
    fn builtin_engine_masks_custom_words() {
        let mut table = PlaceholderTable::with_seed(7);
        let config = RedactConfig {
            enabled: true,
            words: vec!["秘密项目".to_string()],
            ..Default::default()
        };
        let text = "这是秘密项目，不要外传";
        let outcome = Engine::with_builtin(&config).mask_text(text, &config, &mut table);

        assert!(outcome.text.contains("{{PERSON_"));
        assert!(!outcome.text.contains("秘密项目"));
        assert_eq!(table.restore(&outcome.text), text);
    }

    #[test]
    fn whitelist_keeps_values_untouched() {
        let mut table = PlaceholderTable::with_seed(7);
        let config = RedactConfig {
            enabled: true,
            allow: vec!["jane.smith@gmail.com".to_string()],
            ..Default::default()
        };
        let text = "mail jane.smith@gmail.com";
        let outcome = Engine::with_builtin(&config).mask_text(text, &config, &mut table);

        assert_eq!(outcome.text, text);
        assert!(outcome.hits.is_empty());
    }

    #[test]
    fn custom_rules_support_mask_and_drop() {
        let mut table = PlaceholderTable::with_seed(7);
        let config = RedactConfig {
            enabled: true,
            rules: vec![
                CustomRule {
                    name: "ticket".to_string(),
                    pattern: r"TICKET-[0-9]{6}".to_string(),
                    kind: Kind::Secret,
                    action: Action::Mask,
                },
                CustomRule {
                    name: "temp-path".to_string(),
                    pattern: r"/tmp/[a-z]+".to_string(),
                    kind: Kind::Secret,
                    action: Action::Drop,
                },
            ],
            ..Default::default()
        };
        let outcome = Engine::with_builtin(&config).mask_text(
            "see TICKET-123456 at /tmp/abc",
            &config,
            &mut table,
        );

        assert!(outcome.text.contains("[REDACTED]"));
        assert!(!outcome.text.contains("TICKET-123456"));
        assert!(!outcome.text.contains("/tmp/abc"));
    }
}
