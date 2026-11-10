//! 用户自定义正则规则检测器。
//!
//! 规则由用户显式配置，因此不受 `secrets` / `personal` / `kinds` 开关限制，
//! 只受总开关 `enabled` 控制。无效正则会被跳过并记录警告。

use regex::Regex;

use crate::redact::{Action, CustomRule, Detector, Hit, Kind, RedactConfig};

pub struct CustomRuleDetector {
    rules: Vec<CompiledRule>,
}

struct CompiledRule {
    regex: Regex,
    kind: Kind,
    action: Action,
}

impl CustomRuleDetector {
    pub fn new(rules: &[CustomRule]) -> Self {
        let rules = rules
            .iter()
            .filter_map(|rule| match Regex::new(&rule.pattern) {
                Ok(regex) => Some(CompiledRule {
                    regex,
                    kind: rule.kind,
                    action: rule.action,
                }),
                Err(error) => {
                    log::warn!("忽略无效的脱敏规则 {}: {error}", rule.name);
                    None
                }
            })
            .collect();
        Self { rules }
    }
}

impl Detector for CustomRuleDetector {
    fn detect(&self, text: &str, _config: &RedactConfig) -> Vec<Hit> {
        let mut hits = Vec::new();
        for rule in &self.rules {
            for found in rule.regex.find_iter(text) {
                hits.push(Hit {
                    start: found.start(),
                    end: found.end(),
                    kind: rule.kind,
                    action: rule.action,
                });
            }
        }
        hits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(pattern: &str, kind: Kind, action: Action) -> CustomRule {
        CustomRule {
            name: "test".to_string(),
            pattern: pattern.to_string(),
            kind,
            action,
        }
    }

    #[test]
    fn emits_hits_with_the_configured_kind_and_action() {
        let detector =
            CustomRuleDetector::new(&[rule(r"TICKET-[0-9]{6}", Kind::Secret, Action::Mask)]);
        let config = RedactConfig::default();
        let hits = detector.detect("see TICKET-123456 now", &config);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, Kind::Secret);
        assert_eq!(hits[0].action, Action::Mask);
    }

    #[test]
    fn skips_invalid_patterns() {
        let detector = CustomRuleDetector::new(&[
            rule("(", Kind::Secret, Action::Placeholder),
            rule(r"[0-9]{3}", Kind::Account, Action::Placeholder),
        ]);
        let config = RedactConfig::default();
        let hits = detector.detect("abc 123", &config);

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].kind, Kind::Account);
    }
}
