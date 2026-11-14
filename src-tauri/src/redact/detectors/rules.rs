//! 用户自定义正则规则检测器。
//!
//! 规则由用户显式配置，因此不受 `secrets` / `personal` / `kinds` 开关限制，
//! 只受总开关 `enabled` 控制。无效正则会被跳过并记录警告。

use std::sync::{Arc, Mutex};

use regex::Regex;

use crate::redact::{Action, CustomRule, Detector, Hit, Kind, RedactConfig};

/// 最近一次编译结果。
///
/// 每个代理请求都会重建一次引擎，而 [`invalid_rules`] 与
/// [`CustomRuleDetector::new`] 又要各编译一遍同样的规则。规则只在设置变化时
/// 才会变，单槽缓存一份即可：配置变化时自然失配重建。
static CACHE: Mutex<Option<CacheEntry>> = Mutex::new(None);

struct CacheEntry {
    /// 编译时使用的规则快照（正则 + 命中类型 + 动作），用于判断配置是否变化。
    key: Vec<(String, Kind, Action)>,
    compiled: Arc<Compiled>,
}

struct Compiled {
    rules: Vec<CompiledRule>,
    /// 无法使用的规则说明，顺序与配置中的规则一致。
    errors: Vec<String>,
}

struct CompiledRule {
    regex: Regex,
    kind: Kind,
    action: Action,
}

pub struct CustomRuleDetector {
    compiled: Arc<Compiled>,
}

impl CustomRuleDetector {
    pub fn new(rules: &[CustomRule]) -> Self {
        Self {
            compiled: compiled(rules),
        }
    }
}

/// 取当前配置的编译结果：命中缓存时直接复用，不再重新编译。
fn compiled(rules: &[CustomRule]) -> Arc<Compiled> {
    let mut cache = CACHE.lock().unwrap_or_else(|error| error.into_inner());
    if let Some(entry) = cache.as_ref() {
        // 逐项比较而不是先克隆规则：命中路径上不产生分配。
        if entry.key.len() == rules.len()
            && entry
                .key
                .iter()
                .zip(rules)
                .all(|((pattern, kind, action), rule)| {
                    pattern == &rule.pattern && *kind == rule.kind && *action == rule.action
                })
        {
            return Arc::clone(&entry.compiled);
        }
    }

    let compiled = Arc::new(compile_all(rules));
    *cache = Some(CacheEntry {
        key: rules
            .iter()
            .map(|rule| (rule.pattern.clone(), rule.kind, rule.action))
            .collect(),
        compiled: Arc::clone(&compiled),
    });
    compiled
}

fn compile_all(rules: &[CustomRule]) -> Compiled {
    let mut compiled = Vec::new();
    let mut errors = Vec::new();
    for rule in rules {
        if rule.pattern.trim().is_empty() {
            continue;
        }
        match compile(rule) {
            Ok(regex) => compiled.push(CompiledRule {
                regex,
                kind: rule.kind,
                action: rule.action,
            }),
            Err(error) => {
                let message = error.message(&rule.name);
                // 只在配置变化（缓存重建）时记录一次，避免每个请求都刷同样的警告。
                log::warn!("忽略无效的脱敏规则: {message}");
                errors.push(message);
            }
        }
    }
    Compiled {
        rules: compiled,
        errors,
    }
}

fn compile(rule: &CustomRule) -> Result<Regex, RuleError> {
    if rule.pattern.trim().is_empty() {
        return Err(RuleError::Empty);
    }
    Regex::new(&rule.pattern).map_err(|error| RuleError::Invalid(error.to_string()))
}

/// 规则不可用的原因。
enum RuleError {
    /// 正则为空，匹配不到任何有效区间。
    Empty,
    /// 正则无法编译。
    Invalid(String),
}

impl RuleError {
    fn message(&self, name: &str) -> String {
        match self {
            RuleError::Empty => format!("规则 {name} 的正则为空"),
            RuleError::Invalid(error) => format!("规则 {name}: {error}"),
        }
    }
}

/// 列出配置里无法使用的规则。
///
/// 空正则代表「刚添加、还没填」，不算错误：默认 `failClosed` 下把它当无效规则
/// 会让用户点一下「添加规则」就拒绝所有请求。空规则由引擎直接跳过。
/// 无法编译的正则仍会列出；`failClosed` 开启时，调用方应据此拒绝请求，
/// 避免用户以为敏感信息已被处理、实际上原文被发了出去。
pub fn invalid_rules(rules: &[CustomRule]) -> Vec<String> {
    compiled(rules).errors.clone()
}

impl Detector for CustomRuleDetector {
    fn detect(&self, text: &str, _config: &RedactConfig) -> Vec<Hit> {
        let mut hits = Vec::new();
        for rule in &self.compiled.rules {
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

    #[test]
    fn reports_uncompilable_rules_and_ignores_empty_ones() {
        let messages = invalid_rules(&[
            rule("(", Kind::Secret, Action::Placeholder),
            rule("   ", Kind::Secret, Action::Placeholder),
            rule(r"\d+", Kind::Secret, Action::Placeholder),
        ]);

        assert_eq!(messages.len(), 1, "{messages:?}");
        assert!(messages[0].contains("规则 test"));
    }

    #[test]
    fn cache_follows_rule_changes() {
        // 缓存要随规则换键：改过正则之后不能沿用上一份编译结果。
        let config = RedactConfig::default();
        let first =
            CustomRuleDetector::new(&[rule(r"TICKET-[0-9]{6}", Kind::Secret, Action::Mask)]);
        assert_eq!(first.detect("TICKET-123456", &config).len(), 1);

        let second =
            CustomRuleDetector::new(&[rule(r"TICKET-[0-9]{8}", Kind::Secret, Action::Mask)]);
        assert!(second.detect("TICKET-123456", &config).is_empty());
        assert_eq!(
            invalid_rules(&[rule(r"TICKET-[0-9]{8}", Kind::Secret, Action::Mask)]).len(),
            0
        );
    }
}
