//! 自定义屏蔽词检测器。
//!
//! 词按 PERSON 记录。中文没有词边界，含非 ASCII 的词始终按子串匹配；
//! 纯 ASCII 词在 `words_whole` 开启时使用 `\b` 边界。

use std::sync::{Arc, Mutex};

use regex::Regex;

use crate::redact::{Action, Detector, Hit, Kind, RedactConfig};

/// 最近一次编译结果。
///
/// 每个代理请求都会重建一次 [`crate::redact::Engine`]；词表通常不变，重新编译
/// 这些正则纯属浪费。设置很少变动，单槽缓存就足够：配置变化时自然失配重建。
static CACHE: Mutex<Option<CacheEntry>> = Mutex::new(None);

struct CacheEntry {
    /// 编译时使用的词表快照，用于判断配置是否变化。
    words: Vec<String>,
    any_case: bool,
    whole: bool,
    patterns: Arc<Vec<Regex>>,
}

pub struct WordDetector {
    patterns: Arc<Vec<Regex>>,
}

impl WordDetector {
    pub fn new(words: &[String], any_case: bool, whole: bool) -> Self {
        let mut cache = CACHE.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(entry) = cache.as_ref() {
            // 逐项比较而不是先克隆词表：命中路径上不产生分配。
            if entry.any_case == any_case
                && entry.whole == whole
                && entry.words.len() == words.len()
                && entry
                    .words
                    .iter()
                    .zip(words)
                    .all(|(cached, word)| cached == word)
            {
                return Self {
                    patterns: Arc::clone(&entry.patterns),
                };
            }
        }

        let patterns = Arc::new(compile(words, any_case, whole));
        *cache = Some(CacheEntry {
            words: words.to_vec(),
            any_case,
            whole,
            patterns: Arc::clone(&patterns),
        });
        Self { patterns }
    }
}

fn compile(words: &[String], any_case: bool, whole: bool) -> Vec<Regex> {
    words
        .iter()
        .filter(|word| !word.is_empty())
        .filter_map(|word| {
            let escaped = regex::escape(word);
            let pattern = if whole && word.is_ascii() {
                format!(r"\b{escaped}\b")
            } else {
                escaped
            };
            let pattern = if any_case {
                format!("(?i){pattern}")
            } else {
                pattern
            };
            Regex::new(&pattern).ok()
        })
        .collect()
}

impl Detector for WordDetector {
    fn detect(&self, text: &str, config: &RedactConfig) -> Vec<Hit> {
        // 词按 PERSON 记录，因此受「个人信息」与 PERSON 类型开关控制。
        if !config.personal || !kind_enabled(config, Kind::Person) {
            return Vec::new();
        }
        let mut hits = Vec::new();
        for regex in self.patterns.iter() {
            for found in regex.find_iter(text) {
                hits.push(Hit {
                    start: found.start(),
                    end: found.end(),
                    kind: Kind::Person,
                    action: Action::Placeholder,
                });
            }
        }
        hits
    }
}

/// 配置里的 `kinds` 是否允许该类型；空列表表示全部允许。
fn kind_enabled(config: &RedactConfig, kind: Kind) -> bool {
    config.kinds.is_empty() || config.kinds.contains(&kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect<'a>(text: &'a str, words: &[&str], any_case: bool, whole: bool) -> Vec<&'a str> {
        let config = RedactConfig {
            enabled: true,
            ..Default::default()
        };
        let words: Vec<String> = words.iter().map(|w| w.to_string()).collect();
        WordDetector::new(&words, any_case, whole)
            .detect(text, &config)
            .into_iter()
            .map(|hit| &text[hit.start..hit.end])
            .collect()
    }

    #[test]
    fn matches_ascii_words_at_boundaries() {
        assert_eq!(
            detect("secretary and secret", &["secret"], false, true),
            vec!["secret"]
        );
        assert_eq!(
            detect("secretary and secret", &["secret"], false, false),
            vec!["secret", "secret"]
        );
    }

    #[test]
    fn matches_case_insensitively_when_asked() {
        assert_eq!(
            detect("SeCrEt here", &["secret"], true, true),
            vec!["SeCrEt"]
        );
        assert!(detect("SeCrEt here", &["secret"], false, true).is_empty());
    }

    #[test]
    fn matches_chinese_words_without_boundaries() {
        assert_eq!(
            detect("这是秘密项目，不要外传", &["秘密项目"], false, true),
            vec!["秘密项目"]
        );
    }

    #[test]
    fn recompiles_when_the_configuration_changes() {
        // 缓存要随配置换键：大小写开关不同，匹配结果必须跟着变，
        // 切回旧配置时也不能沿用上一份正则。
        let words = vec!["Secret".to_string()];
        let config = RedactConfig {
            enabled: true,
            ..Default::default()
        };
        let case_insensitive = WordDetector::new(&words, true, true);
        let case_sensitive = WordDetector::new(&words, false, true);

        assert_eq!(case_insensitive.detect("secret here", &config).len(), 1);
        assert!(case_sensitive.detect("secret here", &config).is_empty());
        assert_eq!(
            WordDetector::new(&words, true, true)
                .detect("secret here", &config)
                .len(),
            1
        );
    }
}
