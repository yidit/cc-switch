//! 自定义屏蔽词检测器。
//!
//! 词按 PERSON 记录。中文没有词边界，含非 ASCII 的词始终按子串匹配；
//! 纯 ASCII 词在 `words_whole` 开启时使用 `\b` 边界。

use regex::Regex;

use crate::redact::{Action, Detector, Hit, Kind, RedactConfig};

pub struct WordDetector {
    patterns: Vec<Regex>,
}

impl WordDetector {
    pub fn new(words: &[String], any_case: bool, whole: bool) -> Self {
        let patterns = words
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
            .collect();
        Self { patterns }
    }
}

impl Detector for WordDetector {
    fn detect(&self, text: &str, _config: &RedactConfig) -> Vec<Hit> {
        let mut hits = Vec::new();
        for regex in &self.patterns {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(text: &str, words: &[&str], any_case: bool, whole: bool) -> Vec<&str> {
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
}
