//! 电话号码检测器。
//!
//! 只匹配带分隔符的号码、分组号码与中国大陆手机号，避免把时间戳、端口、
//! 版本号和尺寸当成电话（评估语料对这些 `keep` 值有硬约束）。

use std::sync::OnceLock;

use regex::Regex;

use crate::redact::{Action, Detector, Hit, Kind, RedactConfig};

pub struct PhoneDetector;

impl Detector for PhoneDetector {
    fn detect(&self, text: &str, config: &RedactConfig) -> Vec<Hit> {
        if !config.personal || !kind_enabled(config, Kind::Phone) {
            return Vec::new();
        }
        // 简单的前置判断：没有数字的文本不可能命中。
        if !text.bytes().any(|byte| byte.is_ascii_digit()) {
            return Vec::new();
        }

        let mut hits = Vec::new();
        for regex in regexes() {
            for found in regex.find_iter(text) {
                if !plausible_phone(found.as_str()) {
                    continue;
                }
                hits.push(Hit {
                    start: found.start(),
                    end: found.end(),
                    kind: Kind::Phone,
                    action: Action::Placeholder,
                });
            }
        }
        // 长区间排在前面，便于下面剔除被它包含的短匹配。
        hits.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
        hits.dedup();

        // 同一条号码会被多个正则命中（如 `415-555-0132` 里还包含
        // `555-0132`），只保留最长的那个。
        let mut kept: Vec<Hit> = Vec::with_capacity(hits.len());
        for hit in hits {
            if kept
                .last()
                .is_some_and(|last| hit.start >= last.start && hit.end <= last.end)
            {
                continue;
            }
            kept.push(hit);
        }
        kept
    }
}

fn regexes() -> &'static [Regex] {
    static RES: OnceLock<Vec<Regex>> = OnceLock::new();
    RES.get_or_init(|| {
        [
            // 415-555-0132 / 415 555 0132 / 90-1234-5678 / 139 1234 5678
            r"\b\d{2,4}[- ]\d{3,4}[- ]\d{3,4}\b",
            // 555-0199 / 555 0199
            r"\b\d{3}[- ]\d{4}\b",
            // 7700 900123
            r"\b\d{4} \d{6}\b",
            // 中国大陆手机号（11 位，1 开头，第二位 3-9）
            r"\b1[3-9]\d{9}\b",
        ]
        .iter()
        .map(|pattern| Regex::new(pattern).expect("电话正则应始终合法"))
        .collect()
    })
}

fn kind_enabled(config: &RedactConfig, kind: Kind) -> bool {
    config.kinds.is_empty() || config.kinds.contains(&kind)
}

fn plausible_phone(value: &str) -> bool {
    let digits = value.chars().filter(|c| c.is_ascii_digit()).count();
    if !(7..=15).contains(&digits) {
        return false;
    }
    if value.contains('.') {
        return false;
    }
    // 全 0 不是电话号码。
    !value
        .chars()
        .filter(|c| c.is_ascii_digit())
        .all(|c| c == '0')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(text: &str) -> Vec<&str> {
        let config = RedactConfig {
            enabled: true,
            ..Default::default()
        };
        PhoneDetector
            .detect(text, &config)
            .into_iter()
            .map(|hit| &text[hit.start..hit.end])
            .collect()
    }

    #[test]
    fn detects_separated_numbers() {
        assert_eq!(detect("Call 415-555-0132 now"), vec!["415-555-0132"]);
        assert_eq!(detect("号码 139 1234 5678"), vec!["139 1234 5678"]);
        assert_eq!(detect("tel: 90-1234-5678"), vec!["90-1234-5678"]);
        assert_eq!(detect("dial 7700 900123"), vec!["7700 900123"]);
    }

    #[test]
    fn detects_short_and_mobile_numbers() {
        assert_eq!(detect("zip 555-0199"), vec!["555-0199"]);
        assert_eq!(detect("手机 13800138000"), vec!["13800138000"]);
        assert_eq!(detect("Call +1 415-555-0132"), vec!["415-555-0132"]);
    }

    #[test]
    fn ignores_timestamps_ports_and_versions() {
        assert!(detect("ts 1761379200").is_empty());
        assert!(detect("ts 1761379200123").is_empty());
        assert!(detect("port 3425, retry 30000ms").is_empty());
        assert!(detect("pid 48213, exit status 2").is_empty());
        assert!(detect("go1.26.8 on darwin/arm64").is_empty());
        assert!(detect("1624x1487 at 2x").is_empty());
        assert!(detect("1.0833333333333333").is_empty());
    }

    #[test]
    fn ignores_unseparated_id_like_numbers() {
        assert!(detect("run 48213097715").is_empty());
        assert!(detect("6123456789").is_empty());
        assert!(detect("1792903687").is_empty());
    }

    #[test]
    fn respects_personal_and_kinds_switches() {
        let text = "415-555-0132";
        let off = RedactConfig {
            enabled: true,
            personal: false,
            ..Default::default()
        };
        assert!(PhoneDetector.detect(text, &off).is_empty());

        let limited = RedactConfig {
            enabled: true,
            kinds: vec![Kind::Email],
            ..Default::default()
        };
        assert!(PhoneDetector.detect(text, &limited).is_empty());
    }
}
