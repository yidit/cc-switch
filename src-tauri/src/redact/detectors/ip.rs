//! 公网 IPv4 检测器。
//!
//! 回环、未指定与广播地址不指向具体主机，本地开发里随处可见，不算个人信息。

use std::net::Ipv4Addr;
use std::sync::OnceLock;

use regex::Regex;

use crate::redact::{Action, Detector, Hit, Kind, RedactConfig};

pub struct IpDetector;

impl Detector for IpDetector {
    fn detect(&self, text: &str, config: &RedactConfig) -> Vec<Hit> {
        if !config.personal || !kind_enabled(config, Kind::Ip) {
            return Vec::new();
        }
        // 没有点的文本不可能出现 IPv4。
        if !text.contains('.') {
            return Vec::new();
        }

        let mut hits = Vec::new();
        for found in regex().find_iter(text) {
            if !ip_bounded(text, found.start(), found.end()) {
                continue;
            }
            if is_non_identifying(found.as_str()) {
                continue;
            }
            hits.push(Hit {
                start: found.start(),
                end: found.end(),
                kind: Kind::Ip,
                action: Action::Placeholder,
            });
        }
        hits
    }
}

fn regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])",
        )
        .expect("IPv4 正则应始终合法")
    })
}

/// 两侧不能紧邻数字或点，避免从更长的数字/版本号中间截取。
fn ip_bounded(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    let bad = |ch: Option<char>| ch.is_some_and(|c| c.is_ascii_digit() || c == '.');
    !bad(before) && !bad(after)
}

fn is_non_identifying(value: &str) -> bool {
    value
        .parse::<Ipv4Addr>()
        .is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified() || ip.is_broadcast())
}

/// 配置里的 `kinds` 是否允许该类型；空列表表示全部允许。
fn kind_enabled(config: &RedactConfig, kind: Kind) -> bool {
    config.kinds.is_empty() || config.kinds.contains(&kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(text: &str) -> Vec<&str> {
        let config = RedactConfig {
            enabled: true,
            ..Default::default()
        };
        IpDetector
            .detect(text, &config)
            .into_iter()
            .map(|hit| &text[hit.start..hit.end])
            .collect()
    }

    #[test]
    fn detects_public_and_private_addresses() {
        assert_eq!(detect("server 203.0.113.42"), vec!["203.0.113.42"]);
        assert_eq!(detect("gateway 192.168.1.1"), vec!["192.168.1.1"]);
    }

    #[test]
    fn ignores_non_identifying_addresses() {
        assert!(detect("localhost 127.0.0.1").is_empty());
        assert!(detect("bind 0.0.0.0").is_empty());
        assert!(detect("broadcast 255.255.255.255").is_empty());
    }

    #[test]
    fn ignores_versions_and_longer_numbers() {
        assert!(detect("version 1.2.3.4.5").is_empty());
        assert!(detect("build 10.20.30.40.50").is_empty());
        assert!(detect("1761379200123").is_empty());
    }

    #[test]
    fn respects_personal_and_kinds_switches() {
        let text = "203.0.113.42";
        let off = RedactConfig {
            enabled: true,
            personal: false,
            ..Default::default()
        };
        assert!(IpDetector.detect(text, &off).is_empty());

        let limited = RedactConfig {
            enabled: true,
            kinds: vec![Kind::Email],
            ..Default::default()
        };
        assert!(IpDetector.detect(text, &limited).is_empty());
    }
}
