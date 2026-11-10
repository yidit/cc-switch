//! 账户类信息检测器：银行卡、IBAN、中国大陆身份证号。
//!
//! 三者都带结构校验（Luhn、IBAN mod-97、身份证校验位），只靠格式的
//! 数字串不会命中。

use std::sync::OnceLock;

use regex::Regex;

use crate::redact::{Action, Detector, Hit, Kind, RedactConfig};

pub struct AccountDetector;

impl Detector for AccountDetector {
    fn detect(&self, text: &str, config: &RedactConfig) -> Vec<Hit> {
        if !config.personal || !kind_enabled(config, Kind::Account) {
            return Vec::new();
        }

        let mut hits = Vec::new();
        for rule in rules() {
            for found in rule.regex.find_iter(text) {
                let value = found.as_str();
                if !(rule.validate)(value) {
                    continue;
                }
                hits.push(Hit {
                    start: found.start(),
                    end: found.end(),
                    kind: Kind::Account,
                    action: Action::Placeholder,
                });
            }
        }
        hits.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
        hits.dedup();
        hits
    }
}

struct Rule {
    regex: Regex,
    validate: fn(&str) -> bool,
}

fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        vec![
            // 4-4-4-4 分组的银行卡号。
            Rule {
                regex: Regex::new(r"\b(?:\d{4}[ -]){3}\d{4}\b").expect("银行卡正则应始终合法"),
                validate: luhn,
            },
            // IBAN：国家代码 + 校验位 + 分段；可带空格或连写。
            Rule {
                regex: Regex::new(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{1,4}){2,8}\b")
                    .expect("IBAN 正则应始终合法"),
                validate: valid_iban,
            },
            // 中国大陆 18 位身份证号。
            Rule {
                regex: Regex::new(r"\b\d{17}[\dXx]\b").expect("身份证正则应始终合法"),
                validate: valid_id_card,
            },
        ]
    })
}

fn kind_enabled(config: &RedactConfig, kind: Kind) -> bool {
    config.kinds.is_empty() || config.kinds.contains(&kind)
}

/// Luhn 校验；同时要求至少 13 位数字。
fn luhn(value: &str) -> bool {
    let digits: Vec<u32> = value
        .chars()
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() < 13 {
        return false;
    }

    let mut sum = 0;
    for (index, digit) in digits.iter().rev().enumerate() {
        let mut digit = *digit;
        if index % 2 == 1 {
            digit *= 2;
            if digit > 9 {
                digit -= 9;
            }
        }
        sum += digit;
    }
    sum % 10 == 0
}

/// IBAN：长度 15–34，重排后按 mod 97 计算应等于 1。
fn valid_iban(value: &str) -> bool {
    let compact: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    if !(15..=34).contains(&compact.len()) {
        return false;
    }
    if !compact
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return false;
    }

    let (head, tail) = compact.split_at(4);
    let mut remainder: u32 = 0;
    for ch in tail.chars().chain(head.chars()) {
        if let Some(digit) = ch.to_digit(10) {
            remainder = (remainder * 10 + digit) % 97;
        } else {
            let number = ch as u32 - 'A' as u32 + 10;
            remainder = (remainder * 100 + number) % 97;
        }
    }
    remainder == 1
}

/// 中国大陆 18 位身份证号：前 17 位加权求和后取模 11，末位为校验码。
fn valid_id_card(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 18 {
        return false;
    }

    const WEIGHTS: [u32; 17] = [
        7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2,
    ];
    const CHECK_CODES: &[u8; 11] = b"10X98765432";

    let mut sum = 0;
    for (index, weight) in WEIGHTS.iter().enumerate() {
        let Some(digit) = bytes[index].checked_sub(b'0') else {
            return false;
        };
        if digit > 9 {
            return false;
        }
        sum += (digit as u32) * weight;
    }

    let expected = CHECK_CODES[(sum % 11) as usize];
    bytes[17].to_ascii_uppercase() == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(text: &str) -> Vec<&str> {
        let config = RedactConfig {
            enabled: true,
            ..Default::default()
        };
        AccountDetector
            .detect(text, &config)
            .into_iter()
            .map(|hit| &text[hit.start..hit.end])
            .collect()
    }

    #[test]
    fn detects_bank_card_iban_and_id_card() {
        assert_eq!(
            detect("card 4111 1111 1111 1111"),
            vec!["4111 1111 1111 1111"]
        );
        assert_eq!(
            detect("IBAN DE89 3704 0044 0532 0130 00"),
            vec!["DE89 3704 0044 0532 0130 00"]
        );
        assert_eq!(
            detect("身份证号 11010519491231002X，开户行"),
            vec!["11010519491231002X"]
        );
    }

    #[test]
    fn ignores_plain_numbers_and_hashes() {
        assert!(detect("1761379200123").is_empty());
        assert!(detect("14902266").is_empty());
        assert!(detect("0x004EA5E0").is_empty());
        assert!(detect(
            "b855cfee9a1c3d4e5f60718293a4b5c6d7e8f901"
        )
        .is_empty());
        assert!(detect("call_Qm7vT2xLk9RbW4nZ").is_empty());
    }

    #[test]
    fn rejects_numbers_that_fail_checksums() {
        // 格式像银行卡，但 Luhn 不通过。
        assert!(detect("1234 5678 9012 3456").is_empty());
        // 格式像身份证，但校验位不对。
        assert!(detect("110105194912310021").is_empty());
    }

    #[test]
    fn respects_personal_and_kinds_switches() {
        let text = "4111 1111 1111 1111";
        let off = RedactConfig {
            enabled: true,
            personal: false,
            ..Default::default()
        };
        assert!(AccountDetector.detect(text, &off).is_empty());

        let limited = RedactConfig {
            enabled: true,
            kinds: vec![Kind::Email],
            ..Default::default()
        };
        assert!(AccountDetector.detect(text, &limited).is_empty());
    }
}
