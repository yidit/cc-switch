//! 邮箱地址检测器。
//!
//! 评估语料要求排除几类「看起来像邮箱」的文本：媒体文件名（`logo@3x.png`）、
//! SSH 地址（`git@host`）、Git 机器人地址、示例域名，以及 `dependabot[bot]@…`
//! 这类本地部分带方括号的地址。

use std::sync::OnceLock;

use regex::Regex;

use crate::redact::{Action, Detector, Hit, Kind, RedactConfig};

pub struct EmailDetector;

impl Detector for EmailDetector {
    fn detect(&self, text: &str, config: &RedactConfig) -> Vec<Hit> {
        if !config.personal || !kind_enabled(config, Kind::Email) {
            return Vec::new();
        }
        // 廉价前置判断：没有 @ 的文本不可能命中，长上下文里能省掉整个正则扫描。
        if !text.contains('@') {
            return Vec::new();
        }

        let mut hits = Vec::new();
        for captures in regex().captures_iter(text) {
            let Some(found) = captures.get(1) else {
                continue;
            };
            if !plausible_email(found.as_str()) {
                continue;
            }
            hits.push(Hit {
                start: found.start(),
                end: found.end(),
                kind: Kind::Email,
                action: Action::Placeholder,
            });
        }
        hits
    }
}

fn regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // 前导字符不能是本地部分字符、`]`、`:` 或 `/`：
        // - 排除 `dependabot[bot]@…` 的 `bot@…` 片段；
        // - 排除连接串 userinfo 里的 `password@host`。
        // 结尾要求非字母数字或文本结束，避免把 `intro@2x.mp4` 截成 `intro@2x.mp`。
        Regex::new(
            r"(?:^|[^A-Za-z0-9._%+\-\[\]:/])([A-Za-z0-9._%+\-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})(?:[^A-Za-z0-9]|$)",
        )
        .expect("邮箱正则应始终合法")
    })
}

/// 配置里的 `kinds` 是否允许该类型；空列表表示全部允许。
fn kind_enabled(config: &RedactConfig, kind: Kind) -> bool {
    config.kinds.is_empty() || config.kinds.contains(&kind)
}

fn plausible_email(value: &str) -> bool {
    let Some((local, domain)) = value.rsplit_once('@') else {
        return false;
    };
    let local = local.to_ascii_lowercase();
    let domain = domain.to_ascii_lowercase();

    // SSH 地址：git@host
    if local == "git" {
        return false;
    }
    // Git 机器人地址：deploy-bot@git.acme-corp.cn
    if local.ends_with("bot") && domain.starts_with("git.") {
        return false;
    }
    // 文档示例域名。
    if is_example_domain(&domain) {
        return false;
    }
    // GitHub noreply 地址。
    if domain == "users.noreply.github.com" || domain.ends_with(".users.noreply.github.com") {
        return false;
    }
    // 媒体文件名：logo@3x.png / intro@2x.mp4
    if is_media_scale_domain(&domain) {
        return false;
    }

    true
}

fn is_example_domain(domain: &str) -> bool {
    ["example.com", "example.org", "example.net"]
        .iter()
        .any(|base| domain == *base || domain.ends_with(&format!(".{base}")))
}

/// `2x.jpg`、`3x.png` 这类分辨率后缀不是邮箱域名。
fn is_media_scale_domain(domain: &str) -> bool {
    let Some((stem, ext)) = domain.rsplit_once('.') else {
        return false;
    };
    let scale = stem.split('.').next().unwrap_or(stem);
    let Some(digits) = scale.strip_suffix('x') else {
        return false;
    };
    digits.bytes().all(|b| b.is_ascii_digit())
        && matches!(
            ext,
            "png" | "jpg" | "jpeg" | "gif" | "webp" | "svg" | "mp4" | "mov" | "webm" | "avi"
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
        EmailDetector
            .detect(text, &config)
            .into_iter()
            .map(|hit| &text[hit.start..hit.end])
            .collect()
    }

    #[test]
    fn detects_ordinary_addresses() {
        assert_eq!(
            detect("Contact jane.smith@gmail.com for details."),
            vec!["jane.smith@gmail.com"]
        );
        assert_eq!(
            detect("li.na@qq.com 和 omar.haddad@proton.me"),
            vec!["li.na@qq.com", "omar.haddad@proton.me"]
        );
    }

    #[test]
    fn ignores_media_file_names() {
        assert!(detect("![shot](/tmp/261020_14-16-11@2x.jpg)").is_empty());
        assert!(detect("import logo from './assets/logo@3x.png';").is_empty());
        assert!(detect("import intro from './media/intro@2x.mp4';").is_empty());
    }

    #[test]
    fn ignores_ssh_and_bot_addresses() {
        assert!(detect("git clone https://git@gitlab.acme-corp.cn/team/repo.git").is_empty());
        assert!(detect("deploy-bot@git.acme-corp.cn").is_empty());
        assert!(detect(
            "Author: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>"
        )
        .is_empty());
    }

    #[test]
    fn ignores_url_userinfo() {
        assert!(
            detect("DATABASE_URL=postgres://app:hunter2pass@db.acme-corp.cn:5432/orders")
                .is_empty()
        );
    }

    #[test]
    fn ignores_example_and_cache_names() {
        assert!(detect("// e.g. send(\"user@example.com\", subject)").is_empty());
        assert!(detect("open /Users/x/Library/Caches/go-build/63700b7ab65fd1d3@v63").is_empty());
    }

    #[test]
    fn respects_personal_and_kinds_switches() {
        let text = "jane.smith@gmail.com";
        let off = RedactConfig {
            enabled: true,
            personal: false,
            ..Default::default()
        };
        assert!(EmailDetector.detect(text, &off).is_empty());

        let limited = RedactConfig {
            enabled: true,
            kinds: vec![Kind::Phone],
            ..Default::default()
        };
        assert!(EmailDetector.detect(text, &limited).is_empty());
    }
}
