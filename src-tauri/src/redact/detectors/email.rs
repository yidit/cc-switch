//! 邮箱地址检测器。
//!
//! 评估语料要求排除几类「看起来像邮箱」的文本：媒体文件名（`logo@3x.png`）、
//! SSH 地址（`git@host`）、Git 机器人地址、示例域名，以及 `dependabot[bot]@…`
//! 这类 `@` 前面带方括号的地址。

use std::sync::OnceLock;

use regex::Regex;

use crate::redact::{Action, Detector, Hit, Kind, RedactConfig};

pub struct EmailDetector;

impl Detector for EmailDetector {
    fn detect(&self, text: &str, config: &RedactConfig) -> Vec<Hit> {
        if !config.personal || !kind_enabled(config, Kind::Email) {
            return Vec::new();
        }
        // 简单的前置判断：没有 @ 的文本不可能命中，长上下文里能省掉整个正则扫描。
        if !text.contains('@') {
            return Vec::new();
        }

        let mut hits = Vec::new();
        for found in regex().find_iter(text) {
            if !has_email_boundaries(text, found.start(), found.end()) {
                continue;
            }
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

/// 检查地址两端的边界。
///
/// 正则只匹配地址本身（不吞前后的分隔符），这样相邻的两个地址
/// `a@b.com c@d.com` 都能被找到；边界在匹配之后单独判断。
fn has_email_boundaries(text: &str, start: usize, end: usize) -> bool {
    if let Some(previous) = text[..start].chars().next_back() {
        if previous == ':' {
            // `mailto:` 是地址的一部分，放行；连接串 userinfo（`scheme://user:pass@host`）
            // 里的 `:` 仍然按「匹配从中间开始」排除。
            let before_colon = &text[..start - 1];
            if !before_colon.to_ascii_lowercase().ends_with("mailto") {
                return false;
            }
        } else if previous.is_ascii_alphanumeric()
            || matches!(previous, '.' | '_' | '%' | '+' | '-' | ']' | '/')
        {
            return false;
        }
    }
    if let Some(next) = text[end..].chars().next() {
        if next.is_ascii_alphanumeric() {
            return false;
        }
    }
    true
}

fn regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // 只匹配地址本身，前后边界由 `has_email_boundaries` 判断：
        // - `dependabot[bot]@…` 里的 `]` 会让本地部分无法匹配；
        // - 连接串 userinfo 的 `password@host` 由前导 `:` / `/` 排除；
        // - 相邻地址（逗号、分号或空格分隔）都能各自命中。
        Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
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
    fn detects_addresses_separated_by_a_single_delimiter() {
        assert_eq!(detect("a@b.com c@d.com"), vec!["a@b.com", "c@d.com"]);
        assert_eq!(detect("a@b.com,c@d.com"), vec!["a@b.com", "c@d.com"]);
        assert_eq!(detect("cc: a@b.com;d@e.com"), vec!["a@b.com", "d@e.com"]);
    }

    #[test]
    fn detects_mailto_links() {
        let address = ["alice", "@", "corp.cn"].concat();
        let text = format!("mailto:{address}");
        assert_eq!(detect(&text), vec![address.as_str()]);

        let upper = format!("MAILTO:{address}");
        assert_eq!(detect(&upper), vec![address.as_str()]);
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
