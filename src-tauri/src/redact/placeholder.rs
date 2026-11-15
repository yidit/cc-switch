//! 占位符生成、映射与还原。
//!
//! 格式与 magpie 一致：`{{KIND_xxxxxxxx}}`，后缀为 8 位 base32 字符
//! （`a-z2-7`）。同一张表内，相同的原值复用同一个占位符；配置了盐值时，
//! 不同请求之间也保持一致。

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::types::{Kind, RedactConfig};

/// RFC 4648 base32 的小写字母表。
const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// 占位符长度（`{{` + KIND + `_` + 8 位 + `}}` 中后缀的位数）。
const SUFFIX_LEN: usize = 8;

/// 一次请求（或一个会话）内的占位符映射。
pub struct PlaceholderTable {
    /// 原值 → 占位符。
    forward: HashMap<String, String>,
    /// 占位符 → 原值。
    backward: HashMap<String, String>,
    source: Source,
}

/// 占位符后缀的来源。
enum Source {
    /// 每次请求随机生成（没有配置盐值时使用）。
    Random(Rng),
    /// 用本机盐值计算：相同盐值下，相同原值总是得到相同占位符。
    Salted(Vec<u8>),
}

impl PlaceholderTable {
    /// 用系统随机源创建。
    pub fn new() -> Self {
        Self::from_rng(Rng::new())
    }

    /// 用固定种子创建，便于测试复现。
    pub fn with_seed(seed: u64) -> Self {
        Self::from_rng(Rng::from_seed(seed))
    }

    /// 用本机盐值创建：`salt` 相同、原值相同时，不同请求会得到同一个占位符。
    ///
    /// 这样上游的提示缓存和会话指纹不会因为占位符变化而失效；盐值由本机随机
    /// 生成，随设置一起保存，不同设备之间互不相同。
    pub fn with_salt(salt: &str) -> Self {
        Self {
            forward: HashMap::new(),
            backward: HashMap::new(),
            source: Source::Salted(salt.as_bytes().to_vec()),
        }
    }

    /// 按配置里的盐值创建；旧配置没有盐值时，退化为每次请求随机。
    pub fn from_config(config: &RedactConfig) -> Self {
        match config.salt.as_deref() {
            Some(salt) => Self::with_salt(salt),
            None => Self::new(),
        }
    }

    fn from_rng(rng: Rng) -> Self {
        Self {
            forward: HashMap::new(),
            backward: HashMap::new(),
            source: Source::Random(rng),
        }
    }

    /// 为 `value` 取得占位符；同一原值总是得到同一个结果。
    pub fn placeholder_for(&mut self, value: &str, kind: Kind) -> String {
        if let Some(existing) = self.forward.get(value) {
            return existing.clone();
        }

        let mut attempt = 0u32;
        let placeholder = loop {
            let suffix = match &mut self.source {
                Source::Random(rng) => rng.base32(SUFFIX_LEN),
                Source::Salted(salt) => salted_suffix(salt, kind, value, attempt),
            };
            let candidate = format!("{{{{{}_{}}}}}", kind.as_str(), suffix);
            if !self.backward.contains_key(&candidate) {
                break candidate;
            }
            // 后缀只有 40 bit，发生重复的概率极低；换一组输入重新计算即可。
            attempt = attempt.wrapping_add(1);
        };

        self.forward.insert(value.to_string(), placeholder.clone());
        self.backward.insert(placeholder.clone(), value.to_string());
        placeholder
    }

    /// 把文本中的占位符还原为原值。
    ///
    /// 单次扫描 `{{...}}` 片段并查表：不逐项 `contains`/`replace`（占位符多时
    /// 是 O(n·m)），也不会把还原出来的原值再当成占位符二次替换。表中没有的
    /// `{{...}}` 保持原样。
    pub fn restore(&self, text: &str) -> String {
        if self.backward.is_empty() || !text.contains("{{") {
            return text.to_string();
        }

        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(open) = rest.find("{{") {
            out.push_str(&rest[..open]);
            let tail = &rest[open..];
            let candidate = tail.find("}}").map(|end| end + 2);
            if let Some(end) = candidate {
                if let Some(value) = self.backward.get(&tail[..end]) {
                    out.push_str(value);
                    rest = &tail[end..];
                    continue;
                }
            }
            // 不是已知占位符：先输出第一个 `{`，从下一个字符继续，
            // 这样 `{{{{...}}` 之类的重叠也能正确前进。
            out.push('{');
            rest = &tail[1..];
        }
        out.push_str(rest);
        out
    }

    /// 已记录的原值数量。
    pub fn len(&self) -> usize {
        self.forward.len()
    }

    pub fn is_empty(&self) -> bool {
        self.forward.is_empty()
    }
}

impl Default for PlaceholderTable {
    fn default() -> Self {
        Self::new()
    }
}

/// 小型 xorshift64* 随机数生成器。
///
/// 占位符只需要不可预测且唯一，不用于安全用途；不引入额外依赖。
struct Rng {
    state: u64,
}

impl Rng {
    fn new() -> Self {
        let uuid = Uuid::new_v4();
        let bytes: [u8; 8] = uuid.as_bytes()[..8].try_into().expect("UUID 至少 8 字节");
        Self::from_seed(u64::from_le_bytes(bytes))
    }

    fn from_seed(seed: u64) -> Self {
        Self {
            // 状态不能为 0，否则 xorshift 永远输出 0。
            state: seed.max(1),
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// 生成 `len` 位 base32 字符串。
    fn base32(&mut self, len: usize) -> String {
        let mut out = String::with_capacity(len);
        while out.len() < len {
            let mut bits = self.next_u64();
            // 每轮最多取 12 个 5 位组（64 / 5 = 12.8）。
            for _ in 0..13 {
                out.push(ALPHABET[(bits & 31) as usize] as char);
                bits >>= 5;
                if out.len() == len {
                    break;
                }
            }
        }
        out
    }
}

/// 根据「盐值 + 类型 + 原值 + 尝试次数」计算 8 位 base32 后缀。
///
/// 取 SHA-256 的前 5 字节（40 bit）映射到 base32 字母表；同一输入结果固定。
fn salted_suffix(salt: &[u8], kind: Kind, value: &str, attempt: u32) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(kind.as_str().as_bytes());
    // 用 0 分隔，避免 `kind` 与 `value` 拼接后产生歧义。
    hasher.update([0u8]);
    hasher.update(value.as_bytes());
    hasher.update(attempt.to_le_bytes());
    let digest = hasher.finalize();

    let mut bits: u64 = 0;
    for byte in digest.iter().take(5) {
        bits = (bits << 8) | u64::from(*byte);
    }

    let mut out = String::with_capacity(SUFFIX_LEN);
    for index in (0..SUFFIX_LEN).rev() {
        out.push(ALPHABET[((bits >> (index * 5)) & 31) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_placeholder(text: &str, kind: Kind) -> bool {
        let Some(rest) = text.strip_prefix("{{") else {
            return false;
        };
        let Some(rest) = rest.strip_suffix("}}") else {
            return false;
        };
        let Some((prefix, suffix)) = rest.split_once('_') else {
            return false;
        };
        prefix == kind.as_str()
            && suffix.len() == SUFFIX_LEN
            && suffix.bytes().all(|b| ALPHABET.contains(&b))
    }

    #[test]
    fn placeholder_has_the_expected_format() {
        let mut table = PlaceholderTable::with_seed(1);
        let placeholder = table.placeholder_for("alice@example.com", Kind::Email);
        assert!(is_placeholder(&placeholder, Kind::Email), "{placeholder}");
    }

    #[test]
    fn same_value_reuses_the_same_placeholder() {
        let mut table = PlaceholderTable::with_seed(1);
        let a = table.placeholder_for("secret", Kind::Secret);
        let b = table.placeholder_for("secret", Kind::Secret);
        assert_eq!(a, b);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn different_values_get_different_placeholders() {
        let mut table = PlaceholderTable::with_seed(1);
        let a = table.placeholder_for("one", Kind::Secret);
        let b = table.placeholder_for("two", Kind::Secret);
        assert_ne!(a, b);
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn restore_returns_the_original_text() {
        let mut table = PlaceholderTable::with_seed(1);
        let email = table.placeholder_for("alice@example.com", Kind::Email);
        let phone = table.placeholder_for("+1 415-555-0132", Kind::Phone);
        let masked = format!("写邮件到 {email}，或拨打 {phone}");
        assert_eq!(
            table.restore(&masked),
            "写邮件到 alice@example.com，或拨打 +1 415-555-0132"
        );
    }

    #[test]
    fn restore_leaves_unknown_placeholders_alone() {
        let table = PlaceholderTable::with_seed(1);
        let text = "unknown {{EMAIL_abcd2345}} stays";
        assert_eq!(table.restore(text), text);
    }

    #[test]
    fn restore_handles_adjacent_and_unknown_placeholders() {
        let mut table = PlaceholderTable::with_seed(3);
        let email = table.placeholder_for("alice@example.com", Kind::Email);
        let text = format!("{email}{{{{EMAIL_unknown0}}}}{email}");

        assert_eq!(
            table.restore(&text),
            "alice@example.com{{EMAIL_unknown0}}alice@example.com"
        );
    }

    #[test]
    fn seed_makes_generation_reproducible() {
        let mut first = PlaceholderTable::with_seed(42);
        let mut second = PlaceholderTable::with_seed(42);
        assert_eq!(
            first.placeholder_for("value", Kind::Secret),
            second.placeholder_for("value", Kind::Secret)
        );
    }

    #[test]
    fn salt_keeps_placeholders_stable_across_requests() {
        let mut first = PlaceholderTable::with_salt("device-salt");
        let mut second = PlaceholderTable::with_salt("device-salt");

        let a = first.placeholder_for("alice@example.com", Kind::Email);
        let b = second.placeholder_for("alice@example.com", Kind::Email);
        assert_eq!(a, b, "相同盐值下，相同原值必须得到同一个占位符");
        assert!(is_placeholder(&a, Kind::Email), "{a}");
        assert_eq!(second.restore(&b), "alice@example.com");
    }

    #[test]
    fn salt_changes_the_suffix() {
        let mut first = PlaceholderTable::with_salt("salt-a");
        let mut second = PlaceholderTable::with_salt("salt-b");
        assert_ne!(
            first.placeholder_for("alice@example.com", Kind::Email),
            second.placeholder_for("alice@example.com", Kind::Email)
        );
    }
}
