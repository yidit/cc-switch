//! 占位符生成、映射与还原。
//!
//! 格式与 magpie 一致：`{{KIND_xxxxxxxx}}`，后缀为 8 位 base32 字符
//! （`a-z2-7`）。同一张表内，相同的原值复用同一个占位符。

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
    /// 按请求随机（没有配置盐时的回退）。
    Random(Rng),
    /// 按设备盐派生：同一盐下相同原值总是得到相同占位符。
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

    /// 用设备盐创建：相同 `salt`、相同原值在不同请求里得到同一个占位符。
    ///
    /// 这样上游提示缓存与会话指纹不会因为占位符变化而失效；盐由本机随机
    /// 生成并随设置保存，不同设备之间互不相同。
    pub fn with_salt(salt: &str) -> Self {
        Self {
            forward: HashMap::new(),
            backward: HashMap::new(),
            source: Source::Salted(salt.as_bytes().to_vec()),
        }
    }

    /// 按配置里的盐创建；没有盐（旧配置）时退化为按请求随机。
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
            // 掩码空间是 40 bit，撞车概率极低；换一个派生输入继续尝试。
            attempt = attempt.wrapping_add(1);
        };

        self.forward.insert(value.to_string(), placeholder.clone());
        self.backward.insert(placeholder.clone(), value.to_string());
        placeholder
    }

    /// 把文本中的占位符还原为原值。
    ///
    /// 占位符互不重叠，替换顺序不影响结果；表中没有的 `{{...}}` 保持原样。
    pub fn restore(&self, text: &str) -> String {
        if self.backward.is_empty() {
            return text.to_string();
        }

        let mut out = text.to_string();
        for (placeholder, value) in &self.backward {
            if out.contains(placeholder) {
                out = out.replace(placeholder, value);
            }
        }
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

/// 由「盐 + 类型 + 原值 + 尝试次数」派生 8 位 base32 后缀。
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
        assert_eq!(a, b, "同一盐下相同原值必须得到同一个占位符");
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
