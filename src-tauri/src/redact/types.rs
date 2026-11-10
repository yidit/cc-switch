//! 脱敏配置与结果类型。
//!
//! 序列化字段使用 camelCase，与前端设置保持一致；枚举值使用大写，
//! 与 magpie 的 `Kind` 及评估语料一致（见 `docs/redact/eval-baseline.md`）。

use serde::{Deserialize, Serialize};

/// 敏感值类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Kind {
    /// API key、私钥、JWT、连接串密码等。
    Secret,
    /// 人名，第一阶段仅由自定义词/词典命中。
    Person,
    /// 手机号与电话号码。
    Phone,
    /// 邮箱地址。
    Email,
    /// 银行卡、IBAN、身份证号等账户信息。
    Account,
    /// 地址，第一阶段不实现。
    Address,
}

impl Kind {
    /// 用于占位符前缀的大写名称。
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Secret => "SECRET",
            Kind::Person => "PERSON",
            Kind::Phone => "PHONE",
            Kind::Email => "EMAIL",
            Kind::Account => "ACCOUNT",
            Kind::Address => "ADDRESS",
        }
    }

    /// 是否属于「个人信息」大类。
    pub fn is_personal(self) -> bool {
        matches!(
            self,
            Kind::Person | Kind::Phone | Kind::Email | Kind::Account | Kind::Address
        )
    }
}

/// 命中区间，使用 UTF-8 字节偏移。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hit {
    pub start: usize,
    pub end: usize,
    pub kind: Kind,
    /// 该命中应如何替换；内置检测器默认使用占位符。
    pub action: Action,
}

/// 替换动作。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// 替换为 `{{KIND_xxxxxxxx}}` 占位符，响应到达前还原。
    #[default]
    Placeholder,
    /// 替换为固定掩码字符，不保留映射。
    Mask,
    /// 直接删除该值。
    Drop,
}

/// 用户自定义规则。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomRule {
    /// 规则名称，仅用于展示与日志。
    pub name: String,
    /// 正则表达式（Rust `regex` 语法）。
    pub pattern: String,
    pub kind: Kind,
    #[serde(default)]
    pub action: Action,
}

/// 本地模型配置。
///
/// 模型用于识别规则层无法可靠判断的人名和地址；默认关闭，需要用户显式
/// 下载并启用。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelConfig {
    /// 是否启用本地模型。
    #[serde(default)]
    pub enabled: bool,
    /// 命中阈值：模型给出的置信度达到该值才脱敏。
    #[serde(default = "default_model_threshold")]
    pub threshold: f32,
    /// 每次请求最多交给模型的 token 数，从最新的内容往前算。
    #[serde(default = "default_model_max_tokens")]
    pub max_tokens_per_request: usize,
}

fn default_model_threshold() -> f32 {
    0.8
}

fn default_model_max_tokens() -> usize {
    4096
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            threshold: default_model_threshold(),
            max_tokens_per_request: default_model_max_tokens(),
        }
    }
}

/// 脱敏配置。
///
/// `kinds` 为空时，表示 `personal` 覆盖全部个人信息类型。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactConfig {
    /// 总开关，默认关闭。
    #[serde(default)]
    pub enabled: bool,
    /// 是否检测密钥类信息。
    #[serde(default = "default_true")]
    pub secrets: bool,
    /// 是否检测个人信息。
    #[serde(default = "default_true")]
    pub personal: bool,
    /// 进一步限定个人信息的类型；为空表示全部。
    #[serde(default)]
    pub kinds: Vec<Kind>,
    /// 自定义屏蔽词。
    #[serde(default)]
    pub words: Vec<String>,
    /// 自定义词是否忽略大小写。
    #[serde(default)]
    pub words_any_case: bool,
    /// 自定义词是否仅整词匹配。
    #[serde(default = "default_true")]
    pub words_whole: bool,
    /// 用户自定义正则规则。
    #[serde(default)]
    pub rules: Vec<CustomRule>,
    /// 白名单：命中的值永不脱敏。
    #[serde(default)]
    pub allow: Vec<String>,
    /// 脱敏失败时拒绝请求，而不是把原文发往上游。
    #[serde(default = "default_true")]
    pub fail_closed: bool,
    /// 生成占位符用的盐值（本机随机生成，保存设置时补齐）。
    ///
    /// 盐值相同时，相同的原值总是得到相同的占位符，因此上游的提示缓存
    /// 和会话指纹在不同请求之间保持不变。`None` 表示旧配置，此时每次
    /// 请求都会重新随机。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,
    /// 本地模型配置。
    #[serde(default)]
    pub model: ModelConfig,
}

fn default_true() -> bool {
    true
}

impl Default for RedactConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            secrets: true,
            personal: true,
            kinds: Vec::new(),
            words: Vec::new(),
            words_any_case: false,
            words_whole: true,
            rules: Vec::new(),
            allow: Vec::new(),
            fail_closed: true,
            salt: None,
            model: ModelConfig::default(),
        }
    }
}

/// 一次脱敏的结果。
#[derive(Debug, Clone)]
pub struct MaskOutcome {
    /// 替换后的文本。
    pub text: String,
    /// 命中的区间，按位置排序且互不重叠。
    pub hits: Vec<Hit>,
    /// 实际写入的占位符数量（Mask / Drop 动作不计入）。
    pub placeholders: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_to_off_but_detects_both_categories() {
        let config = RedactConfig::default();
        assert!(!config.enabled);
        assert!(config.secrets);
        assert!(config.personal);
        assert!(config.fail_closed);
    }

    #[test]
    fn kinds_serialize_uppercase() {
        let json = serde_json::to_string(&Kind::Email).unwrap();
        assert_eq!(json, "\"EMAIL\"");
    }

    #[test]
    fn config_uses_camel_case_keys() {
        let json = serde_json::to_value(RedactConfig::default()).unwrap();
        assert!(json.get("wordsAnyCase").is_some());
        assert!(json.get("failClosed").is_some());
        assert!(json.get("kinds").is_some());
    }

    #[test]
    fn personal_kinds_are_classified() {
        assert!(!Kind::Secret.is_personal());
        assert!(Kind::Email.is_personal());
        assert!(Kind::Address.is_personal());
    }
}
