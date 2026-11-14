//! JSON 结构感知的脱敏与还原。
//!
//! 只处理字符串值，键名与结构化枚举字段保持原样。调用方负责解析与序列化
//! JSON；本模块直接操作 `serde_json::Value`，避免在代理链路里重复实现。

use std::collections::HashMap;

use serde_json::Value;

use crate::redact::{Engine, Hit, ModelEngine, PlaceholderTable, RedactConfig};

/// 这些键的值是协议枚举或标识符，不参与脱敏。
///
/// 必须保持字典序：`should_skip` 对全小写键直接二分查找。
const SKIP_KEYS: &[&str] = &[
    "call_id",
    "encoding",
    "encrypted_content",
    "event",
    "finish_reason",
    "format",
    "id",
    "item_id",
    "media_type",
    "mime_type",
    "modalities",
    "model",
    "object",
    "request_id",
    "response_id",
    "role",
    "session_id",
    // 不透明签名与加密内容：改一个字节上游就会拒绝，且高熵值会误触密钥规则。
    "signature",
    "status",
    "stop_reason",
    "thought_signature",
    "thoughtsignature",
    "tool_call_id",
    "tool_use_id",
    "type",
];

/// 一次 JSON 脱敏的统计。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct JsonMaskStats {
    /// 实际参与检测的字符串数量。
    pub strings: usize,
    /// 命中的区间数量。
    pub hits: usize,
    /// 写入的占位符数量。
    pub placeholders: usize,
}

/// 递归脱敏 `value` 中的字符串，返回统计。
///
/// 传入 `model` 时会先用模型扫描一遍文本：扫描从最新内容往前进行，
/// 受 `config.model.max_tokens_per_request` 限制，结果再与规则命中合并。
pub fn mask_json(
    value: &mut Value,
    engine: &Engine,
    config: &RedactConfig,
    table: &mut PlaceholderTable,
    model: Option<&ModelEngine>,
) -> Result<JsonMaskStats, String> {
    let mut stats = JsonMaskStats::default();
    if !config.enabled {
        return Ok(stats);
    }

    let model_hits = match model {
        Some(model) if config.model.enabled => {
            // 只借用字符串，不克隆：请求体可能有几 MB 的文本，复制一份纯属浪费内存。
            let mut texts = Vec::new();
            collect_strings(value, None, &mut texts);

            // 倒序遍历：预算优先给最新的消息。
            let mut budget = config.model.max_tokens_per_request;
            let mut hits: HashMap<usize, Vec<Hit>> = HashMap::new();
            for (index, text) in texts.iter().enumerate().rev() {
                if budget == 0 {
                    break;
                }
                let found = model.detect(text, config, &mut budget)?;
                if !found.is_empty() {
                    hits.insert(index, found);
                }
            }
            // 释放对 value 的不可变借用，下面才能就地改写。
            drop(texts);
            Some(hits)
        }
        _ => None,
    };

    let mut index = 0usize;
    walk_mask(
        value,
        None,
        engine,
        config,
        table,
        &mut stats,
        model_hits.as_ref(),
        &mut index,
    );
    Ok(stats)
}

fn collect_strings<'a>(value: &'a Value, key: Option<&str>, out: &mut Vec<&'a str>) {
    match value {
        Value::String(text)
            if !key.is_some_and(should_skip) && !looks_like_encoded_payload(text) =>
        {
            out.push(text)
        }
        Value::String(_) => {}
        Value::Array(items) => {
            for item in items {
                collect_strings(item, key, out);
            }
        }
        Value::Object(map) => {
            // 思考内容与签名绑定：改写正文或加密数据都会让上游校验失败。
            let block_type = map.get("type").and_then(Value::as_str);
            let is_thinking = block_type == Some("thinking");
            let is_redacted_thinking = block_type == Some("redacted_thinking");
            let is_thought_part = map.get("thought").and_then(Value::as_bool) == Some(true)
                || map.contains_key("thoughtSignature")
                || map.contains_key("thought_signature");
            for (child_key, child) in map {
                if (is_redacted_thinking && child_key == "data")
                    || (is_thinking && child_key == "thinking")
                    || (is_thought_part && child_key == "text")
                {
                    continue;
                }
                collect_strings(child, Some(child_key), out);
            }
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_mask(
    value: &mut Value,
    key: Option<&str>,
    engine: &Engine,
    config: &RedactConfig,
    table: &mut PlaceholderTable,
    stats: &mut JsonMaskStats,
    model_hits: Option<&HashMap<usize, Vec<Hit>>>,
    index: &mut usize,
) {
    match value {
        Value::String(text) => {
            if key.is_some_and(should_skip) || looks_like_encoded_payload(text) {
                return;
            }
            let current = *index;
            *index += 1;
            let extra = model_hits
                .and_then(|hits| hits.get(&current))
                .map(Vec::as_slice)
                .unwrap_or(&[]);

            // 就地脱敏：没有命中时原字符串保持不变，不再整段复制。
            let (hits, placeholders) = engine.mask_in_place(text, config, table, extra);
            stats.strings += 1;
            stats.hits += hits.len();
            stats.placeholders += placeholders;
        }
        Value::Array(items) => {
            for item in items {
                walk_mask(item, key, engine, config, table, stats, model_hits, index);
            }
        }
        Value::Object(map) => {
            let block_type = map.get("type").and_then(Value::as_str);
            let is_thinking = block_type == Some("thinking");
            let is_redacted_thinking = block_type == Some("redacted_thinking");
            let is_thought_part = map.get("thought").and_then(Value::as_bool) == Some(true)
                || map.contains_key("thoughtSignature")
                || map.contains_key("thought_signature");
            for (child_key, child) in map.iter_mut() {
                if (is_redacted_thinking && child_key == "data")
                    || (is_thinking && child_key == "thinking")
                    || (is_thought_part && child_key == "text")
                {
                    continue;
                }
                walk_mask(
                    child,
                    Some(child_key),
                    engine,
                    config,
                    table,
                    stats,
                    model_hits,
                    index,
                );
            }
        }
        _ => {}
    }
}

/// 递归还原 `value` 中字符串里的占位符，返回发生替换的字符串数量。
pub fn restore_json(value: &mut Value, table: &PlaceholderTable) -> usize {
    let mut restored = 0;
    walk_restore(value, table, &mut restored);
    restored
}

fn walk_restore(value: &mut Value, table: &PlaceholderTable, restored: &mut usize) {
    match value {
        Value::String(text) => {
            let next = table.restore(text);
            if next != *text {
                *text = next;
                *restored += 1;
            }
        }
        Value::Array(items) => {
            for item in items {
                walk_restore(item, table, restored);
            }
        }
        Value::Object(map) => {
            for child in map.values_mut() {
                walk_restore(child, table, restored);
            }
        }
        _ => {}
    }
}

fn should_skip(key: &str) -> bool {
    // 协议字段名绝大多数是全小写：直接二分，省掉对 35 个键的逐项比较。
    if !key.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return SKIP_KEYS.binary_search(&key).is_ok();
    }
    // 少见的大写写法（如 `Type`）退回大小写不敏感比较。
    SKIP_KEYS.iter().any(|skip| skip.eq_ignore_ascii_case(key))
}

/// 判断字符串是否像 base64 或 data URL 这类编码后的二进制内容。
///
/// 图片、附件在请求里通常是几 MB 的 base64：规则正则扫描代价高，模型的
/// token 预算会被瞬间吃光，自定义规则还可能把数据改坏，因此整段跳过。
fn looks_like_encoded_payload(text: &str) -> bool {
    const MIN_LEN: usize = 1024;
    if text.len() < MIN_LEN {
        return false;
    }

    let is_data_url = text.starts_with("data:");
    let body = if is_data_url {
        text.split_once(',').map_or(text, |(_, body)| body)
    } else {
        text
    };
    if body.len() < MIN_LEN {
        return false;
    }

    // 统计全部字符，而不是遇到不认识的字符就直接返回：`.env`、配置块里的
    // 键值也只由字母数字和 `= _ -` 组成，必须靠比例和空白规则把它们排除。
    let mut allowed = 0usize;
    let mut total = 0usize;
    for ch in body.chars() {
        // data URL 允许带换行；其他文本只要出现空白就不是编码数据（多行 .env、
        // 密钥配置同样只由安全字符组成），可以当场判定，不必再扫完整段文本。
        if ch.is_whitespace() && !is_data_url {
            return false;
        }
        total += 1;
        if ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=' | '-' | '_') {
            allowed += 1;
        }
    }
    // data URL 的正文再按比例判断是否真的像编码数据。
    total > 0 && allowed * 100 >= total * 98
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn engine_and_config() -> (Engine, RedactConfig) {
        let config = RedactConfig {
            enabled: true,
            ..Default::default()
        };
        (Engine::with_builtin(&config), config)
    }

    #[test]
    fn masks_only_text_values() {
        let (engine, config) = engine_and_config();
        let mut table = PlaceholderTable::with_seed(7);
        let mut value = json!({
            "role": "user",
            "model": "claude-3-5-sonnet",
            "content": [
                {"type": "text", "text": "mail jane.smith@gmail.com"},
                {"type": "text", "text": "call 415-555-0132"}
            ]
        });

        let stats =
            mask_json(&mut value, &engine, &config, &mut table, None).expect("脱敏不应失败");

        assert_eq!(stats.hits, 2);
        assert!(value["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("{{EMAIL_"));
        assert!(value["content"][1]["text"]
            .as_str()
            .unwrap()
            .contains("{{PHONE_"));
        assert_eq!(value["role"], "user");
        assert_eq!(value["model"], "claude-3-5-sonnet");
    }

    #[test]
    fn restores_the_original_json() {
        let (engine, config) = engine_and_config();
        let mut table = PlaceholderTable::with_seed(7);
        let original = json!({
            "content": "mail jane.smith@gmail.com",
            "nested": {"note": "card 4111 1111 1111 1111"}
        });
        let mut value = original.clone();

        mask_json(&mut value, &engine, &config, &mut table, None).expect("脱敏不应失败");
        let restored_count = restore_json(&mut value, &table);

        assert_eq!(restored_count, 2);
        assert_eq!(value, original);
    }

    #[test]
    fn skips_encoded_binary_payloads() {
        let (engine, config) = engine_and_config();
        let mut table = PlaceholderTable::with_seed(7);
        let payload = format!("data:image/png;base64,{}", "A".repeat(4096));
        let mut value = json!({"content": payload});

        let stats =
            mask_json(&mut value, &engine, &config, &mut table, None).expect("脱敏不应失败");

        assert_eq!(stats.strings, 0, "base64 负载不应参与脱敏");
        assert_eq!(
            value["content"].as_str().unwrap(),
            payload,
            "base64 负载必须保持原样"
        );
    }

    #[test]
    fn masks_env_style_blocks() {
        let (engine, config) = engine_and_config();
        let mut table = PlaceholderTable::with_seed(7);
        let key = format!("{}{}", "AIza", "SyA1234567890abcdefghijklmnopqrstuv");
        let text = (0..80)
            .map(|index| format!("SERVICE_{index}_TOKEN={key}\n"))
            .collect::<String>();
        let mut value = json!({"content": text});

        let stats =
            mask_json(&mut value, &engine, &config, &mut table, None).expect("脱敏不应失败");

        assert_eq!(stats.strings, 1, ".env 风格的配置块应参与脱敏");
        assert!(value["content"].as_str().unwrap().contains("{{SECRET_"));
    }

    #[test]
    fn long_prose_is_still_masked() {
        let (engine, config) = engine_and_config();
        let mut table = PlaceholderTable::with_seed(7);
        let text = "这是一段普通文本，包含邮箱 jane.smith@gmail.com。".repeat(100);
        let mut value = json!({"content": text});

        let stats =
            mask_json(&mut value, &engine, &config, &mut table, None).expect("脱敏不应失败");

        assert_eq!(stats.strings, 1);
        assert!(value["content"].as_str().unwrap().contains("{{EMAIL_"));
    }

    #[test]
    fn skips_structural_keys() {
        let (engine, config) = engine_and_config();
        let mut table = PlaceholderTable::with_seed(7);
        // 即使值看起来像密钥，结构化字段也不处理。
        let mut value = json!({"type": "sk-proj-Qm7vT2xLk9RbW4nZpE6sJc8YhD3fGa5uKiN1oVr0"});

        let stats =
            mask_json(&mut value, &engine, &config, &mut table, None).expect("脱敏不应失败");

        assert_eq!(stats.strings, 0);
        assert!(value["type"].as_str().unwrap().starts_with("sk-proj-"));
    }

    #[test]
    fn skips_opaque_signature_and_encrypted_fields() {
        let (engine, config) = engine_and_config();
        let mut table = PlaceholderTable::with_seed(7);
        let opaque = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=";
        let mut value = json!({
            "content": [
                {"type": "thinking", "thinking": "mail jane.smith@gmail.com", "signature": opaque},
                {"type": "redacted_thinking", "data": opaque},
                {"type": "text", "text": "mail jane.smith@gmail.com"},
                {"text": "mail jane.smith@gmail.com", "thought": true}
            ],
            "encrypted_content": opaque
        });

        let stats =
            mask_json(&mut value, &engine, &config, &mut table, None).expect("脱敏不应失败");

        assert_eq!(value["content"][0]["thinking"], "mail jane.smith@gmail.com");
        assert_eq!(value["content"][0]["signature"], opaque);
        assert_eq!(value["content"][1]["data"], opaque);
        assert_eq!(
            value["content"][3]["text"], "mail jane.smith@gmail.com",
            "Gemini 的 thought part 不能改写"
        );
        assert_eq!(value["encrypted_content"], opaque);
        assert!(value["content"][2]["text"]
            .as_str()
            .unwrap()
            .contains("{{EMAIL_"));
        assert_eq!(stats.strings, 1, "只有普通 text 块参与脱敏");
    }

    #[test]
    fn disabled_config_does_nothing() {
        let config = RedactConfig::default();
        let engine = Engine::with_builtin(&config);
        let mut table = PlaceholderTable::with_seed(7);
        let original = json!({"text": "mail jane.smith@gmail.com"});
        let mut value = original.clone();

        let stats =
            mask_json(&mut value, &engine, &config, &mut table, None).expect("脱敏不应失败");

        assert_eq!(stats, JsonMaskStats::default());
        assert_eq!(value, original);
    }
}
