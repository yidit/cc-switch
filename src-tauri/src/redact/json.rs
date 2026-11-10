//! JSON 结构感知的脱敏与还原。
//!
//! 只处理字符串值，键名与结构化枚举字段保持原样。调用方负责解析与序列化
//! JSON；本模块直接操作 `serde_json::Value`，避免在代理链路里重复实现。

use serde_json::Value;

use crate::redact::{Engine, PlaceholderTable, RedactConfig};

/// 这些键的值是协议枚举或标识符，不参与脱敏。
const SKIP_KEYS: &[&str] = &[
    "type",
    "role",
    "object",
    "model",
    "finish_reason",
    "stop_reason",
    "status",
    "event",
    "modalities",
    "format",
    "encoding",
    "media_type",
    "mime_type",
    "id",
    "item_id",
    "session_id",
    "request_id",
    "response_id",
    "tool_use_id",
    "tool_call_id",
    "call_id",
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
pub fn mask_json(
    value: &mut Value,
    engine: &Engine,
    config: &RedactConfig,
    table: &mut PlaceholderTable,
) -> JsonMaskStats {
    let mut stats = JsonMaskStats::default();
    if !config.enabled {
        return stats;
    }
    walk_mask(value, None, engine, config, table, &mut stats);
    stats
}

fn walk_mask(
    value: &mut Value,
    key: Option<&str>,
    engine: &Engine,
    config: &RedactConfig,
    table: &mut PlaceholderTable,
    stats: &mut JsonMaskStats,
) {
    match value {
        Value::String(text) => {
            if key.is_some_and(should_skip) {
                return;
            }
            let outcome = engine.mask_text(text, config, table);
            *text = outcome.text;
            stats.strings += 1;
            stats.hits += outcome.hits.len();
            stats.placeholders += outcome.placeholders;
        }
        Value::Array(items) => {
            for item in items {
                walk_mask(item, key, engine, config, table, stats);
            }
        }
        Value::Object(map) => {
            for (child_key, child) in map.iter_mut() {
                walk_mask(child, Some(child_key), engine, config, table, stats);
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
    SKIP_KEYS.iter().any(|skip| skip.eq_ignore_ascii_case(key))
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

        let stats = mask_json(&mut value, &engine, &config, &mut table);

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

        mask_json(&mut value, &engine, &config, &mut table);
        let restored_count = restore_json(&mut value, &table);

        assert_eq!(restored_count, 2);
        assert_eq!(value, original);
    }

    #[test]
    fn skips_structural_keys() {
        let (engine, config) = engine_and_config();
        let mut table = PlaceholderTable::with_seed(7);
        // 即使值看起来像密钥，结构化字段也不处理。
        let mut value = json!({"type": "sk-proj-Qm7vT2xLk9RbW4nZpE6sJc8YhD3fGa5uKiN1oVr0"});

        let stats = mask_json(&mut value, &engine, &config, &mut table);

        assert_eq!(stats.strings, 0);
        assert!(value["type"].as_str().unwrap().starts_with("sk-proj-"));
    }

    #[test]
    fn disabled_config_does_nothing() {
        let config = RedactConfig::default();
        let engine = Engine::with_builtin(&config);
        let mut table = PlaceholderTable::with_seed(7);
        let original = json!({"text": "mail jane.smith@gmail.com"});
        let mut value = original.clone();

        let stats = mask_json(&mut value, &engine, &config, &mut table);

        assert_eq!(stats, JsonMaskStats::default());
        assert_eq!(value, original);
    }
}
