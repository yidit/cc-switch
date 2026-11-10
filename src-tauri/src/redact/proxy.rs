//! 代理链路的脱敏接入层。
//!
//! 这里只放与 HTTP/JSON 无关的纯函数，便于单元测试；真正的插入点
//! （请求转发前、响应写出前）在 `proxy::handlers` 与
//! `proxy::response_processor` 中。

use std::sync::Arc;

use serde_json::Value;

use crate::redact::{
    invalid_rules,
    json::{mask_json, restore_json},
    Engine, PlaceholderTable, RedactConfig,
};

/// 对请求 JSON 做脱敏。
///
/// - 未开启时返回 `Ok(None)`；
/// - 没有命中时返回 `Ok(None)`，调用方据此跳过响应还原；
/// - 开启 `failClosed` 且配置里的自定义规则无法使用时返回 `Err`，调用方必须
///   拒绝请求，不能把原文发给上游。
pub fn mask_request_body(
    body: &mut Value,
    config: &RedactConfig,
) -> Result<Option<Arc<PlaceholderTable>>, String> {
    if !config.enabled {
        return Ok(None);
    }

    let errors = invalid_rules(&config.rules);
    if !errors.is_empty() {
        if config.fail_closed {
            return Err(format!("请求脱敏配置无效：{}", errors.join("；")));
        }
        log::warn!("请求脱敏规则无效，已跳过：{}", errors.join("；"));
    }

    let engine = Engine::with_builtin(config);
    // 配置了盐时按盐派生占位符，保证跨请求稳定；老配置没有盐则按请求随机。
    let mut table = PlaceholderTable::from_config(config);
    let stats = mask_json(body, &engine, config, &mut table);

    if stats.placeholders == 0 && stats.hits == 0 {
        return Ok(None);
    }
    Ok(Some(Arc::new(table)))
}

/// 还原非流式响应体。
///
/// 优先按 JSON 处理（保留键顺序），失败时按 UTF-8 文本处理；没有发生
/// 替换或无法解析时返回 `None`。
pub fn restore_response_body(bytes: &[u8], table: &PlaceholderTable) -> Option<Vec<u8>> {
    if table.is_empty() {
        return None;
    }

    if let Ok(mut value) = serde_json::from_slice::<Value>(bytes) {
        let changed = restore_json(&mut value, table);
        if changed == 0 {
            return None;
        }
        return serde_json::to_vec(&value).ok();
    }

    let text = std::str::from_utf8(bytes).ok()?;
    let restored = table.restore(text);
    if restored == text {
        None
    } else {
        Some(restored.into_bytes())
    }
}

/// 流式响应里单个 chunk 的还原。
///
/// 占位符可能被拆到两个 chunk，因此把末尾可能不完整的 `{{…` 留在
/// `pending` 中，等下一个 chunk 到达再一起还原。
pub fn restore_stream_chunk(
    table: &PlaceholderTable,
    pending: &mut Vec<u8>,
    chunk: &[u8],
) -> Vec<u8> {
    // 先把 pending 整体取出，避免后面写回时与原缓冲区的借用冲突。
    let mut buffer = std::mem::take(pending);
    buffer.extend_from_slice(chunk);

    let Ok(text) = std::str::from_utf8(&buffer) else {
        // 非法 UTF-8：不冒险改写，原样放行。
        return buffer;
    };

    let keep_from = incomplete_placeholder_start(text);
    let restored = table.restore(&text[..keep_from]);
    let tail = text.as_bytes()[keep_from..].to_vec();

    pending.extend_from_slice(&tail);
    restored.into_bytes()
}

/// 流结束时把 `pending` 里剩余的内容还原并返回。
///
/// 剩余内容不是合法 UTF-8 时原样返回，避免 `from_utf8_lossy` 改写字节。
pub fn flush_stream_restore(table: &PlaceholderTable, pending: &mut Vec<u8>) -> Option<Vec<u8>> {
    if pending.is_empty() {
        return None;
    }
    let bytes = std::mem::take(pending);
    match std::str::from_utf8(&bytes) {
        Ok(text) => Some(table.restore(text).into_bytes()),
        Err(_) => Some(bytes),
    }
}

/// 占位符最长约 24 字节；留出余量，超过这个长度的 `{{…` 不当作不完整占位符。
const MAX_PLACEHOLDER_BYTES: usize = 64;

/// 返回应当保留到下一个 chunk 的起点。
fn incomplete_placeholder_start(text: &str) -> usize {
    let bytes = text.as_bytes();
    let len = bytes.len();

    // 末尾单个 `{` 可能只是 `{{` 的前半个：chunk 恰好切在这里时也要缓存。
    if len > 0 && bytes[len - 1] == b'{' && (len < 2 || bytes[len - 2] != b'{') {
        return len - 1;
    }

    let Some(start) = text.rfind("{{") else {
        return len;
    };
    let tail = &text[start..];
    if !tail.contains("}}") && tail.len() <= MAX_PLACEHOLDER_BYTES {
        start
    } else {
        len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn enabled() -> RedactConfig {
        RedactConfig {
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn masks_request_body_and_tracks_placeholders() {
        let mut body = json!({"content": "mail jane.smith@gmail.com"});
        let table = mask_request_body(&mut body, &enabled())
            .expect("配置有效")
            .expect("应有命中");

        let text = body["content"].as_str().unwrap();
        assert!(text.contains("{{EMAIL_"));
        assert_eq!(table.restore(text), "mail jane.smith@gmail.com");
    }

    #[test]
    fn returns_none_when_nothing_is_masked() {
        let mut body = json!({"content": "nothing sensitive here"});
        assert!(mask_request_body(&mut body, &enabled())
            .expect("配置有效")
            .is_none());
    }

    #[test]
    fn fail_closed_blocks_invalid_rules() {
        let config = RedactConfig {
            enabled: true,
            rules: vec![crate::redact::CustomRule {
                name: "broken".to_string(),
                pattern: "(".to_string(),
                kind: crate::redact::Kind::Secret,
                action: crate::redact::Action::Placeholder,
            }],
            ..Default::default()
        };
        let mut body = json!({"content": "hello"});
        let error = match mask_request_body(&mut body, &config) {
            Err(message) => message,
            Ok(_) => panic!("应拒绝请求"),
        };
        assert!(error.contains("broken"), "{error}");
    }

    #[test]
    fn fail_open_skips_invalid_rules() {
        let config = RedactConfig {
            enabled: true,
            fail_closed: false,
            rules: vec![crate::redact::CustomRule {
                name: "broken".to_string(),
                pattern: "(".to_string(),
                kind: crate::redact::Kind::Secret,
                action: crate::redact::Action::Placeholder,
            }],
            ..Default::default()
        };
        let mut body = json!({"content": "mail jane.smith@gmail.com"});
        let table = mask_request_body(&mut body, &config)
            .expect("fail-open 不应报错")
            .expect("内置规则仍应命中");
        assert!(body["content"].as_str().unwrap().contains("{{EMAIL_"));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn salted_config_produces_stable_placeholders() {
        let config = RedactConfig {
            enabled: true,
            salt: Some("device-salt".to_string()),
            ..Default::default()
        };
        let mut first = json!({"content": "mail jane.smith@gmail.com"});
        let mut second = json!({"content": "mail jane.smith@gmail.com"});

        mask_request_body(&mut first, &config).unwrap().unwrap();
        mask_request_body(&mut second, &config).unwrap().unwrap();

        assert_eq!(
            first["content"], second["content"],
            "同一盐下相同原值必须得到同一个占位符"
        );
    }

    #[test]
    fn restores_json_response() {
        let mut table = PlaceholderTable::with_seed(7);
        let placeholder = table.placeholder_for("jane.smith@gmail.com", crate::redact::Kind::Email);
        let bytes = format!(r#"{{"content":"mail {placeholder}"}}"#).into_bytes();

        let restored = restore_response_body(&bytes, &table).expect("应发生还原");
        let value: Value = serde_json::from_slice(&restored).unwrap();
        assert_eq!(value["content"], "mail jane.smith@gmail.com");
    }

    #[test]
    fn restores_plain_text_response() {
        let mut table = PlaceholderTable::with_seed(7);
        let placeholder = table.placeholder_for("415-555-0132", crate::redact::Kind::Phone);
        let bytes = format!("call {placeholder}").into_bytes();

        let restored = restore_response_body(&bytes, &table).unwrap();
        assert_eq!(String::from_utf8(restored).unwrap(), "call 415-555-0132");
    }

    #[test]
    fn restores_a_placeholder_split_across_chunks() {
        let mut table = PlaceholderTable::with_seed(7);
        let placeholder = table.placeholder_for("jane.smith@gmail.com", crate::redact::Kind::Email);
        let (first, second) = placeholder.split_at(placeholder.len() / 2);

        let mut pending = Vec::new();
        let out1 = restore_stream_chunk(&table, &mut pending, first.as_bytes());
        let out2 = restore_stream_chunk(&table, &mut pending, second.as_bytes());

        assert!(out1.is_empty(), "不完整的占位符应留在 pending");
        assert_eq!(String::from_utf8(out2).unwrap(), "jane.smith@gmail.com");
        assert!(pending.is_empty());
    }

    #[test]
    fn flush_restores_the_tail() {
        let mut table = PlaceholderTable::with_seed(7);
        let placeholder = table.placeholder_for("jane.smith@gmail.com", crate::redact::Kind::Email);
        let mut pending = placeholder.into_bytes();

        let flushed = flush_stream_restore(&table, &mut pending).unwrap();
        assert_eq!(String::from_utf8(flushed).unwrap(), "jane.smith@gmail.com");
    }

    #[test]
    fn restores_a_placeholder_split_at_every_boundary() {
        let mut table = PlaceholderTable::with_seed(7);
        let placeholder = table.placeholder_for("jane.smith@gmail.com", crate::redact::Kind::Email);

        for split in 0..=placeholder.len() {
            let mut pending = Vec::new();
            let mut out = Vec::new();
            out.extend(restore_stream_chunk(
                &table,
                &mut pending,
                &placeholder.as_bytes()[..split],
            ));
            out.extend(restore_stream_chunk(
                &table,
                &mut pending,
                &placeholder.as_bytes()[split..],
            ));

            assert_eq!(
                String::from_utf8(out).unwrap(),
                "jane.smith@gmail.com",
                "在字节 {split} 处切开时未还原"
            );
            assert!(pending.is_empty(), "在字节 {split} 处切开后仍有余留");
        }
    }

    #[test]
    fn flush_keeps_non_utf8_bytes_untouched() {
        let table = PlaceholderTable::with_seed(7);
        let mut pending = vec![0xff, 0xfe, 0x00];

        let flushed = flush_stream_restore(&table, &mut pending).expect("应返回余留内容");
        assert_eq!(flushed, vec![0xff, 0xfe, 0x00]);
        assert!(pending.is_empty());
    }
}
