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

    // 本地模型：启用但文件不可用时，按 failClosed 决定拒绝还是退回规则层。
    let model = if config.model.enabled {
        match crate::redact::model::load_engine() {
            Ok(model) => Some(model),
            Err(error) => {
                if config.fail_closed {
                    return Err(format!("本地脱敏模型不可用：{error}"));
                }
                log::warn!("本地脱敏模型不可用，本次只使用规则层：{error}");
                None
            }
        }
    } else {
        None
    };

    // 配置了盐值时按盐值计算占位符，不同请求之间保持一致；旧配置没有盐值时，每次请求随机。
    let table = PlaceholderTable::from_config(config);
    let (stats, table) = match run_mask(body, &engine, config, table, model.as_deref()) {
        Ok(result) => result,
        Err(error) => {
            if config.fail_closed {
                return Err(format!("本地脱敏模型推理失败：{error}"));
            }
            // 模型在扫描阶段失败时请求体还没有被改动，退回到只跑规则层。
            log::warn!("本地脱敏模型推理失败，本次只使用规则层：{error}");
            run_mask(
                body,
                &engine,
                config,
                PlaceholderTable::from_config(config),
                None,
            )?
        }
    };

    if stats.placeholders == 0 && stats.hits == 0 {
        return Ok(None);
    }
    Ok(Some(Arc::new(table)))
}

/// 跑一遍脱敏，返回统计与写入了占位符的表。
///
/// 单独抽出来是为了在模型推理失败时能用一张干净的表重跑规则层：`mask_json`
/// 在扫描阶段（模型推理）还没改动请求体，失败后重跑不会留下半成品。
fn run_mask(
    body: &mut Value,
    engine: &Engine,
    config: &RedactConfig,
    mut table: PlaceholderTable,
    model: Option<&crate::redact::ModelEngine>,
) -> Result<(crate::redact::json::JsonMaskStats, PlaceholderTable), String> {
    let stats = mask_json(body, engine, config, &mut table, model)?;
    Ok((stats, table))
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

/// 流式还原最多缓冲的字节数。
///
/// SSE 的行以换行结尾，正常情况下 `pending` 只会剩下一个不完整的短行。
/// 上游若长时间不发送换行，不能无限缓冲（会撑爆内存），超过此值就按纯文本
/// 还原后立即输出；代价是跨该边界的占位符可能漏还原，属于异常上游下的取舍。
const MAX_PENDING_BYTES: usize = 8 * 1024 * 1024;

/// 流式响应里单个 chunk 的还原。
///
/// 按行处理 SSE：完整的行立即还原并输出，不完整的行留在 `pending` 等下一个
/// chunk。`data:` 行如果能解析成 JSON，就在字符串值上还原后重新序列化，避免
/// 带换行、引号或反斜杠的原值破坏 JSON 转义；解析失败时退回按文本还原。
pub fn restore_stream_chunk(
    table: &PlaceholderTable,
    pending: &mut Vec<u8>,
    chunk: &[u8],
) -> Vec<u8> {
    let mut buffer = std::mem::take(pending);
    buffer.extend_from_slice(chunk);

    let mut out = Vec::with_capacity(buffer.len());
    let mut start = 0usize;
    for (index, byte) in buffer.iter().enumerate() {
        if *byte == b'\n' {
            restore_line(table, &buffer[start..=index], &mut out);
            start = index + 1;
        }
    }
    pending.extend_from_slice(&buffer[start..]);

    if pending.len() > MAX_PENDING_BYTES {
        // 超限：把缓冲当作一段纯文本直接还原输出，避免内存无限增长。
        let tail = std::mem::take(pending);
        restore_line(table, &tail, &mut out);
    }
    out
}

/// 流结束时把 `pending` 里剩余的内容还原并返回。
pub fn flush_stream_restore(table: &PlaceholderTable, pending: &mut Vec<u8>) -> Option<Vec<u8>> {
    if pending.is_empty() {
        return None;
    }
    let bytes = std::mem::take(pending);
    let mut out = Vec::with_capacity(bytes.len());
    restore_line(table, &bytes, &mut out);
    Some(out)
}

/// 还原一整行（包含行尾换行符，如果有）。
fn restore_line(table: &PlaceholderTable, line: &[u8], out: &mut Vec<u8>) {
    let Ok(text) = std::str::from_utf8(line) else {
        // 非 UTF-8 字节不可能是占位符的一部分，原样透传。
        out.extend_from_slice(line);
        return;
    };

    let (body, ending) = split_line_ending(text);
    if let Some((prefix, payload)) = sse_data_payload(body) {
        if let Some(restored) = restore_json_payload(table, payload) {
            out.extend_from_slice(prefix.as_bytes());
            out.extend_from_slice(restored.as_bytes());
            out.extend_from_slice(ending.as_bytes());
            return;
        }
    }

    out.extend_from_slice(table.restore(body).as_bytes());
    out.extend_from_slice(ending.as_bytes());
}

/// 拆出行内容与行尾换行符。
fn split_line_ending(text: &str) -> (&str, &str) {
    if let Some(body) = text.strip_suffix("\r\n") {
        (body, "\r\n")
    } else if let Some(body) = text.strip_suffix('\n') {
        (body, "\n")
    } else {
        (text, "")
    }
}

/// 取出 `data:` 行的前缀与 payload（不含行尾换行）。
fn sse_data_payload(line: &str) -> Option<(&str, &str)> {
    let rest = line.strip_prefix("data:")?;
    let payload = rest.strip_prefix(' ').unwrap_or(rest);
    Some((&line[..5], payload))
}

/// 把 `data:` 的 JSON 解析出来还原，返回重新序列化后的 payload；
/// 不是 JSON 或没有变化时返回 `None`，由调用方按纯文本处理。
fn restore_json_payload(table: &PlaceholderTable, payload: &str) -> Option<String> {
    let mut value: Value = serde_json::from_str(payload).ok()?;
    let changed = restore_json(&mut value, table);
    if changed == 0 {
        return None;
    }
    serde_json::to_string(&value).ok()
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
            .expect("关闭 failClosed 后不应报错")
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
            "相同盐值下，相同原值必须得到同一个占位符"
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

    fn parse_sse_line(line: &str) -> Value {
        let payload = line.trim_start_matches("data:").trim();
        serde_json::from_str(payload).expect("SSE data 应是合法 JSON")
    }

    #[test]
    fn restores_a_placeholder_split_across_chunks() {
        let mut table = PlaceholderTable::with_seed(7);
        let placeholder = table.placeholder_for("jane.smith@gmail.com", crate::redact::Kind::Email);
        let line = format!("data: {{\"text\":\"{placeholder}\"}}\n");
        let (first, second) = line.split_at(line.len() / 2);

        let mut pending = Vec::new();
        let out1 = restore_stream_chunk(&table, &mut pending, first.as_bytes());
        let out2 = restore_stream_chunk(&table, &mut pending, second.as_bytes());

        assert!(out1.is_empty(), "不完整的行应留在 pending");
        let value = parse_sse_line(&String::from_utf8(out2).unwrap());
        assert_eq!(value["text"], "jane.smith@gmail.com");
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
        let line = format!("data: {{\"text\":\"{placeholder}\"}}\n");

        for split in 0..=line.len() {
            let mut pending = Vec::new();
            let mut out = Vec::new();
            out.extend(restore_stream_chunk(
                &table,
                &mut pending,
                &line.as_bytes()[..split],
            ));
            out.extend(restore_stream_chunk(
                &table,
                &mut pending,
                &line.as_bytes()[split..],
            ));
            if let Some(tail) = flush_stream_restore(&table, &mut pending) {
                out.extend(tail);
            }

            let value = parse_sse_line(&String::from_utf8(out).unwrap());
            assert_eq!(
                value["text"], "jane.smith@gmail.com",
                "在字节 {split} 处切开时未还原"
            );
            assert!(pending.is_empty(), "在字节 {split} 处切开后仍剩余内容");
        }
    }

    #[test]
    fn restores_placeholders_when_a_chunk_cuts_a_multibyte_character() {
        let mut table = PlaceholderTable::with_seed(7);
        let placeholder = table.placeholder_for("jane.smith@gmail.com", crate::redact::Kind::Email);
        let line = format!("data: {{\"text\":\"{placeholder}中\"}}\n");
        let bytes = line.as_bytes();
        // “中”占 3 字节，在它内部切开：前一个 chunk 的尾部不是合法 UTF-8。
        let split = line.find('中').expect("测试行包含中文") + 1;

        let mut pending = Vec::new();
        let mut out = Vec::new();
        out.extend(restore_stream_chunk(&table, &mut pending, &bytes[..split]));
        out.extend(restore_stream_chunk(&table, &mut pending, &bytes[split..]));
        if let Some(tail) = flush_stream_restore(&table, &mut pending) {
            out.extend(tail);
        }

        let value = parse_sse_line(&String::from_utf8(out).unwrap());
        assert_eq!(
            value["text"], "jane.smith@gmail.com中",
            "切在多字节字符中间时也要还原完整的占位符"
        );
        assert!(pending.is_empty());
    }

    #[test]
    fn passes_invalid_utf8_bytes_through_without_stalling() {
        let mut table = PlaceholderTable::with_seed(7);
        let placeholder = table.placeholder_for("jane.smith@gmail.com", crate::redact::Kind::Email);

        let mut pending = Vec::new();
        let mut out = restore_stream_chunk(&table, &mut pending, &[b'x', 0xff, b'\n']);
        assert_eq!(out, vec![b'x', 0xff, b'\n'], "非法字节应原样输出");
        assert!(pending.is_empty(), "非法字节不能留在缓冲区");

        let line = format!("data: {{\"text\":\"{placeholder}\"}}\n");
        out.extend(restore_stream_chunk(&table, &mut pending, line.as_bytes()));
        let value = parse_sse_line(std::str::from_utf8(&out[3..]).unwrap());
        assert_eq!(value["text"], "jane.smith@gmail.com");
        assert!(pending.is_empty());
    }

    #[test]
    fn restores_json_unsafe_values_in_sse_data() {
        let mut table = PlaceholderTable::with_seed(7);
        let secret = "line1\nline2 \"quoted\" C:\\temp";
        let placeholder = table.placeholder_for(secret, crate::redact::Kind::Secret);
        let line = format!("data: {{\"delta\":{{\"text\":\"{placeholder}\"}}}}\n");

        let mut pending = Vec::new();
        let out = restore_stream_chunk(&table, &mut pending, line.as_bytes());

        let value = parse_sse_line(&String::from_utf8(out).unwrap());
        assert_eq!(value["delta"]["text"], secret);
        assert!(pending.is_empty());
    }

    #[test]
    fn restores_plain_text_sse_lines_without_reserializing() {
        let mut table = PlaceholderTable::with_seed(7);
        let placeholder = table.placeholder_for("415-555-0132", crate::redact::Kind::Phone);
        let line = format!("data: call {placeholder}\n");

        let mut pending = Vec::new();
        let out = restore_stream_chunk(&table, &mut pending, line.as_bytes());

        assert_eq!(String::from_utf8(out).unwrap(), "data: call 415-555-0132\n");
        assert!(pending.is_empty());
    }

    #[test]
    fn passes_other_sse_lines_through() {
        let table = PlaceholderTable::with_seed(7);
        let mut pending = Vec::new();
        let out = restore_stream_chunk(
            &table,
            &mut pending,
            b"event: message\nid: 42\n: keep-alive\n",
        );

        assert_eq!(
            String::from_utf8(out).unwrap(),
            "event: message\nid: 42\n: keep-alive\n"
        );
        assert!(pending.is_empty());
    }

    #[test]
    fn flush_keeps_non_utf8_bytes_untouched() {
        let table = PlaceholderTable::with_seed(7);
        let mut pending = vec![0xff, 0xfe, 0x00];

        let flushed = flush_stream_restore(&table, &mut pending).expect("应返回剩余内容");
        assert_eq!(flushed, vec![0xff, 0xfe, 0x00]);
        assert!(pending.is_empty());
    }

    #[test]
    fn caps_pending_buffer_when_upstream_never_sends_a_newline() {
        let mut table = PlaceholderTable::with_seed(7);
        let placeholder = table.placeholder_for("jane.smith@gmail.com", crate::redact::Kind::Email);

        let mut pending = Vec::new();
        let mut chunk = placeholder.clone().into_bytes();
        chunk.extend(std::iter::repeat(b'x').take(MAX_PENDING_BYTES + 1));

        let out = restore_stream_chunk(&table, &mut pending, &chunk);

        assert!(pending.is_empty(), "超过上限后不能继续缓冲");
        let text = String::from_utf8(out).expect("输出应是合法 UTF-8");
        assert!(text.starts_with("jane.smith@gmail.com"), "{text:.80}");
    }
}
