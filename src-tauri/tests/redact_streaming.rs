//! 结构化往返：JSON 请求脱敏后必须能逐值还原，SSE 分块不能破坏占位符。
//!
//! 这里的用例覆盖代理链路的两个关键不变量：
//! - 请求体脱敏 → 响应回显占位符 → 还原后与原文一致；
//! - 占位符被任意位置切开时，流式还原仍能得到完整原值。

use cc_switch_lib::redact::{json, proxy, Engine, PlaceholderTable, RedactConfig};
use serde_json::json;

fn enabled() -> RedactConfig {
    RedactConfig {
        enabled: true,
        ..Default::default()
    }
}

const EMAIL: &str = "jane.smith@acme.com";
const PHONE: &str = "415-555-0132";
const KEY: &str = "sk-proj-AbC123xYz456QwE789RtY012UiO345";

#[test]
fn json_request_round_trips_through_restore() {
    let original = json!({
        "model": "claude-3-5-sonnet-20241022",
        "messages": [
            {"role": "user", "content": format!("mail {EMAIL} or call {PHONE}")},
            {"role": "user", "content": format!("key {KEY}")}
        ],
        "metadata": {"type": "text", "session_id": "550e8400-e29b-41d4-a716-446655440000"}
    });
    let mut body = original.clone();

    let table = proxy::mask_request_body(&mut body, &enabled())
        .expect("脱敏不应失败")
        .expect("应当有命中");
    assert!(!body.to_string().contains(EMAIL));
    assert!(!body.to_string().contains(PHONE));
    assert!(!body.to_string().contains(KEY));

    // 上游把请求内容原样回显在响应里，占位符需要还原成原值。
    let masked_text = body["messages"][0]["content"].as_str().unwrap().to_string();
    let mut response = json!({"content": [{"type": "text", "text": masked_text}]});
    let restored = json::restore_json(&mut response, &table);

    assert_eq!(restored, 1);
    assert_eq!(
        response["content"][0]["text"].as_str().unwrap(),
        format!("mail {EMAIL} or call {PHONE}")
    );
    // 结构化字段必须保持原样。
    assert_eq!(body["model"], original["model"]);
    assert_eq!(body["metadata"], original["metadata"]);
}

#[test]
fn plain_response_body_is_restored() {
    let config = enabled();
    let engine = Engine::with_builtin(&config);
    let mut table = PlaceholderTable::with_seed(7);
    let outcome = engine.mask_text(&format!("contact {EMAIL}"), &config, &mut table);
    let masked = outcome.text;

    let response = format!("Here is the address: {masked}\n");
    let restored = proxy::restore_response_body(response.as_bytes(), &table).expect("应发生还原");

    assert_eq!(
        String::from_utf8(restored).unwrap(),
        format!("Here is the address: contact {EMAIL}\n")
    );
}

#[test]
fn sse_restores_placeholders_split_at_any_byte() {
    let config = enabled();
    let engine = Engine::with_builtin(&config);
    let mut table = PlaceholderTable::with_seed(7);
    let outcome = engine.mask_text(
        &format!("mail {EMAIL} and call {PHONE}"),
        &config,
        &mut table,
    );
    let masked = outcome.text;
    let expected = format!("data: mail {EMAIL} and call {PHONE}\n\n");
    let input = format!("data: {masked}\n\n");

    // 逐字节喂入：占位符必然被切在每一个可能的位置上。
    let mut pending = Vec::new();
    let mut output = Vec::new();
    for byte in input.as_bytes() {
        output.extend(proxy::restore_stream_chunk(
            &table,
            &mut pending,
            std::slice::from_ref(byte),
        ));
    }
    if let Some(tail) = proxy::flush_stream_restore(&table, &mut pending) {
        output.extend(tail);
    }

    assert_eq!(String::from_utf8(output).unwrap(), expected);
}

#[test]
fn sse_flush_restores_a_tail_without_newline() {
    let config = enabled();
    let engine = Engine::with_builtin(&config);
    let mut table = PlaceholderTable::with_seed(7);
    let outbreak = engine.mask_text(&format!("tail {EMAIL}"), &config, &mut table);

    let mut pending = Vec::new();
    let output = proxy::restore_stream_chunk(&table, &mut pending, outbreak.text.as_bytes());
    assert!(output.is_empty(), "没有换行时应先缓冲");
    let tail = proxy::flush_stream_restore(&table, &mut pending).expect("结束时应有剩余内容");
    assert_eq!(String::from_utf8(tail).unwrap(), format!("tail {EMAIL}"));
}

#[test]
fn whole_body_is_byte_identical_across_requests() {
    // 同一请求体连续脱敏两次，序列化结果必须逐字节相同：
    // 这是上游提示缓存能否命中的前提。
    let config = RedactConfig {
        enabled: true,
        salt: Some("fixed-test-salt".to_string()),
        ..Default::default()
    };
    let body = json!({
        "model": "claude-3-5-sonnet-20241022",
        "messages": [
            {"role": "user", "content": format!("mail {EMAIL}")},
            {"role": "user", "content": format!("key {KEY} and call {PHONE}")}
        ]
    });

    let mut first = body.clone();
    let mut second = body.clone();
    let first_table = proxy::mask_request_body(&mut first, &config)
        .expect("脱敏不应失败")
        .expect("应当有命中");
    let second_table = proxy::mask_request_body(&mut second, &config)
        .expect("脱敏不应失败")
        .expect("应当有命中");

    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&second).unwrap(),
        "同盐值下两次脱敏的结果必须逐字节相同"
    );
    assert_eq!(
        first.to_string().matches("{{").count(),
        second.to_string().matches("{{").count(),
        "占位符数量应一致"
    );
    assert_eq!(
        first_table.restore(&first.to_string()),
        second_table.restore(&second.to_string())
    );
}

#[test]
fn placeholders_stay_stable_across_requests_with_a_salt() {
    let config = RedactConfig {
        enabled: true,
        salt: Some("fixed-test-salt".to_string()),
        ..Default::default()
    };
    let engine = Engine::with_builtin(&config);

    let mut first = PlaceholderTable::from_config(&config);
    let mut second = PlaceholderTable::from_config(&config);
    let one = engine.mask_text(EMAIL, &config, &mut first);
    let two = engine.mask_text(EMAIL, &config, &mut second);

    assert_eq!(one.text, two.text, "同盐值下同一原值必须得到相同占位符");
}
