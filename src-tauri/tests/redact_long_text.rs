//! 长文本：256K / 512K 量级的召回、误判、往返与耗时。
//!
//! 真实场景里长文本主要来自「整段代码上下文」和「长对话历史」。这里用三种
//! 形态压不同路径：
//! - 纯散文：基础扫描成本与误判；
//! - 稀疏敏感：每 50KB 一个敏感值，检验召回不被长度稀释；
//! - 密集敏感：每 1KB 一个密钥，压最坏路径（大量命中、占位符表与重写）。
//!
//! 耗时数字来自当前构建配置（`cargo test` 默认是 debug，CI 的 nextest 也是）。
//! 断言只设「不得病态变慢」的宽松上限，具体数字用 `--nocapture` 观察。

use std::time::{Duration, Instant};

use cc_switch_lib::redact::{Engine, PlaceholderTable, RedactConfig};

const EMAIL: &str = "jane.smith@acme.com";
const PHONE: &str = "415-555-0132";
const KEY: &str = "sk-proj-AbC123xYz456QwE789RtY012UiO345";

/// 单次处理的宽松上限：超过说明出现了病态复杂度，而不是「慢一点」。
const SANITY_LIMIT: Duration = Duration::from_secs(60);

fn enabled() -> RedactConfig {
    RedactConfig {
        enabled: true,
        ..Default::default()
    }
}

/// 一段不含任何敏感值的普通文本。
fn prose_block() -> &'static str {
    "The parser walks the token stream and records each identifier for later analysis. \
     Numbers such as 42, 3.14 and 2024 remain untouched. "
}

/// 拼到至少 `size` 字节的纯散文。
fn prose_of_size(size: usize) -> String {
    let block = prose_block();
    let mut text = String::with_capacity(size + block.len());
    while text.len() < size {
        text.push_str(block);
    }
    text
}

/// 每 50KB 放一个敏感值，返回文本与放入的值。
fn sparse_of_size(size: usize) -> (String, Vec<&'static str>) {
    let block = prose_block();
    let mut text = String::with_capacity(size + block.len());
    let mut values = Vec::new();
    let mut next_at = 0usize;
    while text.len() < size {
        if text.len() >= next_at {
            let value = match values.len() % 3 {
                0 => EMAIL,
                1 => PHONE,
                _ => KEY,
            };
            text.push_str(value);
            text.push(' ');
            values.push(value);
            next_at = text.len() + 50 * 1024;
        }
        text.push_str(block);
    }
    (text, values)
}

/// 每 1KB 放一个互不相同的密钥，返回文本与全部密钥。
fn dense_of_size(size: usize) -> (String, Vec<String>) {
    let block = prose_block();
    let mut text = String::with_capacity(size + block.len());
    let mut keys = Vec::new();
    let mut index = 0usize;
    while text.len() < size {
        let key = format!("sk-proj-AbC{index:05}QwE789RtY012UiO345XyZ");
        text.push_str(&key);
        text.push(' ');
        keys.push(key);
        index += 1;
        // 用普通文本把相邻密钥隔开，避免它们粘连成别的形态。
        text.push_str(block);
    }
    (text, keys)
}

fn elapsed_note(label: &str, bytes: usize, elapsed: Duration, hits: usize) {
    let per_mb = elapsed.as_secs_f64() / (bytes as f64 / (1024.0 * 1024.0));
    println!(
        "{label}: {} KB，{elapsed:?}（{per_mb:.1} ms/MB），命中 {hits}",
        bytes / 1024
    );
}

#[test]
fn plain_prose_has_no_placeholders_at_any_size() {
    let config = enabled();
    let engine = Engine::with_builtin(&config);

    for size in [64 * 1024, 256 * 1024, 512 * 1024] {
        let text = prose_of_size(size);
        let mut table = PlaceholderTable::with_seed(7);
        let start = Instant::now();
        let outcome = engine.mask_text(&text, &config, &mut table);
        let elapsed = start.elapsed();

        elapsed_note("纯散文", text.len(), elapsed, outcome.hits.len());
        assert_eq!(
            outcome.placeholders,
            0,
            "{} KB 纯散文不应产生占位符",
            size / 1024
        );
        assert_eq!(outcome.text, text, "纯散文应原样保留");
        assert!(elapsed < SANITY_LIMIT, "纯散文处理耗时异常：{elapsed:?}");
    }
}

#[test]
fn sparse_secrets_survive_long_context() {
    let config = enabled();
    let engine = Engine::with_builtin(&config);

    for size in [64 * 1024, 256 * 1024, 512 * 1024] {
        let (text, values) = sparse_of_size(size);
        let mut table = PlaceholderTable::with_seed(7);
        let start = Instant::now();
        let outcome = engine.mask_text(&text, &config, &mut table);
        let elapsed = start.elapsed();

        elapsed_note("稀疏敏感", text.len(), elapsed, outcome.hits.len());
        for value in &values {
            assert!(
                !outcome.text.contains(value),
                "{} KB 文本中 {value:?} 未被脱敏",
                size / 1024
            );
        }
        // 往返：把占位符还原回原值，必须与原文逐字相等。
        assert_eq!(table.restore(&outcome.text), text, "往返结果不一致");
        assert!(elapsed < SANITY_LIMIT, "稀疏敏感处理耗时异常：{elapsed:?}");
    }
}

#[test]
fn long_text_placeholders_are_stable_across_requests() {
    // 长对话的真实形态：每一轮都把完整历史重新发上来。只要盐值固定，
    // 同一份历史两次脱敏的结果必须逐字节相同，否则上游提示缓存每轮失效。
    let config = RedactConfig {
        enabled: true,
        salt: Some("fixed-long-text-salt".to_string()),
        ..Default::default()
    };
    let engine = Engine::with_builtin(&config);
    let (text, _values) = sparse_of_size(512 * 1024);

    let mut first_table = PlaceholderTable::from_config(&config);
    let first = engine.mask_text(&text, &config, &mut first_table);
    let mut second_table = PlaceholderTable::from_config(&config);
    let second = engine.mask_text(&text, &config, &mut second_table);

    assert_eq!(
        first.text, second.text,
        "同一份 512 KB 文本两次脱敏结果必须逐字节相同"
    );
    assert_eq!(first.placeholders, second.placeholders, "占位符数量应一致");
    assert!(first.placeholders > 0, "语料里应有敏感值");
    assert_eq!(first_table.restore(&first.text), text, "第一次往返不一致");
    assert_eq!(second_table.restore(&second.text), text, "第二次往返不一致");
}

#[test]
fn dense_secrets_all_get_masked() {
    let config = enabled();
    let engine = Engine::with_builtin(&config);

    for size in [64 * 1024, 256 * 1024, 512 * 1024] {
        let (text, keys) = dense_of_size(size);
        let mut table = PlaceholderTable::with_seed(7);
        let start = Instant::now();
        let outcome = engine.mask_text(&text, &config, &mut table);
        let elapsed = start.elapsed();

        elapsed_note("密集密钥", text.len(), elapsed, outcome.hits.len());
        for key in &keys {
            assert!(
                !outcome.text.contains(key.as_str()),
                "{} KB 文本中密钥 {key:?} 未被脱敏",
                size / 1024
            );
        }
        assert!(
            outcome.placeholders >= keys.len(),
            "占位符数量 {} 少于密钥数量 {}",
            outcome.placeholders,
            keys.len()
        );
        assert_eq!(table.restore(&outcome.text), text, "往返结果不一致");
        assert!(elapsed < SANITY_LIMIT, "密集密钥处理耗时异常：{elapsed:?}");
    }
}

#[test]
fn large_json_body_is_fully_masked() {
    use serde_json::json;

    let config = enabled();
    // 20 条消息，每条约 25KB，合计约 500KB。
    let filler = prose_block().repeat(180);
    let mut messages = Vec::new();
    for index in 0..20 {
        let text = format!("{filler} item {index} mail {EMAIL} phone {PHONE}");
        messages.push(json!({"role": "user", "content": text}));
    }
    let mut body = json!({"model": "claude-3-5-sonnet-20241022", "messages": messages});

    let start = Instant::now();
    let table = cc_switch_lib::redact::proxy::mask_request_body(&mut body, &config)
        .expect("脱敏不应失败")
        .expect("应当有命中");
    let elapsed = start.elapsed();

    let serialized = serde_json::to_vec(&body).expect("序列化");
    let serialized = String::from_utf8(serialized).expect("UTF-8");
    elapsed_note("JSON 请求体", serialized.len(), elapsed, 0);

    assert!(!serialized.contains(EMAIL), "邮箱未被脱敏");
    assert!(!serialized.contains(PHONE), "电话未被脱敏");
    assert_eq!(
        body["model"], "claude-3-5-sonnet-20241022",
        "模型字段不应被改"
    );
    assert!(
        table.restore(&serialized).contains(EMAIL),
        "还原后应恢复原值"
    );
    assert!(
        elapsed < SANITY_LIMIT,
        "JSON 请求体处理耗时异常：{elapsed:?}"
    );
}

#[test]
fn long_sse_line_is_restored_in_chunks() {
    use cc_switch_lib::redact::proxy;

    let config = enabled();
    let engine = Engine::with_builtin(&config);

    // 一段含 500 个占位符的文本，模拟上游把长回复塞进单行 SSE。
    let mut source = String::new();
    for index in 0..500 {
        source.push_str(&format!("mail user{index}@acme.com "));
    }
    let mut table = PlaceholderTable::with_seed(7);
    let outcome = engine.mask_text(&source, &config, &mut table);
    assert!(outcome.placeholders >= 400, "应产生足量占位符");

    let line = format!("data: {}\n\n", outcome.text);

    let start = Instant::now();
    let mut pending = Vec::new();
    let mut output = Vec::new();
    for chunk in line.as_bytes().chunks(4096) {
        output.extend(proxy::restore_stream_chunk(&table, &mut pending, chunk));
    }
    if let Some(tail) = proxy::flush_stream_restore(&table, &mut pending) {
        output.extend(tail);
    }
    let elapsed = start.elapsed();

    elapsed_note("SSE 还原", line.len(), elapsed, outcome.placeholders);

    let restored = String::from_utf8(output).expect("还原结果应为 UTF-8");
    assert_eq!(restored, format!("data: {source}\n\n"));
    assert!(elapsed < SANITY_LIMIT, "SSE 还原耗时异常：{elapsed:?}");
}
