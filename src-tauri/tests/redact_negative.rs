//! 误判回归：负样本必须逐字保留，且整段文本不产生任何占位符。
//!
//! 语料见 `tests/fixtures/redact/negative-cases.json`，按误判成因分类。
//! 与 `redact_engine.rs` 的区别：那边的 `keep` 混在正样本里，这边是专门
//! 针对「看起来像敏感值、实际不是」的文本，任何一条被改写都视为回归。

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use cc_switch_lib::redact::{Engine, PlaceholderTable, RedactConfig};
use regex::Regex;
use serde_json::Value;

/// 占位符形如 `{{KIND_xxxxxxxx}}`。
const PLACEHOLDER: &str = r"\{\{[A-Z_]+_[a-z2-7]{8}\}\}";

fn load_cases() -> Vec<Value> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/redact/negative-cases.json");
    let raw =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("读取 {} 失败: {e}", path.display()));
    let fixture: Value = serde_json::from_str(&raw).expect("负样本语料不是合法 JSON");
    fixture["cases"]
        .as_array()
        .expect("cases 必须是数组")
        .clone()
}

#[test]
fn negative_cases_stay_untouched() {
    let config = RedactConfig {
        enabled: true,
        ..Default::default()
    };
    let engine = Engine::with_builtin(&config);
    let placeholder = Regex::new(PLACEHOLDER).expect("占位符正则应合法");

    let mut categories: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut failures = Vec::new();
    let mut stale_known_issues = Vec::new();
    let mut known_issues = 0usize;

    for case in load_cases() {
        let id = case["id"].as_str().expect("id");
        let category = case["category"].as_str().expect("category");
        let text = case["text"].as_str().expect("text");
        let known = case.get("known_issue").and_then(Value::as_str);

        let mut table = PlaceholderTable::with_seed(7);
        let outcome = engine.mask_text(text, &config, &mut table);

        let mut case_failures = Vec::new();
        for keep in case["keep"].as_array().expect("keep") {
            let value = keep.as_str().expect("keep 值");
            if !outcome.text.contains(value) {
                case_failures.push(format!(
                    "{id}（{category}）：{value:?} 被改写，原因：{}",
                    case["reason"].as_str().unwrap_or("")
                ));
            }
        }
        if placeholder.is_match(&outcome.text) {
            case_failures.push(format!(
                "{id}（{category}）：产生占位符，脱敏结果 {:?}",
                outcome.text
            ));
        }

        match known {
            // 已知问题：必须仍然复现；修复后应删除标记，否则这里会提醒。
            Some(reason) => {
                known_issues += 1;
                if case_failures.is_empty() {
                    stale_known_issues.push(format!(
                        "{id}：已不再误判（{reason}），请移除 known_issue 标记"
                    ));
                }
            }
            None => {
                let entry = categories.entry(category.to_string()).or_default();
                entry.0 += 1;
                if !case_failures.is_empty() {
                    entry.1 += 1;
                    failures.extend(case_failures);
                }
            }
        }
    }

    let summary = categories
        .iter()
        .map(|(name, (total, wrong))| format!("{name}: {wrong}/{total} 误判"))
        .collect::<Vec<_>>()
        .join("，");

    assert!(
        failures.is_empty(),
        "负样本出现误判（{summary}）：\n{}",
        failures.join("\n")
    );
    assert!(
        stale_known_issues.is_empty(),
        "以下已知问题已修复，请更新语料：\n{}（当前记录 {} 条已知问题）",
        stale_known_issues.join("\n"),
        known_issues
    );
}

#[test]
fn allowlist_values_are_never_masked() {
    let config = RedactConfig {
        enabled: true,
        allow: vec!["sk-proj-KeepThisKey1234567890abcdef".to_string()],
        ..Default::default()
    };
    let engine = Engine::with_builtin(&config);
    let mut table = PlaceholderTable::with_seed(7);

    let text =
        "allowed sk-proj-KeepThisKey1234567890abcdef and blocked sk-proj-OtherKey1234567890abcdef";
    let outcome = engine.mask_text(text, &config, &mut table);

    assert!(
        outcome.text.contains("sk-proj-KeepThisKey1234567890abcdef"),
        "白名单里的值不应被脱敏：{}",
        outcome.text
    );
    assert!(
        !outcome.text.contains("sk-proj-OtherKey1234567890abcdef"),
        "白名单之外的值仍应脱敏：{}",
        outcome.text
    );
}

#[test]
fn custom_words_respect_the_whole_word_switch() {
    let mut config = RedactConfig {
        enabled: true,
        words: vec!["Ann".to_string()],
        words_whole: true,
        ..Default::default()
    };
    let engine = Engine::with_builtin(&config);

    let mut table = PlaceholderTable::with_seed(7);
    let whole = engine.mask_text("Annual report for Ann", &config, &mut table);
    assert!(
        whole.text.contains("Annual"),
        "整词匹配不应命中 Annual：{}",
        whole.text
    );
    assert!(
        !whole.text.contains("Ann "),
        "整词匹配应命中独立的 Ann：{}",
        whole.text
    );

    config.words_whole = false;
    let engine = Engine::with_builtin(&config);
    let mut table = PlaceholderTable::with_seed(7);
    let substring = engine.mask_text("Annual report", &config, &mut table);
    assert!(
        !substring.text.contains("Annual"),
        "关闭整词匹配后应按子串命中：{}",
        substring.text
    );
}

#[test]
fn disabled_kinds_leave_matching_text_alone() {
    let config = RedactConfig {
        enabled: true,
        kinds: vec![cc_switch_lib::redact::Kind::Secret],
        ..Default::default()
    };
    let engine = Engine::with_builtin(&config);
    let mut table = PlaceholderTable::with_seed(7);

    let text = "mail jane.smith@acme.com and key sk-proj-AbC123xYz456QwE789RtY";
    let outcome = engine.mask_text(text, &config, &mut table);

    assert!(
        outcome.text.contains("jane.smith@acme.com"),
        "只勾选密钥时邮箱不应被处理：{}",
        outcome.text
    );
    assert!(
        !outcome.text.contains("sk-proj-AbC123xYz456QwE789RtY"),
        "勾选的密钥类型仍应脱敏：{}",
        outcome.text
    );
}
