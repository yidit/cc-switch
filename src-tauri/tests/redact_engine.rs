//! Phase 1 验收：规则引擎在 magpie 评估语料上的覆盖与误报。
//!
//! 规则层的承诺范围见 `docs/redact/scope.md`：
//! - SECRET / EMAIL / PHONE / ACCOUNT 的 `mask` 值必须全部脱敏；
//! - 所有 `keep` 值都必须保持原样；
//! - PERSON / ADDRESS 的 `mask` 值不要求覆盖（留给可选的模型阶段）。

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use cc_switch_lib::redact::{Engine, PlaceholderTable, RedactConfig};
use regex::Regex;
use serde_json::Value;

/// 占位符与 magpie 一致：`{{KIND_xxxxxxxx}}`。
const PLACEHOLDER: &str = r"\{\{[A-Z_]+_[a-z2-7]{8}\}\}";

/// 第一阶段承诺覆盖的类型。
const RULE_KINDS: [&str; 4] = ["SECRET", "EMAIL", "PHONE", "ACCOUNT"];

fn load_cases() -> Vec<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/redact/eval-cases.json");
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("读取 {} 失败: {e}", path.display()));
    let fixture: Value = serde_json::from_str(&raw).expect("评估语料不是合法 JSON");
    fixture["cases"]
        .as_array()
        .expect("cases 必须是数组")
        .clone()
}

#[derive(Default)]
struct Count {
    mask: usize,
    covered: usize,
    keep: usize,
    wrong: usize,
}

#[test]
fn rule_engine_meets_the_evaluation_baseline() {
    let config = RedactConfig {
        enabled: true,
        ..Default::default()
    };
    let engine = Engine::with_builtin(&config);
    let placeholder = Regex::new(PLACEHOLDER).expect("占位符正则应合法");

    let mut stats: BTreeMap<String, Count> = BTreeMap::new();
    let mut failures = Vec::new();

    for case in load_cases() {
        let id = case["id"].as_str().unwrap();
        let text = case["text"].as_str().unwrap();

        let mut table = PlaceholderTable::with_seed(42);
        let outcome = engine.mask_text(text, &config, &mut table);
        // 先去掉占位符，避免占位符后缀偶然拼出原值。
        let masked = placeholder.replace_all(&outcome.text, "\u{0}");

        for (field, expect_masked) in [("mask", true), ("keep", false)] {
            for item in case[field].as_array().unwrap() {
                let value = item["value"].as_str().unwrap();
                let kind = item["kind"].as_str().unwrap();
                let entry = stats.entry(kind.to_string()).or_default();

                let is_masked = !masked.contains(value);
                if expect_masked {
                    entry.mask += 1;
                    if is_masked {
                        entry.covered += 1;
                    } else if RULE_KINDS.contains(&kind) {
                        failures.push(format!("{id}: {kind} {value:?} 未脱敏"));
                    }
                } else {
                    entry.keep += 1;
                    if is_masked {
                        entry.wrong += 1;
                        failures.push(format!("{id}: {kind} {value:?} 被误脱敏"));
                    }
                }
            }
        }
    }

    // 打印统计，失败时能直接看出哪一类退化。
    for (kind, count) in &stats {
        eprintln!(
            "{kind:8} mask {}/{}  keep-wrong {}/{}",
            count.covered, count.mask, count.wrong, count.keep
        );
    }

    assert!(
        failures.is_empty(),
        "规则引擎未达到评估基线：\n{}",
        failures.join("\n")
    );

    // 规则层承诺覆盖的四类必须全中。
    for kind in RULE_KINDS {
        let count = stats.get(kind).unwrap_or_else(|| panic!("缺少 {kind} 统计"));
        assert_eq!(
            count.covered, count.mask,
            "{kind} 的 mask 覆盖不完整：{}/{}",
            count.covered, count.mask
        );
    }

    // 全部 keep 都不能被误伤。
    for (kind, count) in &stats {
        assert_eq!(count.wrong, 0, "{kind} 出现误报");
    }
}
