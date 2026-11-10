//! Phase 0 基线：校验从 magpie 转换来的脱敏评估语料是否完整。
//!
//! 本文件不实现脱敏逻辑。Phase 1 的引擎测试会复用同一份
//! `tests/fixtures/redact/eval-cases.json`，按 `docs/redact/eval-baseline.md`
//! 的判定方式统计通过率。

use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

/// 与 docs/redact/eval-baseline.md 保持一致。
const EXPECTED_CASES: usize = 85;
const EXPECTED_MASK_VALUES: usize = 47;
const EXPECTED_KEEP_VALUES: usize = 144;

/// 语料允许的敏感类型。
const KNOWN_KINDS: [&str; 6] = ["SECRET", "PERSON", "PHONE", "EMAIL", "ACCOUNT", "ADDRESS"];

fn load_fixture() -> Value {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/redact/eval-cases.json");
    let raw =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("读取 {} 失败: {e}", path.display()));
    serde_json::from_str(&raw).expect("评估语料不是合法 JSON")
}

fn cases(fixture: &Value) -> &[Value] {
    fixture["cases"]
        .as_array()
        .expect("cases 必须是数组")
        .as_slice()
}

fn values_of(case: &Value, field: &str) -> &[Value] {
    case[field]
        .as_array()
        .unwrap_or_else(|| panic!("{} 必须是数组", field))
        .as_slice()
}

#[test]
fn fixture_has_expected_case_and_value_counts() {
    let fixture = load_fixture();
    let all = cases(&fixture);

    let mask_values: usize = all.iter().map(|c| values_of(c, "mask").len()).sum();
    let keep_values: usize = all.iter().map(|c| values_of(c, "keep").len()).sum();

    assert_eq!(
        all.len(),
        EXPECTED_CASES,
        "用例数变化时，请同步 docs/redact/eval-baseline.md 与这里的常量"
    );
    assert_eq!(mask_values, EXPECTED_MASK_VALUES, "待脱敏值数量变化");
    assert_eq!(keep_values, EXPECTED_KEEP_VALUES, "必须保留值数量变化");
}

#[test]
fn case_ids_are_unique_and_texts_are_not_empty() {
    let fixture = load_fixture();
    let mut seen = HashSet::new();

    for case in cases(&fixture) {
        let id = case["id"].as_str().expect("每个用例都要有 id");
        assert!(!id.is_empty(), "用例 id 不能为空");
        assert!(seen.insert(id.to_string()), "重复的用例 id: {id}");

        let text = case["text"].as_str().expect("每个用例都要有 text");
        assert!(!text.is_empty(), "用例 {id} 的 text 不能为空");
    }
}

#[test]
fn every_value_appears_in_its_text() {
    let fixture = load_fixture();

    for case in cases(&fixture) {
        let id = case["id"].as_str().unwrap();
        let text = case["text"].as_str().unwrap();

        for (field, values) in [
            ("mask", values_of(case, "mask")),
            ("keep", values_of(case, "keep")),
        ] {
            for item in values {
                let value = item["value"]
                    .as_str()
                    .unwrap_or_else(|| panic!("用例 {id} 的 {field} 项缺少 value"));
                assert!(
                    text.contains(value),
                    "用例 {id}: {field} 值 {value:?} 不在原文中"
                );
            }
        }
    }
}

#[test]
fn kinds_are_known() {
    let fixture = load_fixture();

    for case in cases(&fixture) {
        let id = case["id"].as_str().unwrap();
        for field in ["mask", "keep"] {
            for item in values_of(case, field) {
                let kind = item["kind"]
                    .as_str()
                    .unwrap_or_else(|| panic!("用例 {id} 的 {field} 项缺少 kind"));
                assert!(KNOWN_KINDS.contains(&kind), "用例 {id} 出现未知类型 {kind}");
            }
        }
    }
}

#[test]
fn chinese_text_survives_the_conversion() {
    let fixture = load_fixture();
    let case = cases(&fixture)
        .iter()
        .find(|c| c["id"] == "hex-addresses")
        .expect("缺少 hex-addresses 用例");

    let text = case["text"].as_str().unwrap();
    assert!(text.contains("逆向笔记"), "中文文本在转换中损坏");
    assert!(text.contains("0x004EA5E0"), "十六进制值缺失");
}

#[test]
fn fixture_records_its_upstream_revision() {
    let fixture = load_fixture();
    let commit = fixture["upstream_commit"].as_str().unwrap_or_default();
    assert_eq!(commit.len(), 40, "upstream_commit 应是 40 位 sha");
    assert_eq!(fixture["license"], "MIT", "语料必须保留 MIT 许可声明");
}
