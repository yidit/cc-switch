//! 本地模型评估：阈值网格下的召回与误改。
//!
//! 默认 `#[ignore]`，因为需要先下载模型文件（设置页「下载模型」或
//! `redact_model_status` / `download_redact_model` 命令）。运行方式：
//!
//! ```text
//! cargo test --test redact_model_eval -- --ignored --nocapture
//! ```
//!
//! 模型只新增 PERSON / ADDRESS 等自由文本类型；SECRET、EMAIL 等仍由规则层负责，
//! 因此这里单独统计模型自己的命中，不与规则层的结果混算。

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use cc_switch_lib::redact::{model, ModelConfig, RedactConfig};
use serde_json::Value;

/// 评估的阈值网格。0.8 是默认值。
const THRESHOLDS: [f32; 3] = [0.8, 0.5, 0.3];

/// 默认阈值下的最低召回：mask 值至少被找到这么多。
const MIN_COVERAGE_AT_DEFAULT: f64 = 0.80;
/// 默认阈值下允许的误改比例。
const MAX_WRONG_AT_DEFAULT: f64 = 0.03;

fn config(threshold: f32) -> RedactConfig {
    RedactConfig {
        enabled: true,
        // 模型输出会按开关过滤：两个总开关都关时什么都不剩。
        secrets: true,
        personal: true,
        model: ModelConfig {
            enabled: true,
            threshold,
            max_tokens_per_request: 4096,
        },
        ..Default::default()
    }
}

fn load_cases() -> Vec<Value> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/redact/eval-cases.json");
    let raw =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("读取 {} 失败: {e}", path.display()));
    let fixture: Value = serde_json::from_str(&raw).expect("评估语料不是合法 JSON");
    fixture["cases"]
        .as_array()
        .expect("cases 必须是数组")
        .clone()
}

/// 把命中区间替换成 `█`，只用于判断「原值是否还在」。
fn mask_by_hits(text: &str, hits: &[cc_switch_lib::redact::Hit]) -> String {
    let mut sorted = hits.to_vec();
    sorted.sort_by_key(|hit| (hit.start, hit.end));
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0usize;
    for hit in sorted {
        if hit.start < cursor || hit.end > text.len() {
            continue;
        }
        out.push_str(&text[cursor..hit.start]);
        out.push('█');
        cursor = hit.end;
    }
    out.push_str(&text[cursor..]);
    out
}

#[derive(Default, Clone, Copy)]
struct Stats {
    mask: usize,
    covered: usize,
    keep: usize,
    wrong: usize,
    hits: usize,
}

fn evaluate(threshold: f32, cases: &[Value]) -> BTreeMap<String, Stats> {
    let config = config(threshold);
    let engine = model::load_engine().expect("本地模型应能加载（先下载模型文件）");
    let mut stats: BTreeMap<String, Stats> = BTreeMap::new();

    for case in cases {
        let text = case["text"].as_str().expect("text");
        let mut budget = config.model.max_tokens_per_request;
        let hits = engine
            .detect(text, &config, &mut budget)
            .expect("推理不应失败");
        let masked = mask_by_hits(text, &hits);

        for hit in &hits {
            let kind = format!("{:?}", hit.kind).to_uppercase();
            stats.entry(kind).or_default().hits += 1;
        }
        for entry in case["mask"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
            let value = entry["value"].as_str().unwrap_or("");
            let kind = entry["kind"].as_str().unwrap_or("?").to_string();
            let row = stats.entry(kind).or_default();
            row.mask += 1;
            if !masked.contains(value) {
                row.covered += 1;
            }
        }
        for entry in case["keep"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
            let value = entry["value"].as_str().unwrap_or("");
            let kind = entry["kind"].as_str().unwrap_or("?").to_string();
            let row = stats.entry(kind).or_default();
            row.keep += 1;
            if !masked.contains(value) {
                row.wrong += 1;
            }
        }
    }
    stats
}

#[test]
#[ignore = "需要本地模型文件：cargo test --test redact_model_eval -- --ignored --nocapture"]
fn model_meets_its_threshold_baseline() {
    let cases = load_cases();
    let mut results = Vec::new();

    for threshold in THRESHOLDS {
        let stats = evaluate(threshold, &cases);
        let mut mask = 0usize;
        let mut covered = 0usize;
        let mut keep = 0usize;
        let mut wrong = 0usize;
        println!("阈值 {threshold}：{} 个用例", cases.len());
        for (kind, row) in &stats {
            println!(
                "  {kind:<8} 模型命中 {:>3}  mask {}/{}  keep-wrong {}/{}",
                row.hits, row.covered, row.mask, row.wrong, row.keep
            );
            mask += row.mask;
            covered += row.covered;
            keep += row.keep;
            wrong += row.wrong;
        }
        println!("  合计：mask {covered}/{mask}，keep-wrong {wrong}/{keep}");
        results.push((threshold, covered, mask, wrong, keep));
    }

    let (_, covered, mask, wrong, keep) = results[0];
    let coverage = covered as f64 / mask.max(1) as f64;
    let wrong_rate = wrong as f64 / keep.max(1) as f64;

    assert!(
        coverage >= MIN_COVERAGE_AT_DEFAULT,
        "默认阈值召回 {:.1}% 低于下限 {:.0}%：{covered}/{mask}",
        coverage * 100.0,
        MIN_COVERAGE_AT_DEFAULT * 100.0
    );
    assert!(
        wrong_rate <= MAX_WRONG_AT_DEFAULT,
        "默认阈值误改 {:.1}% 高于上限 {:.0}%：{wrong}/{keep}",
        wrong_rate * 100.0,
        MAX_WRONG_AT_DEFAULT * 100.0
    );
}

#[test]
#[ignore = "需要本地模型文件"]
fn exhausted_budget_stops_inference() {
    let config = config(0.8);
    let engine = model::load_engine().expect("本地模型应能加载");
    let mut budget = 0usize;

    let hits = engine
        .detect(
            "Alice Johnson lives in San Francisco.",
            &config,
            &mut budget,
        )
        .expect("预算为 0 时应直接返回空结果");

    assert!(hits.is_empty(), "预算为 0 时不应产生命中");
    assert_eq!(budget, 0, "预算不应被消耗成负数或回填");
}
