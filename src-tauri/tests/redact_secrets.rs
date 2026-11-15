//! 密钥正样本召回：各供应商格式的假密钥必须被替换，且周边文本保持原样。
//!
//! 语料见 `tests/fixtures/redact/secrets-by-provider.json`。这些值都是按真实
//! 格式拼出的虚构数据，用于锁定「新增规则或调整规则集后仍然识别」的行为。

use std::fs;
use std::path::PathBuf;

use cc_switch_lib::redact::{Engine, PlaceholderTable, RedactConfig};
use serde_json::Value;

fn load_cases() -> Vec<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/redact/secrets-by-provider.json");
    let raw =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("读取 {} 失败: {e}", path.display()));
    let fixture: Value = serde_json::from_str(&raw).expect("密钥语料不是合法 JSON");
    fixture["cases"]
        .as_array()
        .expect("cases 必须是数组")
        .clone()
}

#[test]
fn every_provider_secret_is_masked() {
    let config = RedactConfig {
        enabled: true,
        ..Default::default()
    };
    let engine = Engine::with_builtin(&config);

    let mut failures = Vec::new();
    let mut stale_known_issues = Vec::new();
    let mut known_issues = 0usize;
    let cases = load_cases();
    for case in &cases {
        let id = case["id"].as_str().expect("id");
        let provider = case["provider"].as_str().expect("provider");
        // 部分假密钥按前缀/正文分开存放：平台密钥扫描会把拼接后的字符串
        // 当成真凭据并拦截推送，分开写不影响测试覆盖。
        let secret = match case.get("secret_parts").and_then(Value::as_array) {
            Some(parts) => parts
                .iter()
                .map(|part| part.as_str().expect("secret_parts 元素"))
                .collect::<String>(),
            None => case["secret"].as_str().expect("secret").to_string(),
        };
        let text = case["text"]
            .as_str()
            .expect("text")
            .replace("{secret}", &secret);
        let text = text.as_str();
        let known = case.get("known_issue").and_then(Value::as_str);

        let mut table = PlaceholderTable::with_seed(7);
        let outcome = engine.mask_text(text, &config, &mut table);

        let mut case_failures = Vec::new();
        if outcome.text.contains(secret.as_str()) {
            case_failures.push(format!("{id}（{provider}）：{secret:?} 未被脱敏"));
        }
        if !outcome.text.contains("{{SECRET_") {
            case_failures.push(format!(
                "{id}（{provider}）：没有生成 SECRET 占位符，结果 {:?}",
                outcome.text
            ));
        }
        // 密钥之外的文本必须保留，避免「整段改写」式的过度脱敏。
        // 语料可用 `keep` 显式指定上下文，否则按 secret 切分自动推导。
        let context: Vec<&str> = match case.get("keep").and_then(Value::as_array) {
            Some(items) => items
                .iter()
                .map(|item| item.as_str().expect("keep 值"))
                .collect(),
            None => text
                .split(secret.as_str())
                .filter(|part| !part.is_empty())
                .collect(),
        };
        for part in &context {
            if !outcome.text.contains(*part) {
                case_failures.push(format!(
                    "{id}（{provider}）：上下文 {part:?} 被一起改写了，结果 {:?}",
                    outcome.text
                ));
            }
        }

        match known {
            Some(reason) => {
                known_issues += 1;
                if case_failures.is_empty() {
                    stale_known_issues.push(format!(
                        "{id}：已不再漏检（{reason}），请移除 known_issue 标记"
                    ));
                }
            }
            None => failures.extend(case_failures),
        }
    }

    assert!(
        failures.is_empty(),
        "{} / {} 条密钥样本未按预期脱敏：\n{}",
        failures.len(),
        cases.len(),
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
fn note_bearing_context_still_masks_the_value() {
    // `KEY=value` 形态要求键名按分隔符含敏感词，值还必须像凭据。
    // 这一条锁定「值像凭据就一定脱敏」的行为，避免后续放宽值过滤时漏掉。
    let config = RedactConfig {
        enabled: true,
        ..Default::default()
    };
    let engine = Engine::with_builtin(&config);
    let mut table = PlaceholderTable::with_seed(7);

    let text = "export GITHUB_TOKEN=ghp_AbC123xYz456QwE789RtY012UiO345PqR6789";
    let outcome = engine.mask_text(text, &config, &mut table);

    assert!(
        !outcome
            .text
            .contains("ghp_AbC123xYz456QwE789RtY012UiO345PqR6789"),
        "导出语句里的令牌应被脱敏：{}",
        outcome.text
    );
    assert!(
        outcome.text.contains("export GITHUB_TOKEN="),
        "键名应保留：{}",
        outcome.text
    );
}
