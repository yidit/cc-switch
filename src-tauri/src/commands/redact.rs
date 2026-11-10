//! 请求脱敏的设置与预览命令。

use serde::Serialize;

/// 脱敏预览结果。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactPreviewResult {
    /// 按当前配置脱敏后的文本。
    pub masked: String,
    /// 命中的区间数量。
    pub hits: usize,
    /// 写入的占位符数量。
    pub placeholders: usize,
}

/// 用当前保存的脱敏配置预览一段文本。
///
/// 预览总是按「已开启」处理，方便用户在打开总开关前看到效果；不改动任何状态。
#[tauri::command]
pub fn preview_redaction(text: String) -> Result<RedactPreviewResult, String> {
    let mut config = crate::settings::redact_config();
    config.enabled = true;

    let engine = crate::redact::Engine::with_builtin(&config);
    let mut table = crate::redact::PlaceholderTable::new();
    let outcome = engine.mask_text(&text, &config, &mut table);

    Ok(RedactPreviewResult {
        masked: outcome.text,
        hits: outcome.hits.len(),
        placeholders: outcome.placeholders,
    })
}
