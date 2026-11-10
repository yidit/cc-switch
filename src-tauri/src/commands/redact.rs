//! 请求脱敏的设置、预览与本地模型管理命令。

use serde::Serialize;

use crate::redact::model_store::{self, ModelStatus};

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
    /// 配置里无法使用的自定义规则（预览会跳过它们）。
    pub errors: Vec<String>,
    /// 本次预览是否用到了本地模型。
    pub used_model: bool,
}

/// 用当前保存的脱敏配置预览一段文本。
///
/// 预览总是按「已开启」处理，方便用户在打开总开关前看到效果；不改动任何状态。
#[tauri::command]
pub async fn preview_redaction(text: String) -> Result<RedactPreviewResult, String> {
    // 本地模型推理较重，放到阻塞线程，避免占住异步运行时。
    tokio::task::spawn_blocking(move || preview(&text))
        .await
        .map_err(|error| format!("预览失败：{error}"))?
}

fn preview(text: &str) -> Result<RedactPreviewResult, String> {
    let mut config = crate::settings::redact_config();
    config.enabled = true;

    let mut errors = crate::redact::invalid_rules(&config.rules);
    let engine = crate::redact::Engine::with_builtin(&config);
    let mut table = crate::redact::PlaceholderTable::from_config(&config);

    let model = if config.model.enabled {
        match crate::redact::model::load_engine() {
            Ok(model) => Some(model),
            Err(error) => {
                errors.push(format!("本地模型不可用：{error}"));
                None
            }
        }
    } else {
        None
    };

    let extra = match &model {
        Some(model) => {
            let mut budget = config.model.max_tokens_per_request;
            model.detect(text, &config, &mut budget)
        }
        None => Vec::new(),
    };

    let outcome = engine.mask_text_with(text, &config, &mut table, &extra);

    Ok(RedactPreviewResult {
        masked: outcome.text,
        hits: outcome.hits.len(),
        placeholders: outcome.placeholders,
        errors,
        used_model: model.is_some(),
    })
}

/// 本地模型当前的下载/安装状态。
#[tauri::command]
pub fn redact_model_status() -> ModelStatus {
    model_store::status()
}

/// 开始下载模型与运行时；进度通过 `redact_model_status` 轮询。
#[tauri::command]
pub async fn download_redact_model() -> Result<(), String> {
    // 立刻返回，下载在后台进行；句柄在函数结束时丢弃，任务继续运行。
    #[allow(clippy::let_underscore_future)]
    let _download_task = tauri::async_runtime::spawn(async {
        if let Err(error) = model_store::download_all().await {
            log::error!("[redact] 模型下载失败: {error}");
        }
    });
    Ok(())
}

/// 删除已下载的模型文件。
#[tauri::command]
pub fn delete_redact_model() -> Result<(), String> {
    model_store::remove_model()
}
