//! 本地模型文件的下载、校验与删除。
//!
//! 模型和 ONNX Runtime 都不随安装包分发：用户首次启用模型时才下载，
//! 每个文件按固定 SHA-256 校验后保存到 `~/.cc-switch/models/`。
//! 下载进度写进全局状态，设置页轮询显示。

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use futures::StreamExt;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::redact::model::model_dir;

/// 模型在 Hugging Face 上的固定提交，避免上游更新导致文件变化。
/// 文件地址直接按该提交固定，见下方 `MODEL_FILES`。
/// 模型文件清单（大小与 SHA-256 来自模型仓库的 `astrlink-model.json`）。
const MODEL_FILES: [FileSpec; 3] = [
    FileSpec {
        name: "model_int8.onnx",
        url: "https://huggingface.co/QuantumNous/astrlink-guard/resolve/7216b6a3b897ef903d4b1ba367ae6fb95b0fa5e4/int8/model_int8.onnx",
        sha256: "0a070d3113615e33ba3b84d6bd486f663a377c04c4b056e7381732179f51832a",
        size: 330_781,
    },
    FileSpec {
        name: "model_int8.onnx_data",
        url: "https://huggingface.co/QuantumNous/astrlink-guard/resolve/7216b6a3b897ef903d4b1ba367ae6fb95b0fa5e4/int8/model_int8.onnx_data",
        sha256: "0ba34216ceead01e0ae2dfd8e46d52b67e7aee80b04f722d9b758613a91c0067",
        size: 37_124_608,
    },
    FileSpec {
        name: "tokenizer.json",
        url: "https://huggingface.co/QuantumNous/astrlink-guard/resolve/7216b6a3b897ef903d4b1ba367ae6fb95b0fa5e4/int8/tokenizer.json",
        sha256: "0cf3b235ef125658015a6c8026a5fe6f28088bf825101a990ec18a10200feef4",
        size: 1_502_881,
    },
];

/// ONNX Runtime 的下载来源。
struct RuntimeSpec {
    url: &'static str,
    sha256: &'static str,
    /// 压缩包类型。
    archive: ArchiveKind,
    /// 压缩包内需要解压的文件。
    member: &'static str,
    /// 解压后的文件名。
    output: &'static str,
    size: u64,
}

/// 压缩包类型；具体变体随平台而定。
#[allow(dead_code)]
enum ArchiveKind {
    TarGz,
    Zip,
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
const RUNTIME: Option<RuntimeSpec> = Some(RuntimeSpec {
    // 官方 PyPI wheel，只取其中的 onnxruntime.dll，避免下载 GitHub 包里
    // 三百多 MB 的调试符号。
    url: "https://files.pythonhosted.org/packages/36/b4/3f1c71ce1d3d21078a6a74c5483bfa2b07e41a8d2b8fb1e9993e6a26d8d3/onnxruntime-1.22.0-cp312-cp312-win_amd64.whl",
    sha256: "c0d534a43d1264d1273c2d4f00a5a588fa98d21117a3345b7104fa0bbcaadb9a",
    archive: ArchiveKind::Zip,
    member: "onnxruntime/capi/onnxruntime.dll",
    output: "onnxruntime.dll",
    size: 12_692_233,
});

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const RUNTIME: Option<RuntimeSpec> = Some(RuntimeSpec {
    url: "https://github.com/microsoft/onnxruntime/releases/download/v1.22.0/onnxruntime-linux-x64-1.22.0.tgz",
    sha256: "8344d55f93d5bc5021ce342db50f62079daf39aaafb5d311a451846228be49b3",
    archive: ArchiveKind::TarGz,
    member: "onnxruntime-linux-x64-1.22.0/lib/libonnxruntime.so.1.22.0",
    output: "libonnxruntime.so",
    size: 7_798_730,
});

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const RUNTIME: Option<RuntimeSpec> = Some(RuntimeSpec {
    url: "https://github.com/microsoft/onnxruntime/releases/download/v1.22.0/onnxruntime-osx-arm64-1.22.0.tgz",
    sha256: "cab6dcbd77e7ec775390e7b73a8939d45fec3379b017c7cb74f5b204c1a1cc07",
    archive: ArchiveKind::TarGz,
    member: "onnxruntime-osx-arm64-1.22.0/lib/libonnxruntime.1.22.0.dylib",
    output: "libonnxruntime.dylib",
    size: 25_943_843,
});

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const RUNTIME: Option<RuntimeSpec> = Some(RuntimeSpec {
    url: "https://github.com/microsoft/onnxruntime/releases/download/v1.22.0/onnxruntime-osx-x86_64-1.22.0.tgz",
    sha256: "e4ec94a7696de74fb1b12846569aa94e499958af6ffa186022cfde16c9d617f0",
    archive: ArchiveKind::TarGz,
    member: "onnxruntime-osx-x86_64-1.22.0/lib/libonnxruntime.1.22.0.dylib",
    output: "libonnxruntime.dylib",
    size: 27_889_590,
});

#[cfg(not(any(
    all(target_os = "windows", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64"),
)))]
const RUNTIME: Option<RuntimeSpec> = None;

struct FileSpec {
    name: &'static str,
    url: &'static str,
    sha256: &'static str,
    size: u64,
}

/// 设置页展示的模型状态。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelStatus {
    /// `missing` / `downloading` / `ready` / `error`。
    pub state: String,
    /// 已下载字节数。
    pub downloaded_bytes: u64,
    /// 需要下载的总字节数。
    pub total_bytes: u64,
    /// 最近一次错误。
    pub error: Option<String>,
    /// 模型目录。
    pub directory: String,
    /// 当前平台的模型是否可下载。
    pub supported: bool,
}

#[derive(Default)]
struct DownloadState {
    running: bool,
    downloaded: u64,
    error: Option<String>,
}

fn state() -> &'static Mutex<DownloadState> {
    static STATE: OnceLock<Mutex<DownloadState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(DownloadState::default()))
}

/// 需要下载的总字节数（含运行时库）。
pub fn download_size() -> u64 {
    let runtime = RUNTIME.as_ref().map_or(0, |spec| spec.size);
    runtime + MODEL_FILES.iter().map(|spec| spec.size).sum::<u64>()
}

/// 当前是否所有文件都已就绪。
pub fn is_ready() -> bool {
    crate::redact::model::files_present(&model_dir())
}

pub fn status() -> ModelStatus {
    let dir = model_dir();
    let ready = is_ready();
    let (running, downloaded, error) = state()
        .lock()
        .map(|state| (state.running, state.downloaded, state.error.clone()))
        .unwrap_or((false, 0, None));

    let state_name = if ready {
        "ready"
    } else if running {
        "downloading"
    } else if error.is_some() {
        "error"
    } else {
        "missing"
    };

    ModelStatus {
        state: state_name.to_string(),
        downloaded_bytes: if ready { download_size() } else { downloaded },
        total_bytes: download_size(),
        error,
        directory: dir.display().to_string(),
        supported: RUNTIME.is_some(),
    }
}

/// 下载并解压所有文件；已经存在且大小正确的文件会跳过。
pub async fn download_all() -> Result<(), String> {
    let spec = RUNTIME
        .as_ref()
        .ok_or_else(|| "当前平台暂不支持本地模型".to_string())?;

    {
        let mut state = state().lock().map_err(|_| "下载状态不可用".to_string())?;
        if state.running {
            return Err("模型正在下载中".to_string());
        }
        state.running = true;
        state.downloaded = 0;
        state.error = None;
    }

    let result = download_inner(spec).await;

    if let Ok(mut state) = state().lock() {
        state.running = false;
        if let Err(error) = &result {
            state.error = Some(error.clone());
        }
    }
    result
}

async fn download_inner(spec: &RuntimeSpec) -> Result<(), String> {
    let dir = model_dir();
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|error| format!("创建模型目录失败：{error}"))?;

    // 已经存在的模型文件直接计入进度。
    for file in &MODEL_FILES {
        let path = dir.join(file.name);
        if file.size_matches(&path) {
            advance(file.size);
        }
    }

    // 运行时库
    let runtime_path = dir.join(spec.output);
    let runtime_marker = dir.join(".runtime.ok");
    if runtime_path.is_file() && runtime_marker.is_file() {
        advance(spec.size);
    } else {
        let archive = dir.join(".runtime.archive");
        download_file(spec.url, &archive, spec.size, spec.sha256).await?;
        let member = spec.member.to_string();
        let output = runtime_path.clone();
        let archive_for_task = archive.clone();
        let kind = match spec.archive {
            ArchiveKind::TarGz => "tgz",
            ArchiveKind::Zip => "zip",
        }
        .to_string();
        tokio::task::spawn_blocking(move || extract(&archive_for_task, &kind, &member, &output))
            .await
            .map_err(|error| format!("解压任务失败：{error}"))??;
        let _ = tokio::fs::remove_file(&archive).await;
        tokio::fs::write(&runtime_marker, spec.sha256)
            .await
            .map_err(|error| format!("写入标记失败：{error}"))?;
    }

    for file in &MODEL_FILES {
        let path = dir.join(file.name);
        if file.size_matches(&path) {
            continue;
        }
        download_file(file.url, &path, file.size, file.sha256).await?;
    }

    if !crate::redact::model::files_present(&dir) {
        return Err("下载完成后仍有文件缺失".to_string());
    }
    Ok(())
}

impl FileSpec {
    fn size_matches(&self, path: &Path) -> bool {
        std::fs::metadata(path)
            .map(|meta| meta.is_file() && meta.len() == self.size)
            .unwrap_or(false)
    }
}

fn advance(bytes: u64) {
    if let Ok(mut state) = state().lock() {
        state.downloaded = state.downloaded.saturating_add(bytes);
    }
}

async fn download_file(
    url: &str,
    dest: &Path,
    expected_size: u64,
    expected_sha: &str,
) -> Result<(), String> {
    let client = crate::proxy::http_client::get();
    let response = client
        .get(url)
        .timeout(Duration::from_secs(60))
        .send()
        .await
        .map_err(|error| format!("下载失败：{error}"))?;
    if !response.status().is_success() {
        return Err(format!("下载失败：HTTP {}", response.status()));
    }

    let temp = dest.with_extension("part");
    let mut file = tokio::fs::File::create(&temp)
        .await
        .map_err(|error| format!("写入临时文件失败：{error}"))?;
    let mut hasher = Sha256::new();
    let mut received: u64 = 0;
    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| format!("下载中断：{error}"))?;
        hasher.update(&chunk);
        received += chunk.len() as u64;
        tokio::io::AsyncWriteExt::write_all(&mut file, &chunk)
            .await
            .map_err(|error| format!("写入失败：{error}"))?;
        advance(chunk.len() as u64);
    }
    tokio::io::AsyncWriteExt::flush(&mut file)
        .await
        .map_err(|error| format!("写入失败：{error}"))?;
    drop(file);

    if received != expected_size {
        let _ = tokio::fs::remove_file(&temp).await;
        return Err(format!(
            "文件大小不符：期望 {expected_size}，实际 {received}"
        ));
    }
    let digest = hasher.finalize();
    let actual: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    if actual != expected_sha {
        let _ = tokio::fs::remove_file(&temp).await;
        return Err("文件校验失败，请重试".to_string());
    }

    // Windows 上 rename 不能覆盖已存在的目标文件，先删掉旧的残片。
    let _ = tokio::fs::remove_file(dest).await;
    tokio::fs::rename(&temp, dest)
        .await
        .map_err(|error| format!("保存文件失败：{error}"))?;
    Ok(())
}

/// 从压缩包中取出单个文件。
fn extract(archive: &Path, kind: &str, member: &str, output: &Path) -> Result<(), String> {
    match kind {
        "tgz" => extract_tgz(archive, member, output),
        "zip" => extract_zip(archive, member, output),
        _ => Err(format!("未知的压缩格式：{kind}")),
    }
}

fn extract_tgz(archive: &Path, member: &str, output: &Path) -> Result<(), String> {
    let file = File::open(archive).map_err(|error| format!("打开压缩包失败：{error}"))?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut tar = tar::Archive::new(decoder);

    let entries = tar
        .entries()
        .map_err(|error| format!("读取压缩包失败：{error}"))?;
    for entry in entries {
        let mut entry = entry.map_err(|error| format!("读取压缩包失败：{error}"))?;
        let path = entry
            .path()
            .map_err(|error| format!("解析压缩包路径失败：{error}"))?
            .to_string_lossy()
            .to_string();
        if !path.ends_with(member) {
            continue;
        }
        let mut out = File::create(output).map_err(|error| format!("创建文件失败：{error}"))?;
        std::io::copy(&mut entry, &mut out).map_err(|error| format!("解压失败：{error}"))?;
        return Ok(());
    }
    Err(format!("压缩包中缺少 {member}"))
}

fn extract_zip(archive: &Path, member: &str, output: &Path) -> Result<(), String> {
    let file = File::open(archive).map_err(|error| format!("打开压缩包失败：{error}"))?;
    let mut zip = zip::ZipArchive::new(file).map_err(|error| format!("读取压缩包失败：{error}"))?;
    let mut entry = zip
        .by_name(member)
        .map_err(|error| format!("压缩包中缺少 {member}：{error}"))?;

    let mut out = File::create(output).map_err(|error| format!("创建文件失败：{error}"))?;
    let mut buffer = Vec::with_capacity(entry.size() as usize);
    entry
        .read_to_end(&mut buffer)
        .map_err(|error| format!("解压失败：{error}"))?;
    out.write_all(&buffer)
        .map_err(|error| format!("写入文件失败：{error}"))?;
    Ok(())
}

/// 删除模型文件；已加载的实例会被丢弃。
pub fn remove_model() -> Result<(), String> {
    crate::redact::model::reset_engine();
    let dir = model_dir();
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|error| format!("删除模型失败：{error}"))?;
    }
    if let Ok(mut state) = state().lock() {
        state.downloaded = 0;
        state.error = None;
    }
    Ok(())
}
