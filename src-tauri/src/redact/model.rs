//! 本地 PII 模型（AstrLink Guard）。
//!
//! 模型是 QuantumNous/astrlink-guard 0.1.3 的 int8 ONNX 版本（Apache-2.0），
//! 用 ONNX Runtime 在 CPU 上运行，补充规则层识别不了的人名和地址。
//!
//! 设计要点：
//! - 模型文件按需下载，由 `model_store` 管理；这里只负责加载与推理。
//! - 每次请求有 token 预算，从最新内容往前算，避免长会话拖慢转发。
//! - 推理结果按文本缓存，重复出现的系统提示和历史不需要重算。

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use ndarray::Array2;
use ort::session::Session;
use ort::value::Tensor;
use sha2::{Digest, Sha256};
use tokenizers::Tokenizer;

use crate::redact::{Action, Hit, Kind, RedactConfig};

/// 模型版本，用于目录名和缓存键。
pub const MODEL_VERSION: &str = "0.1.3";

/// 模型文件所在目录名（位于 `~/.cc-switch/models/` 下）。
pub const MODEL_DIR_NAME: &str = "astrlink-guard-0.1.3";

/// 模型推理窗口（含起止特殊 token）。
const WINDOW_TOKENS: usize = 512;
/// 相邻窗口的重叠 token 数。
const WINDOW_OVERLAP: usize = 128;
/// 缓存保留的文本条数。
const CACHE_ENTRIES: usize = 128;

/// 模型输出的 21 个 BIO 标签，顺序与 labels.json 一致。
const LABELS: [&str; 21] = [
    "O",
    "B-email",
    "I-email",
    "B-phone",
    "I-phone",
    "B-account",
    "I-account",
    "B-payment_card",
    "I-payment_card",
    "B-ip_address",
    "I-ip_address",
    "B-url",
    "I-url",
    "B-common_secret",
    "I-common_secret",
    "B-private_address",
    "I-private_address",
    "B-private_date",
    "I-private_date",
    "B-private_person",
    "I-private_person",
];

/// 模型文件目录。
pub fn model_dir() -> PathBuf {
    crate::config::get_app_config_dir()
        .join("models")
        .join(MODEL_DIR_NAME)
}

/// 当前平台需要的 ONNX Runtime 动态库文件名。
pub fn runtime_library_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "onnxruntime.dll"
    } else if cfg!(target_os = "macos") {
        "libonnxruntime.dylib"
    } else {
        "libonnxruntime.so"
    }
}

/// 模型文件是否都已下载。
pub fn files_present(dir: &Path) -> bool {
    dir.join("model_int8.onnx").is_file()
        && dir.join("model_int8.onnx_data").is_file()
        && dir.join("tokenizer.json").is_file()
        && dir.join(runtime_library_name()).is_file()
        // 运行时库解压完成后会写入标记，避免把解压中断的残缺文件当成可用。
        && dir.join(".runtime.ok").is_file()
}

/// 全局只加载一次的模型。
static ENGINE: OnceLock<Mutex<Option<Arc<ModelEngine>>>> = OnceLock::new();

/// 取得已加载的模型；没有加载时返回 `None`（不会触发加载）。
pub fn cached_engine() -> Option<Arc<ModelEngine>> {
    ENGINE
        .get_or_init(|| Mutex::new(None))
        .lock()
        .ok()
        .and_then(|slot| slot.clone())
}

/// 加载模型；失败时返回可展示给用户的错误。
pub fn load_engine() -> Result<Arc<ModelEngine>, String> {
    let slot = ENGINE.get_or_init(|| Mutex::new(None));
    if let Some(engine) = slot.lock().ok().and_then(|slot| slot.clone()) {
        return Ok(engine);
    }

    let dir = model_dir();
    let engine = Arc::new(ModelEngine::load(&dir)?);
    if let Ok(mut slot) = slot.lock() {
        *slot = Some(engine.clone());
    }
    Ok(engine)
}

/// 删除模型后清空已加载的实例。
pub fn reset_engine() {
    if let Some(slot) = ENGINE.get() {
        if let Ok(mut slot) = slot.lock() {
            *slot = None;
        }
    }
}

/// 本地模型推理器。
pub struct ModelEngine {
    session: Mutex<Session>,
    tokenizer: Tokenizer,
    cache: Mutex<HitCache>,
}

impl ModelEngine {
    fn load(dir: &Path) -> Result<Self, String> {
        if !files_present(dir) {
            return Err(format!("模型文件不完整，请先下载（{}）", dir.display()));
        }

        // ort 的动态加载模式在首次创建会话时读取该变量。
        let library = dir.join(runtime_library_name());
        std::env::set_var("ORT_DYLIB_PATH", &library);

        let tokenizer = Tokenizer::from_file(dir.join("tokenizer.json"))
            .map_err(|error| format!("读取 tokenizer 失败：{error}"))?;
        let session = Session::builder()
            .map_err(|error| format!("初始化 ONNX Runtime 失败：{error}"))?
            .commit_from_file(dir.join("model_int8.onnx"))
            .map_err(|error| format!("加载模型失败：{error}"))?;

        Ok(Self {
            session: Mutex::new(session),
            tokenizer,
            cache: Mutex::new(HitCache::new(CACHE_ENTRIES)),
        })
    }

    /// 在文本中找出模型认为需要脱敏的区间。
    ///
    /// `budget` 是本请求剩余的 token 预算，从文本末尾（最新内容）开始消耗。
    pub fn detect(&self, text: &str, config: &RedactConfig, budget: &mut usize) -> Vec<Hit> {
        if *budget == 0 || text.trim().is_empty() {
            return Vec::new();
        }

        let threshold = config.model.threshold.clamp(0.05, 0.99);
        let key = cache_key(text, threshold);
        if let Some(hits) = self.cache.lock().ok().and_then(|cache| cache.get(&key)) {
            return filter_by_config(&hits, config);
        }

        // 缓存未过滤的原始命中：类型开关随时可能变化，过滤放在读取时做，
        // 否则先只开 EMAIL 跑过的文本会一直缺人名/地址的命中。
        let hits = self.infer(text, threshold, budget).collect::<Vec<_>>();

        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(key, hits.clone());
        }
        filter_by_config(&hits, config)
    }

    fn infer(&self, text: &str, threshold: f32, budget: &mut usize) -> impl Iterator<Item = Hit> {
        let mut hits: Vec<Hit> = Vec::new();

        let Ok(encoding) = self.tokenizer.encode(text, false) else {
            log::warn!("[redact] 模型分词失败，跳过该段文本");
            return hits.into_iter();
        };
        let ids = encoding.get_ids();
        let offsets = encoding.get_offsets();
        if ids.is_empty() || ids.len() != offsets.len() {
            return hits.into_iter();
        }

        let Some(cls_id) = self.tokenizer.token_to_id("<s>") else {
            log::warn!("[redact] tokenizer 缺少 <s>，跳过模型推理");
            return hits.into_iter();
        };
        let sep_id = self.tokenizer.token_to_id("</s>").unwrap_or(cls_id);

        for (start, end) in window_plan(ids.len()).into_iter() {
            if *budget < 2 {
                break;
            }
            let content = &ids[start..end];
            let mut window: Vec<i64> = Vec::with_capacity(content.len() + 2);
            window.push(i64::from(cls_id));
            window.extend(content.iter().map(|&id| i64::from(id)));
            window.push(i64::from(sep_id));

            let processed = window.len();
            let Some(scores) = self.run_window(&window) else {
                break;
            };
            decode_window(&scores, start, end, offsets, threshold, &mut hits);

            *budget = budget.saturating_sub(processed);
        }

        merge_hits(hits).into_iter()
    }

    /// 跑一个窗口，返回每个 token 的最高置信度与标签下标。
    fn run_window(&self, ids: &[i64]) -> Option<Vec<(usize, f32)>> {
        let len = ids.len();
        let input_ids = Array2::from_shape_vec((1, len), ids.to_vec()).expect("窗口长度与输入一致");
        let attention =
            Array2::from_shape_vec((1, len), vec![1i64; len]).expect("窗口长度与输入一致");
        let token_types =
            Array2::from_shape_vec((1, len), vec![0i64; len]).expect("窗口长度与输入一致");

        let mut session = self.session.lock().ok()?;
        let outputs = session
            .run(ort::inputs![
                "input_ids" => Tensor::from_array(input_ids).ok()?,
                "attention_mask" => Tensor::from_array(attention).ok()?,
                "token_type_ids" => Tensor::from_array(token_types).ok()?,
            ])
            .ok()?;
        let (shape, data) = outputs[0].try_extract_tensor::<f32>().ok()?;

        let tokens = *shape.get(1)? as usize;
        let classes = *shape.get(2)? as usize;
        if tokens != len || classes != LABELS.len() {
            log::warn!("[redact] 模型输出形状异常：{shape:?}");
            return None;
        }

        let mut result = Vec::with_capacity(tokens);
        for row in 0..tokens {
            let logits = &data[row * classes..(row + 1) * classes];
            let mut best = 0usize;
            let mut best_logit = f32::MIN;
            for (index, &logit) in logits.iter().enumerate() {
                if logit > best_logit {
                    best_logit = logit;
                    best = index;
                }
            }
            let sum: f32 = logits.iter().map(|&logit| (logit - best_logit).exp()).sum();
            result.push((best, 1.0 / sum));
        }
        Some(result)
    }
}

/// 计算窗口切分，窗口从文本末尾往前排（优先处理最新内容）。
fn window_plan(tokens: usize) -> Vec<(usize, usize)> {
    let content = WINDOW_TOKENS - 2;
    if tokens <= content {
        return vec![(0, tokens)];
    }

    let mut plan = Vec::new();
    let mut end = tokens;
    loop {
        let start = end.saturating_sub(content);
        plan.push((start, end));
        if start == 0 {
            break;
        }
        end = start + WINDOW_OVERLAP;
    }
    plan
}

/// 把窗口输出转换成文本区间。
fn decode_window(
    scores: &[(usize, f32)],
    start: usize,
    end: usize,
    offsets: &[(usize, usize)],
    threshold: f32,
    hits: &mut Vec<Hit>,
) {
    // 第 0 行是 <s>，最后一行是 </s>，对应不到原文。
    let mut current: Option<(usize, usize, Kind, f32)> = None;

    for (row, &(label_id, score)) in scores.iter().enumerate() {
        if row == 0 || row > end - start {
            continue;
        }
        let token = start + row - 1;
        let (begin, finish) = offsets[token];
        if begin == finish {
            continue;
        }

        let label = LABELS.get(label_id).copied().unwrap_or("O");
        let parsed = parse_label(label);
        let kind = parsed.as_ref().map(|(kind, _)| *kind);

        match (kind, parsed.as_ref().map(|(_, tag)| *tag)) {
            // 不需要处理（O、IP、URL、日期）或跨类型：结束当前区间。
            (None, _) => close_span(&mut current, threshold, hits),
            (Some(kind), Some(tag)) => {
                let same_kind = current.is_some_and(|span| span.2 == kind);
                if tag == 'B' || !same_kind {
                    close_span(&mut current, threshold, hits);
                    current = Some((begin, finish, kind, score));
                } else if let Some(span) = current.as_mut() {
                    span.1 = finish;
                    span.3 = span.3.min(score);
                }
            }
            _ => {}
        }
    }
    close_span(&mut current, threshold, hits);
}

fn close_span(
    current: &mut Option<(usize, usize, Kind, f32)>,
    threshold: f32,
    hits: &mut Vec<Hit>,
) {
    if let Some((start, end, kind, score)) = current.take() {
        if score >= threshold && start < end {
            hits.push(Hit {
                start,
                end,
                kind,
                action: Action::Placeholder,
            });
        }
    }
}

/// 解析 `B-email` / `I-private_person` 这类标签。
fn parse_label(label: &str) -> Option<(Kind, char)> {
    let (tag, name) = label.split_once('-')?;
    let mut tag_chars = tag.chars();
    let tag = tag_chars.next()?;
    if tag_chars.next().is_some() {
        return None;
    }
    let kind = match name {
        "email" => Kind::Email,
        "phone" => Kind::Phone,
        "account" | "payment_card" => Kind::Account,
        "common_secret" => Kind::Secret,
        "private_person" => Kind::Person,
        "private_address" => Kind::Address,
        // ip_address / url / private_date 不属于本轮脱敏范围。
        _ => return None,
    };
    Some((kind, tag))
}

/// 合并窗口之间重复或重叠的区间。
fn merge_hits(mut hits: Vec<Hit>) -> Vec<Hit> {
    hits.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then(b.end.cmp(&a.end))
            .then(a.kind.as_str().cmp(b.kind.as_str()))
    });

    let mut merged: Vec<Hit> = Vec::with_capacity(hits.len());
    for hit in hits {
        match merged.last_mut() {
            Some(last) if hit.start == last.start && hit.end == last.end => {}
            Some(last) if hit.start < last.end && hit.kind == last.kind => {
                last.end = last.end.max(hit.end);
            }
            Some(last) if hit.start < last.end => {
                // 不同类型且重叠：保留更长的区间。
                if hit.end > last.end {
                    *last = hit;
                }
            }
            _ => merged.push(hit),
        }
    }
    merged
}

fn kind_enabled(config: &RedactConfig, kind: Kind) -> bool {
    if kind == Kind::Secret {
        return config.secrets;
    }
    config.personal && (config.kinds.is_empty() || config.kinds.contains(&kind))
}

fn filter_by_config(hits: &[Hit], config: &RedactConfig) -> Vec<Hit> {
    hits.iter()
        .copied()
        .filter(|hit| kind_enabled(config, hit.kind))
        .collect()
}

fn cache_key(text: &str, threshold: f32) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MODEL_VERSION.as_bytes());
    hasher.update([0u8]);
    hasher.update(threshold.to_bits().to_le_bytes());
    hasher.update(text.as_bytes());
    hasher.finalize().into()
}

/// 简单的条目数上限缓存，避免长会话重复推理。
struct HitCache {
    entries: HashMap<[u8; 32], Vec<Hit>>,
    order: VecDeque<[u8; 32]>,
    capacity: usize,
}

impl HitCache {
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    fn get(&self, key: &[u8; 32]) -> Option<Vec<Hit>> {
        self.entries.get(key).cloned()
    }

    fn insert(&mut self, key: [u8; 32], hits: Vec<Hit>) {
        if let std::collections::hash_map::Entry::Occupied(mut entry) = self.entries.entry(key) {
            entry.insert(hits);
            return;
        }
        if self.order.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        self.order.push_back(key);
        self.entries.insert(key, hits);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_plan_covers_the_whole_text() {
        for tokens in [1usize, 100, 510, 511, 512, 513, 1000, 1603] {
            let plan = window_plan(tokens);
            assert!(!plan.is_empty(), "tokens={tokens}");
            let mut covered = vec![false; tokens];
            for (start, end) in &plan {
                assert!(start < end && *end <= tokens, "tokens={tokens} 窗口越界");
                assert!(end - start <= WINDOW_TOKENS - 2, "tokens={tokens} 窗口过大");
                for item in covered.iter_mut().take(*end).skip(*start) {
                    *item = true;
                }
            }
            assert!(
                covered.iter().all(|&value| value),
                "tokens={tokens} 存在遗漏"
            );
        }
    }

    #[test]
    fn window_plan_starts_from_the_end() {
        let plan = window_plan(1603);
        assert_eq!(plan.first(), Some(&(1093, 1603)));
        assert_eq!(plan.last(), Some(&(0, 457)));
    }

    #[test]
    fn labels_map_to_the_expected_kinds() {
        assert_eq!(parse_label("B-email"), Some((Kind::Email, 'B')));
        assert_eq!(parse_label("I-private_person"), Some((Kind::Person, 'I')));
        assert_eq!(parse_label("B-payment_card"), Some((Kind::Account, 'B')));
        assert_eq!(parse_label("I-account"), Some((Kind::Account, 'I')));
        assert_eq!(parse_label("B-url"), None);
        assert_eq!(parse_label("B-private_date"), None);
        assert_eq!(parse_label("O"), None);
    }

    #[test]
    fn engine_can_be_shared_across_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ModelEngine>();
    }

    #[test]
    fn overlapping_spans_of_the_same_kind_merge() {
        let hit = |start, end, kind| Hit {
            start,
            end,
            kind,
            action: Action::Placeholder,
        };
        let merged = merge_hits(vec![
            hit(0, 10, Kind::Person),
            hit(8, 14, Kind::Person),
            hit(30, 34, Kind::Email),
        ]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].end, 14);
        assert_eq!(merged[1].kind, Kind::Email);
    }
}
