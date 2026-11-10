# 脱敏（Redact）移植范围

本文定义从 [magpie](https://github.com/yetone/magpie)（MIT）移植隐私脱敏功能到 CC Switch 的第一阶段范围。设计与取舍参考了 magpie 的 `internal/redact`、`internal/masking` 与 `internal/gwmw`，但**不移植 Go 代码**，按相同分层在 Rust 侧重新实现。

## 目标

- 对经过 CC Switch 本地代理的请求，在发送上游前把敏感值替换为占位符。
- 上游返回的回复（含流式 SSE）到达客户端前，把占位符还原为原值。
- 敏感类型、自定义词/规则、白名单与替换动作可在设置中配置。
- 默认关闭；开启后失败时不把未脱敏的请求发出去（fail-closed）。

## 非目标（第一阶段）

- **直连 provider 的流量**：不经过 CC Switch 代理的请求无法脱敏，需在 UI 中明确说明。
- **本地 PII 模型**：第一阶段不引入；Phase 5 已作为可选功能加入 AstrLink Guard（见 `phase5.md`），默认关闭。
- **自由文本中的人名、地址**：规则层无法可靠识别；启用本地模型后由模型补足，未启用时仍只靠自定义词/词典。
- **magpie 的 gateway 插件体系**、GUI 插件与账号路由：不移植。
- **图片/视频 prompt 的深度改写**：先跳过，后续单独评估。

## MVP 覆盖类型

| 类型 | 说明 | 第一阶段 | 现状 |
|---|---|---|---|
| `SECRET` | API key、私钥、Bearer/JWT、连接串密码、环境变量中的密钥 | ✅ | ✅ |
| `EMAIL` | 邮箱地址（含 `Name <addr>` 形式） | ✅ | ✅ |
| `PHONE` | 手机号、带国际区号的电话号码 | ✅ | ✅ |
| `ACCOUNT` | 银行卡、IBAN、身份证号 | ✅ | ✅ |
| `PERSON` | 自定义屏蔽词、词典命中的人名 | ⚠️ 仅词典/自定义词 | ✅ 规则 + 可选模型 |
| `ADDRESS` | 地址 | ❌ 第一阶段不做 | ✅ 可选模型 |

类型名与 magpie 的 `Kind` 保持一致，便于直接复用其评估语料（见 `eval-baseline.md`）。

## 占位符格式

沿用 magpie 的格式：

```
{{<KIND>_<8 位 base32>}}
```

- `KIND` 为大写类型名，例如 `{{EMAIL_a1b2c3d4}}`。
- 后缀为 8 位 base32 字符（`a-z2-7`），取 `sha256(本机盐值 ‖ KIND ‖ 原值)` 的前 40 bit
  计算得到，不含原值信息。
- 同一请求内相同的原值复用同一个占位符；同一台机器上，相同的原值在不同请求里也会得到
  同一个占位符，避免上游的提示缓存和会话指纹每轮失效（见 `phase4.md`）。
- 盐值在首次保存脱敏配置时由后端生成，随设置一起保存；旧配置没有盐值时，每次请求重新随机。
- 占位符由规则生成，不依赖模型，也不会被上游翻译或改写；还原时按精确匹配处理。
- 选择该格式的直接收益：magpie 的评估判定正则 `\{\{[A-Z_]+_[a-z2-7]{8}\}\}` 可直接复用。

## 配置 schema（草案）

```json
{
  "redact": {
    "enabled": false,
    "secrets": true,
    "personal": true,
    "kinds": ["EMAIL", "PHONE", "ACCOUNT"],
    "words": [],
    "wordsAnyCase": false,
    "wordsWhole": true,
    "rules": [
      {
        "name": "internal-ticket",
        "pattern": "TICKET-[0-9]{6}",
        "kind": "SECRET",
        "action": "placeholder"
      }
    ],
    "allow": [],
    "actions": {
      "default": "placeholder",
      "byKind": {}
    },
    "failClosed": true
  }
}
```

字段说明：

- `enabled`：总开关，默认 `false`。
- `secrets` / `personal`：magpie 的两个大类开关；`kinds` 用于进一步限定 `personal` 的类型。
- `words`：自定义屏蔽词；`wordsAnyCase` 忽略大小写；`wordsWhole` 仅整词匹配。
- `rules`：用户自定义正则；`action` 可为 `placeholder`、`mask`（固定字符）、`drop`。
- `allow`：白名单，命中的值永不脱敏。
- `failClosed`：脱敏失败时拒绝请求（默认 `true`）。

该 schema 在 Phase 1 写入 `AppSettings`，并通过 WebDAV/S3 同步保存。

## 数据流与插入点

```
客户端请求
  → content_encoding 解码（已有）
  → redact::mask_json          ← 新增：只处理文本字段，记录映射
  → 现有 body_filter / provider adapter
  → 上游

上游响应
  ├─ 普通 JSON → redact::restore
  └─ SSE       → SseBuffer 逐事件 → redact::restore
  → 客户端
```

- 请求体在**最终发送前**脱敏，避免 provider adapter 之间重复处理。
- 响应还原复用 `src-tauri/src/proxy/sse` 的缓冲能力，处理跨 chunk 的占位符。
- `conversation_fingerprint` 与缓存键使用**原文**计算，避免脱敏影响命中率。
- 多次 provider 重试复用同一份掩码映射。

## 失败策略

- 开启脱敏但引擎异常：拒绝请求（fail-closed），返回明确错误，不把原文发往上游。
- 启用本地模型但模型文件缺失或加载失败：`failClosed` 开启时同样拒绝请求；关闭时退回规则层并记录告警。
- 响应还原失败：记录日志并尽量返回已还原部分；不因还原失败中断响应。
- 上游返回的文本里出现未知占位符（例如模型自行编造）：保持原样，不做猜测。

## 与上游语料的关系

`src-tauri/tests/fixtures/redact/eval-cases.json` 来自 magpie 的评估语料（MIT，见同目录 `LICENSE.magpie`），共 85 个用例。它作为 Phase 1 引擎的验收基线：

- 规则层应覆盖其中 25 个 `mask` 值（SECRET/EMAIL/PHONE/ACCOUNT）；
- 其余 22 个 `mask` 值属于 PERSON/ADDRESS，规则层不承诺覆盖，Phase 5 若引入模型再纳入；
- 全部 144 个 `keep` 值都必须保持原样，这是防误报的硬约束。
