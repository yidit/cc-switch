# 脱敏 Phase 4：一致性与异常处理

Phase 1–3 完成了规则引擎、代理接入和设置页。Phase 4 处理正式使用前必须解决的问题：
占位符在不同请求之间变化、fail-closed 没有真正生效、流式响应被切开时的边界情况，
以及设置页缺少规则编辑能力。

## 1. 让占位符在不同请求之间保持一致

**问题**：占位符后缀原本每次请求随机生成。上游的提示缓存按请求内容匹配，系统提示和
历史记录里的占位符一变，缓存就整段失效；`conversation_fingerprint` 也因此在每一轮
得到不同的值，opencode 上游的会话标识会不断变化。

**做法**：

- `RedactConfig.salt`：首次保存脱敏配置时，后端生成随机盐值（`uuid v4`），随后随设置
  一起保存；前端只原样保存，不展示。
- `PlaceholderTable::with_salt(salt)`：后缀取 `sha256(salt ‖ KIND ‖ 0x00 ‖ 原值 ‖ attempt)`
  的前 5 字节，再映射到 base32。同一台机器上，相同的原值在任何请求里都会得到相同结果。
- 后缀只有 40 bit，同一张表内出现重复时，把 `attempt` 加一重新计算（概率可以忽略）。
- 没有盐值的旧配置（或首次保存前就收到请求），退回每次请求随机的模式，行为与 Phase 1 相同。

**安全取舍**：占位符仍是不可逆的哈希，但同一台机器上相同的值会得到相同的占位符，
上游可以据此判断「两段文本里的值相同」。这是为了命中提示缓存付出的代价，设置页已经
说明可以随时关闭脱敏。

## 2. 会话指纹

`RequestContext` 在脱敏之前基于原文计算 `conversation_fingerprint`，forwarder 通过
`with_conversation_fingerprint` 使用这个值。即使占位符退回每次随机的模式，指纹也不会
随请求变化；`mapped_body` 只在缺少预计算值时作为后备。

## 3. fail-closed

- `redact::invalid_rules` 列出空正则和无法编译的自定义规则。
- `mask_request_body` 返回 `Result<Option<Arc<PlaceholderTable>>, String>`：
  - 总开关关闭 → `Ok(None)`；
  - 规则不可用且开启 `failClosed` → `Err`，handlers 直接返回 500，原文不会发往上游；
  - 规则不可用且关闭 `failClosed` → 记录告警，跳过无效规则，继续脱敏。
- 预览命令把无效规则列表返回给设置页，用户可以在保存前看到问题。

## 4. 流式响应被切开的情况

`restore_stream_chunk` 的缓冲规则补上了「chunk 恰好切在单个 `{` 之后」的情况：
`{{EMAIL_…}}` 在任何字节位置被拆开都能正确还原（测试覆盖每个切分位置）。
chunk 切在多字节字符中间时，只处理合法前缀、把不完整字符留在缓冲区，该 chunk 里
完整的占位符仍会还原。`flush_stream_restore` 遇到不是合法 UTF-8 的剩余内容时原样返回，
不再用 `from_utf8_lossy` 改写字节。

## 5. 性能

邮箱、电话、账户检测器在跑正则之前先做简单判断（是否含 `@`、是否含 ASCII 数字），
长上下文里大部分文本可以直接跳过。

## 6. 设置页

- 个人信息类型开关（EMAIL / PHONE / ACCOUNT），全部选中时写回空数组，与后端「空 = 全部」一致。
- 自定义规则编辑：正则、类型、动作（占位符 / 掩码 / 删除），支持新增和删除；
  输入框失焦时才保存，避免每敲一个字符就写一次设置。
- fail-closed 开关。
- 预览区展示无效规则的错误信息。

## 7. 验证

- `cargo test`：66 个单元测试（含盐值一致性、fail-closed、任意切分位置还原、
  非 UTF-8 剩余内容）、6 个语料结构校验、85 例评估语料全部通过。
- `cargo clippy --all-targets -- -D warnings` 与 `cargo fmt --check` 无告警。
- 前端 `tsc --noEmit` 通过；`src/lib/redactConfig.test.ts` 覆盖类型开关和规则增删。

## 仍待处理

- PERSON / ADDRESS 仍只靠自定义词和规则命中，还没有引入模型。
- 上游在回复里改写占位符（例如插入空格）时无法还原，按 scope 的约定保持原样。
- 设置页暂时不允许调整 `wordsAnyCase` / `wordsWhole`，默认值够用之前不开放。
