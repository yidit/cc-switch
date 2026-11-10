# 脱敏 Phase 4：稳定性与硬化

Phase 1–3 完成了规则引擎、代理接入与设置页。Phase 4 处理上线前必须解决的问题：
占位符跨请求漂移、fail-closed 未生效、流式切分边界，以及设置页缺少的规则编辑能力。

## 1. 占位符跨请求稳定

**问题**：占位符后缀原本每次请求随机生成。上游提示缓存以请求字节为键，系统提示和历史里的
占位符一变，缓存就整段失效；`conversation_fingerprint` 也因此在每一轮得到不同的值，
opencode 上游的会话标识会不断漂移。

**方案**：

- `RedactConfig.salt`：首次保存脱敏配置时由后端生成随机盐（`uuid v4`），随设置落盘；
  前端只原样回传，不展示。
- `PlaceholderTable::with_salt(salt)`：后缀取 `sha256(salt ‖ KIND ‖ 0x00 ‖ 原值 ‖ attempt)`
  的前 5 字节，映射到 base32。同一设备、同一原值在不同请求里结果固定。
- 掩码空间为 40 bit，同表内撞车时把 `attempt` 递增后重算（概率可忽略）。
- 没有盐的旧配置（或前端在首次保存前就收到请求）退回随机模式，行为与 Phase 1 一致。

**安全取舍**：占位符仍是不可逆的哈希，但同一设备上相同的值会得到相同的占位符，上游可以
据此判断「两段文本里的值相同」。这是换取提示缓存命中的代价，已在设置页说明可关闭脱敏。

## 2. 会话指纹

`RequestContext::new` 在脱敏之前基于原文计算 `conversation_fingerprint`，forwarder 通过
`with_conversation_fingerprint` 使用该值。即使占位符退化为随机模式，指纹也不会随请求变化；
`mapped_body` 仅在缺少预计算值时作为回退。

## 3. fail-closed

- `redact::invalid_rules` 列出空正则与无法编译的自定义规则。
- `mask_request_body` 返回 `Result<Option<Arc<PlaceholderTable>>, String>`：
  - 总开关关闭 → `Ok(None)`；
  - 规则不可用且 `failClosed` → `Err`，handlers 直接返回 500，原文不会发往上游；
  - 规则不可用且 `failClosed=false` → 记录告警，跳过无效规则继续脱敏。
- 预览命令把无效规则列表回传给设置页，用户能在保存前看到问题。

## 4. 流式边界

`restore_stream_chunk` 的缓存规则补上了「chunk 恰好切在单个 `{` 之后」的情况：
`{{EMAIL_…}}` 在任意字节位置被拆开都能正确还原（测试覆盖全部 16 个切分点）。
`flush_stream_restore` 遇到非 UTF-8 余留内容时原样返回，不再用 `from_utf8_lossy` 改写字节。

## 5. 性能

邮箱、电话、账户检测器在跑正则前先做廉价判断（是否含 `@`、是否含 ASCII 数字），
长上下文中大多数文本块可以直接跳过。

## 6. 设置页

- 个人信息类型开关（EMAIL / PHONE / ACCOUNT），全选时写回空数组，与后端「空 = 全部」一致。
- 自定义规则编辑：正则、类型、动作（占位符 / 掩码 / 删除），支持新增与删除；
  输入框失焦才保存，避免逐字符写设置。
- fail-closed 开关。
- 预览区展示无效规则错误。

## 7. 验证

- `cargo test`：66 个单元测试（含盐稳定、fail-closed、全切分点还原、非 UTF-8 余留）、
  6 个语料结构校验、85 例评估语料全部通过。
- `cargo clippy --all-targets -- -D warnings` 与 `cargo fmt --check` 无告警。
- 前端 `tsc --noEmit` 通过；`src/lib/redactConfig.test.ts` 覆盖类型开关与规则增删。

## 仍待处理

- PERSON / ADDRESS 仍只靠自定义词/规则命中，模型层未引入。
- 上游在回复里改写占位符（例如插入空格）时无法还原，按 scope 约定保持原样。
- 设置页暂不允许调整 `wordsAnyCase` / `wordsWhole`，默认值够用前不暴露。
