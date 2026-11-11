import type { RedactConfig, RedactKind, RedactRule } from "@/types";

/**
 * 请求脱敏配置的纯函数工具。
 *
 * 这些逻辑放在组件外，便于单测；`kinds` 为空数组表示「个人信息全部类型」，
 * 后端语义与这里保持一致。
 */

/** 受 `kinds` 控制的个人信息类型。 */
export const PERSONAL_KINDS = [
  "EMAIL",
  "PHONE",
  "ACCOUNT",
  "PERSON",
  "ADDRESS",
] as const;

export type PersonalKind = (typeof PERSONAL_KINDS)[number];

export const REDACT_KINDS: RedactKind[] = [
  "SECRET",
  "PERSON",
  "PHONE",
  "EMAIL",
  "ACCOUNT",
  "ADDRESS",
];

export const REDACT_ACTIONS = ["placeholder", "mask", "drop"] as const;

function isPersonalKind(kind: RedactKind): kind is PersonalKind {
  return (PERSONAL_KINDS as readonly string[]).includes(kind);
}

/** 某个个人信息类型当前是否生效。 */
export function isKindEnabled(
  config: RedactConfig,
  kind: PersonalKind,
): boolean {
  if (!config.personal) return false;
  return config.kinds.length === 0 || config.kinds.includes(kind);
}

/**
 * 切换某个个人信息类型。
 *
 * 后端用「空数组 = 全部类型」，因此全部关闭时不能只写空数组，
 * 需要同时把 `personal` 关掉；重新打开任意类型时再打开 `personal`。
 */
export function withKindEnabled(
  config: RedactConfig,
  kind: PersonalKind,
  enabled: boolean,
): RedactConfig {
  const selected = new Set<PersonalKind>(
    config.personal
      ? config.kinds.length === 0
        ? [...PERSONAL_KINDS]
        : config.kinds.filter(isPersonalKind)
      : [],
  );

  if (enabled) {
    selected.add(kind);
  } else {
    selected.delete(kind);
  }

  if (!enabled && selected.size === 0) {
    return { ...config, personal: false, kinds: [] };
  }

  const kinds = PERSONAL_KINDS.filter((item) => selected.has(item));
  return {
    ...config,
    personal: true,
    kinds: kinds.length === PERSONAL_KINDS.length ? [] : [...kinds],
  };
}

/** 生成一个不与现有规则重名的规则名。 */
export function nextRuleName(config: RedactConfig): string {
  const used = new Set(config.rules.map((rule) => rule.name));
  let index = config.rules.length + 1;
  while (used.has(`rule-${index}`)) {
    index += 1;
  }
  return `rule-${index}`;
}

/** 新建一条空白规则。 */
export function createRule(config: RedactConfig): RedactRule {
  return {
    name: nextRuleName(config),
    pattern: "",
    kind: "SECRET",
    action: "placeholder",
  };
}

/** 按名称新增或替换规则。 */
export function upsertRule(
  config: RedactConfig,
  rule: RedactRule,
): RedactConfig {
  const exists = config.rules.some((item) => item.name === rule.name);
  return {
    ...config,
    rules: exists
      ? config.rules.map((item) => (item.name === rule.name ? rule : item))
      : [...config.rules, rule],
  };
}

/** 按名称删除规则。 */
export function removeRule(config: RedactConfig, name: string): RedactConfig {
  return {
    ...config,
    rules: config.rules.filter((rule) => rule.name !== name),
  };
}

/** 把多行文本切成列表，支持中英文逗号与换行。 */
export function splitList(value: string): string[] {
  return value
    .split(/[\n,，]/)
    .map((item) => item.trim())
    .filter(Boolean);
}
