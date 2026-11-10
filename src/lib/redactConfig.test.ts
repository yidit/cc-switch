import { describe, expect, it } from "vitest";
import type { RedactConfig, RedactRule } from "@/types";
import {
  PERSONAL_KINDS,
  createRule,
  isKindEnabled,
  nextRuleName,
  removeRule,
  splitList,
  upsertRule,
  withKindEnabled,
} from "./redactConfig";

function makeConfig(overrides: Partial<RedactConfig> = {}): RedactConfig {
  return {
    enabled: true,
    secrets: true,
    personal: true,
    kinds: [],
    words: [],
    wordsAnyCase: false,
    wordsWhole: true,
    rules: [],
    allow: [],
    failClosed: true,
    model: {
      enabled: false,
      threshold: 0.8,
      maxTokensPerRequest: 4096,
    },
    ...overrides,
  };
}

function makeRule(overrides: Partial<RedactRule> = {}): RedactRule {
  return {
    name: "rule-1",
    pattern: "TICKET-[0-9]{6}",
    kind: "SECRET",
    action: "placeholder",
    ...overrides,
  };
}

describe("个人信息类型开关", () => {
  it("空数组表示全部类型都开启", () => {
    const config = makeConfig();
    for (const kind of PERSONAL_KINDS) {
      expect(isKindEnabled(config, kind)).toBe(true);
    }
  });

  it("关闭一个类型后只保留其余类型", () => {
    const config = withKindEnabled(makeConfig(), "PHONE", false);
    expect(config.kinds).toEqual(["EMAIL", "ACCOUNT"]);
    expect(isKindEnabled(config, "PHONE")).toBe(false);
    expect(isKindEnabled(config, "EMAIL")).toBe(true);
  });

  it("重新打开全部类型时写回空数组", () => {
    const disabled = withKindEnabled(makeConfig(), "PHONE", false);
    const enabled = withKindEnabled(disabled, "PHONE", true);
    expect(enabled.kinds).toEqual([]);
  });

  it("关闭最后一个类型时同时关闭个人信息开关", () => {
    const withoutPhone = withKindEnabled(makeConfig(), "PHONE", false);
    const onlyEmail = withKindEnabled(withoutPhone, "ACCOUNT", false);
    const none = withKindEnabled(onlyEmail, "EMAIL", false);

    expect(none.personal).toBe(false);
    expect(none.kinds).toEqual([]);
    expect(isKindEnabled(none, "EMAIL")).toBe(false);
  });

  it("重新打开类型会同时打开个人信息开关", () => {
    const off = { ...makeConfig(), personal: false };
    const on = withKindEnabled(off, "PHONE", true);

    expect(on.personal).toBe(true);
    expect(on.kinds).toEqual(["PHONE"]);
  });

  it("不修改传入的配置", () => {
    const config = makeConfig();
    withKindEnabled(config, "EMAIL", false);
    expect(config.kinds).toEqual([]);
  });

  it("过滤掉与个人信息无关的类型", () => {
    const config = withKindEnabled(
      makeConfig({ kinds: ["SECRET", "EMAIL"] }),
      "PHONE",
      true,
    );
    expect(config.kinds).toEqual(["EMAIL", "PHONE"]);
  });
});

describe("自定义规则", () => {
  it("新建规则使用占位符动作并避免重名", () => {
    const config = makeConfig({ rules: [makeRule({ name: "rule-2" })] });
    const rule = createRule(config);
    expect(rule.action).toBe("placeholder");
    expect(rule.kind).toBe("SECRET");
    expect(config.rules.some((item) => item.name === rule.name)).toBe(false);
  });

  it("按名称新增或替换规则", () => {
    const added = upsertRule(makeConfig(), makeRule());
    expect(added.rules).toHaveLength(1);

    const replaced = upsertRule(added, makeRule({ pattern: "ABC" }));
    expect(replaced.rules).toHaveLength(1);
    expect(replaced.rules[0].pattern).toBe("ABC");
  });

  it("删除规则只影响目标条目", () => {
    const config = makeConfig({
      rules: [makeRule({ name: "a" }), makeRule({ name: "b" })],
    });
    const next = removeRule(config, "a");
    expect(next.rules.map((rule) => rule.name)).toEqual(["b"]);
    expect(config.rules).toHaveLength(2);
  });

  it("nextRuleName 跳过已占用的名字", () => {
    const config = makeConfig({
      rules: [makeRule({ name: "rule-1" }), makeRule({ name: "rule-3" })],
    });
    expect(nextRuleName(config)).toBe("rule-4");
  });
});

describe("splitList", () => {
  it("支持换行、半角与全角逗号并裁剪空白", () => {
    expect(splitList("a, b\nc，d\n\n")).toEqual(["a", "b", "c", "d"]);
  });

  it("空输入返回空数组", () => {
    expect(splitList("   ")).toEqual([]);
  });
});
