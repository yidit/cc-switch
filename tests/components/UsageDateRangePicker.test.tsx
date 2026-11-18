import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { UsageDateRangePicker } from "@/components/usage/UsageDateRangePicker";

const firstDateQuery = vi.hoisted(() => ({
  current: {
    isSuccess: true,
    isError: false,
    data: "2025-06-01" as string | null | undefined,
  },
}));

vi.mock("@/lib/query/usage", () => ({
  useUsageFirstDate: () => firstDateQuery.current,
}));

function toTs(d: Date): number {
  return Math.floor(d.getTime() / 1000);
}

function formatDay(d: Date): string {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(
    d.getDate(),
  ).padStart(2, "0")}`;
}

function openPicker(onApply = vi.fn()) {
  render(
    <UsageDateRangePicker
      selection={{ preset: "7d" }}
      onApply={onApply}
      triggerLabel="7d"
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: /7d/ }));
  return onApply;
}

describe("UsageDateRangePicker bounds", () => {
  beforeEach(() => {
    firstDateQuery.current = {
      isSuccess: true,
      isError: false,
      data: "2025-06-01",
    };
  });

  it("does not apply a custom range before the first usage date is known", () => {
    firstDateQuery.current = {
      isSuccess: false,
      isError: false,
      data: undefined,
    };
    const onApply = openPicker();
    const confirm = screen.getByRole("button", { name: "common.confirm" });
    expect(confirm).toBeDisabled();
    fireEvent.click(confirm);
    expect(onApply).not.toHaveBeenCalled();
  });

  it("still applies a custom range when the first usage date query fails", () => {
    firstDateQuery.current = {
      isSuccess: false,
      isError: true,
      data: undefined,
    };
    const onApply = openPicker();
    const [, endInput] =
      document.querySelectorAll<HTMLInputElement>('input[type="date"]');
    fireEvent.change(endInput, { target: { value: "9999-12-31" } });
    const confirm = screen.getByRole("button", { name: "common.confirm" });
    expect(confirm).toBeEnabled();
    fireEvent.click(confirm);

    expect(onApply).toHaveBeenCalledTimes(1);
    const now = new Date();
    expect(onApply.mock.calls[0][0].customEndDate).toBe(
      toTs(new Date(now.getFullYear(), now.getMonth(), now.getDate(), 23, 59)),
    );
  });

  // #9691：选到 1905 年会让趋势图按天画四万多根柱子，卡死界面
  it("clamps a start date typed before the first usage day", () => {
    const onApply = openPicker();
    const [startInput] =
      document.querySelectorAll<HTMLInputElement>('input[type="date"]');
    expect(startInput.min).toBe("2025-06-01");
    fireEvent.change(startInput, { target: { value: "1905-11-18" } });
    fireEvent.click(screen.getByRole("button", { name: "common.confirm" }));

    expect(onApply).toHaveBeenCalledTimes(1);
    const applied = onApply.mock.calls[0][0];
    expect(applied.preset).toBe("custom");
    expect(applied.customStartDate).toBe(toTs(new Date(2025, 5, 1)));
  });

  it("clamps an end date typed after today", () => {
    const onApply = openPicker();
    const [, endInput] =
      document.querySelectorAll<HTMLInputElement>('input[type="date"]');
    fireEvent.change(endInput, { target: { value: "9999-12-31" } });
    fireEvent.click(screen.getByRole("button", { name: "common.confirm" }));

    const now = new Date();
    const endOfToday = toTs(
      new Date(now.getFullYear(), now.getMonth(), now.getDate(), 23, 59),
    );
    expect(onApply.mock.calls[0][0].customEndDate).toBe(endOfToday);
  });

  it("disables calendar days after today", () => {
    const now = new Date();
    const todayStart = toTs(
      new Date(now.getFullYear(), now.getMonth(), now.getDate()),
    );
    render(
      <UsageDateRangePicker
        selection={{
          preset: "custom",
          customStartDate: todayStart,
          customEndDate: toTs(now),
        }}
        onApply={vi.fn()}
        triggerLabel="custom"
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: /custom/ }));
    // 日历停在本月，42 格网格末尾总有下个月的几天
    const days = Array.from(
      document.querySelectorAll<HTMLButtonElement>("button[aria-pressed]"),
    ).filter((btn) => /^\d+$/.test(btn.textContent ?? ""));
    expect(days).toHaveLength(42);
    const todayBtn = days.find(
      (btn) => btn.getAttribute("aria-current") === "date",
    );
    expect(todayBtn).toBeDefined();
    expect(todayBtn).not.toBeDisabled();
    const todayIndex = days.indexOf(todayBtn!);
    days.forEach((btn, index) => {
      if (index > todayIndex) expect(btn).toBeDisabled();
      else expect(btn).not.toBeDisabled();
    });
  });

  // #9699：逐位键入年份时，没打完的 0002 不能被当成 19xx 年提交并改写输入框
  it("keeps a partially typed year in the field and does not commit it", () => {
    const onApply = openPicker();
    const [startInput] =
      document.querySelectorAll<HTMLInputElement>('input[type="date"]');
    const committedDay = startInput.value;

    fireEvent.change(startInput, { target: { value: "0002-01-01" } });
    // 草稿原样留在输入框里，等用户继续把年份打完
    expect(startInput.value).toBe("0002-01-01");

    fireEvent.click(screen.getByRole("button", { name: "common.confirm" }));
    expect(onApply).toHaveBeenCalledTimes(1);
    const applied = onApply.mock.calls[0][0];
    // 起点仍是原来的日期，没有被 1902 年覆盖
    expect(formatDay(new Date(applied.customStartDate * 1000))).toBe(
      committedDay,
    );
    expect(applied.customStartDate).toBeGreaterThanOrEqual(
      toTs(new Date(2025, 5, 1)),
    );
  });

  it("commits a date once the year is complete", () => {
    const onApply = openPicker();
    const [startInput] =
      document.querySelectorAll<HTMLInputElement>('input[type="date"]');

    fireEvent.change(startInput, { target: { value: "2025-07-01" } });
    expect(startInput.value).toBe("2025-07-01");
    fireEvent.blur(startInput);
    expect(startInput.value).toBe("2025-07-01");

    fireEvent.click(screen.getByRole("button", { name: "common.confirm" }));
    const start = new Date(onApply.mock.calls[0][0].customStartDate * 1000);
    expect([start.getFullYear(), start.getMonth(), start.getDate()]).toEqual([
      2025, 6, 1,
    ]);
  });

  it("restores the committed date when the field is cleared before blurring", () => {
    const onApply = openPicker();
    const [startInput] =
      document.querySelectorAll<HTMLInputElement>('input[type="date"]');
    const committedDay = startInput.value;

    fireEvent.change(startInput, { target: { value: "" } });
    expect(startInput.value).toBe("");
    fireEvent.blur(startInput);
    expect(startInput.value).toBe(committedDay);

    fireEvent.click(screen.getByRole("button", { name: "common.confirm" }));
    expect(
      formatDay(new Date(onApply.mock.calls[0][0].customStartDate * 1000)),
    ).toBe(committedDay);
  });

  it("discards an unfinished typed date when a calendar day is picked", () => {
    openPicker();
    const [startInput] =
      document.querySelectorAll<HTMLInputElement>('input[type="date"]');
    fireEvent.change(startInput, { target: { value: "0002-01-01" } });
    expect(startInput.value).toBe("0002-01-01");

    const todayButton = screen
      .getAllByRole("button")
      .find((btn) => btn.getAttribute("aria-current") === "date");
    expect(todayButton).toBeDefined();
    fireEvent.click(todayButton!);

    expect(startInput.value).toBe(formatDay(new Date()));
  });
});
