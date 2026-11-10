import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Loader2, Play, Plus, Trash2 } from "lucide-react";
import { settingsApi } from "@/lib/api";
import type {
  RedactAction,
  RedactConfig,
  RedactKind,
  RedactRule,
} from "@/types";
import type { SettingsFormState } from "@/hooks/useSettings";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  SettingsBlock,
  SettingsCard,
  SettingsSwitchRow,
} from "@/components/settings/SettingsLayout";
import {
  PERSONAL_KINDS,
  REDACT_ACTIONS,
  REDACT_KINDS,
  createRule,
  isKindEnabled,
  splitList,
  withKindEnabled,
} from "@/lib/redactConfig";

interface PrivacySectionProps {
  settings: SettingsFormState;
  onAutoSave: (updates: Partial<SettingsFormState>) => Promise<boolean>;
}

/** 与后端 `RedactConfig::default()` 保持一致。 */
const DEFAULT_REDACT: RedactConfig = {
  enabled: false,
  secrets: true,
  personal: true,
  kinds: [],
  words: [],
  wordsAnyCase: false,
  wordsWhole: true,
  rules: [],
  allow: [],
  failClosed: true,
};

/**
 * 设置 → 隐私：请求脱敏。
 *
 * 只能处理经过 CC Switch 本地代理的请求；直连 provider 的流量不受影响。
 */
export function PrivacySection({ settings, onAutoSave }: PrivacySectionProps) {
  const { t } = useTranslation();
  const redact = settings.redact ?? DEFAULT_REDACT;

  const [wordsDraft, setWordsDraft] = useState(redact.words.join("\n"));
  const [allowDraft, setAllowDraft] = useState(redact.allow.join("\n"));
  // 规则输入框保留本地草稿，失焦时才写回，避免每敲一个字符保存一次。
  const [ruleDrafts, setRuleDrafts] = useState<RedactRule[]>(redact.rules);
  const [previewInput, setPreviewInput] = useState("");
  const [preview, setPreview] = useState<{
    masked: string;
    hits: number;
    placeholders: number;
    errors: string[];
  } | null>(null);
  const [previewing, setPreviewing] = useState(false);

  useEffect(() => {
    setWordsDraft(redact.words.join("\n"));
  }, [redact.words]);

  useEffect(() => {
    setAllowDraft(redact.allow.join("\n"));
  }, [redact.allow]);

  useEffect(() => {
    setRuleDrafts(redact.rules);
  }, [redact.rules]);

  const update = (patch: Partial<RedactConfig>) => {
    void onAutoSave({ redact: { ...redact, ...patch } });
  };

  const commitRules = (rules: RedactRule[]) => {
    setRuleDrafts(rules);
    update({ rules });
  };

  const patchRule = (index: number, patch: Partial<RedactRule>) => {
    setRuleDrafts((current) =>
      current.map((rule, itemIndex) =>
        itemIndex === index ? { ...rule, ...patch } : rule,
      ),
    );
  };

  const addRule = () => {
    commitRules([...ruleDrafts, createRule(redact)]);
  };

  const deleteRule = (index: number) => {
    commitRules(ruleDrafts.filter((_, itemIndex) => itemIndex !== index));
  };

  const handlePreview = async () => {
    if (!previewInput.trim() || previewing) return;
    setPreviewing(true);
    try {
      setPreview(await settingsApi.previewRedaction(previewInput));
    } catch (error) {
      console.error("[PrivacySection] 预览脱敏失败", error);
    } finally {
      setPreviewing(false);
    }
  };

  const kindLabel = (kind: RedactKind) => t(`settings.privacy.kind${kind}`);
  const actionLabel = (action: RedactAction) =>
    t(`settings.privacy.action${action[0].toUpperCase()}${action.slice(1)}`);

  const personalDisabled = !redact.enabled || !redact.personal;

  return (
    <>
      <SettingsBlock
        title={t("settings.privacy.title")}
        help={{
          title: t("settings.privacy.title"),
          body: t("settings.privacy.description"),
        }}
      >
        <SettingsCard>
          <SettingsSwitchRow
            label={t("settings.privacy.enabled")}
            description={t("settings.privacy.enabledDescription")}
            checked={redact.enabled}
            onCheckedChange={(value) => update({ enabled: value })}
          />
          <SettingsSwitchRow
            label={t("settings.privacy.secrets")}
            description={t("settings.privacy.secretsDescription")}
            checked={redact.secrets}
            disabled={!redact.enabled}
            onCheckedChange={(value) => update({ secrets: value })}
          />
          <SettingsSwitchRow
            label={t("settings.privacy.personal")}
            description={t("settings.privacy.personalDescription")}
            checked={redact.personal}
            disabled={!redact.enabled}
            onCheckedChange={(value) => update({ personal: value })}
          />
          <SettingsSwitchRow
            label={t("settings.privacy.failClosed")}
            description={t("settings.privacy.failClosedDescription")}
            checked={redact.failClosed}
            disabled={!redact.enabled}
            onCheckedChange={(value) => update({ failClosed: value })}
          />
        </SettingsCard>
      </SettingsBlock>

      <SettingsBlock
        title={t("settings.privacy.kindsTitle")}
        help={{
          title: t("settings.privacy.kindsTitle"),
          body: t("settings.privacy.kindsDescription"),
        }}
      >
        <SettingsCard>
          {PERSONAL_KINDS.map((kind) => (
            <SettingsSwitchRow
              key={kind}
              label={kindLabel(kind)}
              checked={isKindEnabled(redact, kind)}
              disabled={personalDisabled}
              onCheckedChange={(value) =>
                update(withKindEnabled(redact, kind, value))
              }
            />
          ))}
        </SettingsCard>
      </SettingsBlock>

      <SettingsBlock
        title={t("settings.privacy.wordsTitle")}
        help={{
          title: t("settings.privacy.wordsTitle"),
          body: t("settings.privacy.wordsDescription"),
        }}
      >
        <SettingsCard>
          <div className="space-y-2 p-5">
            <label
              className="text-body font-medium text-fg-1"
              htmlFor="redact-words"
            >
              {t("settings.privacy.wordsLabel")}
            </label>
            <Textarea
              id="redact-words"
              value={wordsDraft}
              onChange={(event) => setWordsDraft(event.target.value)}
              onBlur={() => update({ words: splitList(wordsDraft) })}
              placeholder={t("settings.privacy.wordsPlaceholder")}
              disabled={!redact.enabled}
              className="min-h-[100px] font-mono"
            />
          </div>
          <div className="space-y-2 border-t border-border p-5">
            <label
              className="text-body font-medium text-fg-1"
              htmlFor="redact-allow"
            >
              {t("settings.privacy.allowLabel")}
            </label>
            <Textarea
              id="redact-allow"
              value={allowDraft}
              onChange={(event) => setAllowDraft(event.target.value)}
              onBlur={() => update({ allow: splitList(allowDraft) })}
              placeholder={t("settings.privacy.allowPlaceholder")}
              disabled={!redact.enabled}
              className="min-h-[80px] font-mono"
            />
          </div>
        </SettingsCard>
      </SettingsBlock>

      <SettingsBlock
        title={t("settings.privacy.rulesTitle")}
        help={{
          title: t("settings.privacy.rulesTitle"),
          body: t("settings.privacy.rulesDescription"),
        }}
      >
        <SettingsCard>
          <div className="space-y-3 p-5">
            {ruleDrafts.length === 0 && (
              <p className="text-caption text-fg-2">
                {t("settings.privacy.rulesEmpty")}
              </p>
            )}
            {ruleDrafts.map((rule, index) => (
              <div
                key={rule.name}
                className="flex flex-wrap items-center gap-2"
              >
                <Input
                  value={rule.pattern}
                  onChange={(event) =>
                    patchRule(index, { pattern: event.target.value })
                  }
                  onBlur={() => commitRules(ruleDrafts)}
                  placeholder={t("settings.privacy.rulePatternPlaceholder")}
                  disabled={!redact.enabled}
                  aria-label={t("settings.privacy.rulePatternPlaceholder")}
                  className="min-w-[220px] flex-1 font-mono"
                />
                <Select
                  value={rule.kind}
                  disabled={!redact.enabled}
                  onValueChange={(value) =>
                    patchRule(index, { kind: value as RedactKind })
                  }
                >
                  <SelectTrigger className="w-[130px]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {REDACT_KINDS.map((kind) => (
                      <SelectItem key={kind} value={kind}>
                        {kindLabel(kind)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Select
                  value={rule.action ?? "placeholder"}
                  disabled={!redact.enabled}
                  onValueChange={(value) =>
                    patchRule(index, { action: value as RedactAction })
                  }
                >
                  <SelectTrigger className="w-[150px]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {REDACT_ACTIONS.map((action) => (
                      <SelectItem key={action} value={action}>
                        {actionLabel(action)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Button
                  type="button"
                  variant="ghost"
                  size="compact"
                  disabled={!redact.enabled}
                  aria-label={t("settings.privacy.ruleRemove")}
                  onClick={() => deleteRule(index)}
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              </div>
            ))}
            <Button
              type="button"
              variant="neutral"
              size="compact"
              disabled={!redact.enabled}
              onClick={addRule}
            >
              <Plus className="h-3.5 w-3.5" />
              {t("settings.privacy.ruleAdd")}
            </Button>
          </div>
        </SettingsCard>
      </SettingsBlock>

      <SettingsBlock
        title={t("settings.privacy.previewTitle")}
        help={{
          title: t("settings.privacy.previewTitle"),
          body: t("settings.privacy.previewDescription"),
        }}
      >
        <SettingsCard>
          <div className="space-y-3 p-5">
            <Textarea
              value={previewInput}
              onChange={(event) => setPreviewInput(event.target.value)}
              placeholder={t("settings.privacy.previewPlaceholder")}
              className="min-h-[100px]"
            />
            <div className="flex items-center gap-2">
              <Button
                type="button"
                variant="neutral"
                size="compact"
                disabled={!previewInput.trim() || previewing}
                onClick={() => void handlePreview()}
              >
                {previewing ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Play className="h-3.5 w-3.5" />
                )}
                {t("settings.privacy.previewButton")}
              </Button>
              {preview && (
                <span className="text-caption text-fg-2">
                  {t("settings.privacy.previewHits", {
                    hits: preview.hits,
                    placeholders: preview.placeholders,
                  })}
                </span>
              )}
            </div>
            {preview && preview.errors.length > 0 && (
              <ul className="space-y-1 rounded-lg border border-danger/40 bg-danger-soft p-3 text-caption text-danger-text">
                {preview.errors.map((error) => (
                  <li key={error}>{error}</li>
                ))}
              </ul>
            )}
            {preview && (
              <pre className="max-h-60 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-border/50 bg-subtle p-3 font-mono text-caption text-fg-1">
                {preview.masked}
              </pre>
            )}
          </div>
        </SettingsCard>
      </SettingsBlock>

      <p className="text-caption text-fg-2">
        {t("settings.privacy.proxyOnly")}
      </p>
    </>
  );
}
