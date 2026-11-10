import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Loader2, Play } from "lucide-react";
import { settingsApi } from "@/lib/api";
import type { RedactConfig } from "@/types";
import type { SettingsFormState } from "@/hooks/useSettings";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import {
  SettingsBlock,
  SettingsCard,
  SettingsSwitchRow,
} from "@/components/settings/SettingsLayout";

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

function splitList(value: string): string[] {
  return value
    .split(/[\n,，]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

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
  const [previewInput, setPreviewInput] = useState("");
  const [preview, setPreview] = useState<{
    masked: string;
    hits: number;
    placeholders: number;
  } | null>(null);
  const [previewing, setPreviewing] = useState(false);

  useEffect(() => {
    setWordsDraft(redact.words.join("\n"));
  }, [redact.words]);

  useEffect(() => {
    setAllowDraft(redact.allow.join("\n"));
  }, [redact.allow]);

  const update = (patch: Partial<RedactConfig>) => {
    void onAutoSave({ redact: { ...redact, ...patch } });
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
