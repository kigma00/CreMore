"use client";

import { useL } from "@/console/text";
import type { Say } from "@/console/text";
import { AreaField, Check, cls, MultiSelectField, SelectField, TextField } from "@/console/ui";
import { type FieldSpec, type Values, label } from "@/console/views/integrations/model";

/* ---------- fields ---------- */

function fieldHelp(field: FieldSpec, L: Say): string {
  if (field.description) return L(field.description_ko ?? field.description, field.description);
  if (field.secret) return L("연동 인증에 사용하는 비밀값입니다. 저장된 값은 다시 표시하지 않으며 바꿀 때만 입력합니다.", "A secret used to authenticate the integration. Saved values are not shown again; enter a value only to replace one.");
  if (field.hint) return L(`입력 예: ${field.hint}`, `Example: ${field.hint}`);
  if (field.kind === "number") return L(`숫자로 입력합니다.${field.min !== undefined ? ` 최소 ${field.min}.` : ""}${field.max !== undefined ? ` 최대 ${field.max}.` : ""}`, `Enter a number.${field.min !== undefined ? ` Minimum ${field.min}.` : ""}${field.max !== undefined ? ` Maximum ${field.max}.` : ""}`);
  if (field.kind === "list" || field.kind === "choices") return field.options
    ? L("여러 항목을 선택할 수 있습니다. 검색·모두 선택·모두 해제를 지원합니다.", "Select multiple items using search, Select all or Clear all.")
    : L("여러 값은 쉼표나 공백으로 구분합니다.", "Separate multiple values with commas or spaces.");
  if (field.kind === "bool") return L("켜면 이 옵션을 적용하고, 끄면 적용하지 않습니다. 필요한 권한은 다음 진행 시 확인합니다.", "Turn on to apply this option, or off to leave it disabled. Required access is checked before continuing.");
  return L(`${label(field, L)} 설정값입니다.${field.required ? " 반드시 입력하세요." : " 필요한 경우 설정하세요."}`, `${label(field, L)} setting.${field.required ? " A value is required." : " Set it when needed."}`);
}

export function FieldGrid({ fields, values, onChange, valueReading }: {
  fields: FieldSpec[]; values: Values; onChange: (name: string, value: string | boolean | string[]) => void; valueReading?: boolean;
}) {
  const L = useL();
  const toggles = fields.filter(field => field.kind === "bool");
  const others = fields.filter(field => field.kind !== "bool");
  return <>
    {others.length ? <div className="row2 ig-fields">{others.map(field => <FieldInput key={field.name} field={field} value={values[field.name]} onChange={value => onChange(field.name, value)} />)}</div> : null}
    {toggles.length ? <div className="ig-opts ig-toggles">{toggles.map(field => {
      const on = values[field.name] === true;
      const sensitive = valueReading && field.name === "read_values";
      return <button type="button" key={field.name} className="ig-opt" role="checkbox" aria-checked={on}
        data-tip={fieldHelp(field, L)} aria-description={fieldHelp(field, L)} onClick={() => onChange(field.name, !on)}>
        <Check on={on} /><span className="nm">{label(field, L)}{sensitive ? <span className="ig-opt-sub">{L("기본 꺼짐", "Off by default")}</span> : null}</span></button>;
    })}</div> : null}
  </>;
}

function FieldInput({ field, value, onChange }: { field: FieldSpec; value: Values[string] | undefined; onChange: (value: string | boolean | string[]) => void }) {
  const L = useL();
  const name = label(field, L) + (field.required ? "" : L(" (선택)", " (optional)"));
  const text = typeof value === "string" ? value : "";
  const placeholder = field.hint ? L(`예: ${field.hint}`, `e.g. ${field.hint}`) : undefined;
  const tip = fieldHelp(field, L);
  switch (field.kind) {
    case "choice":
      return <SelectField tip={tip} label={label(field, L)} value={text || String(field.options?.[0]?.id ?? "")}
        options={(field.options ?? []).map(option => ({ id: option.id, label: label(option, L) }))} onChange={onChange} />;
    case "choices": {
      const list = Array.isArray(value) ? value : [];
      return <MultiSelectField tip={tip} label={label(field, L)} value={list} options={(field.options ?? []).map(option => ({ id: option.id, label: label(option, L) }))} onChange={onChange} />;
    }
    case "multiline":
      return <div className="ig-wide"><AreaField tip={tip} label={name} value={text} onChange={onChange} placeholder={placeholder} rows={4} className="short" mono /></div>;
    case "number":
      if (field.schedule) return <SelectField tip={tip} label={label(field, L)} value={text}
        options={[...new Set([0, 5, 15, 30, 60, 360, 1440, 10080, Number(text || field.default || 0)])].map(minutes => ({
          id: String(minutes), label: minutes === 0 ? L("수동 수집", "Manual collection") : L(`${minutes}분마다`, `Every ${minutes} minutes`) }))}
        onChange={onChange} />;
      return <TextField tip={tip} label={name} value={text} onChange={onChange} type="number" inputMode="numeric" placeholder={placeholder}
        hint={field.name === "schedule_minutes" ? L("분 단위입니다. 0이면 직접 실행할 때만 수집합니다.", "In minutes. Use 0 to collect only when run manually.") : undefined} />;
    case "list":
      if (field.options !== undefined) return <MultiSelectField tip={tip} label={name} value={text.split(/[\s,]+/).filter(Boolean)}
        options={field.options.map(option => ({ id: option.id, label: label(option, L) }))} onChange={items => onChange(items.join(", "))}
        hint={field.description ? L(field.description_ko ?? field.description, field.description) : undefined} />;
      return <TextField tip={tip} label={name} value={text} onChange={onChange} placeholder={placeholder} hint={L("쉼표나 공백으로 구분합니다", "Separate with commas or spaces")} />;
    default:
      return <TextField tip={tip} label={name} value={text} onChange={onChange} placeholder={placeholder} inputMode={field.kind === "url" ? "url" : undefined} />;
  }
}

export function CredentialField({ field, value, stored, shownValue, onChange }: {
  field: FieldSpec; value: string; stored: boolean; shownValue?: string; onChange: (value: string) => void;
}) {
  const L = useL();
  const name = label(field, L) + (field.optional ? L(" (선택)", " (optional)") : "");
  // A saved credential is never shown again; a public field (an account e-mail, a login role) is.
  const placeholder = stored ? shownValue || L("저장된 값 유지 · 바꿀 때만 입력", "Keep the saved value · enter only to replace")
    : field.secret ? L("여기에 붙여 넣기", "Paste here") : undefined;
  if (field.kind === "multiline") return <AreaField tip={fieldHelp(field, L)} label={name} value={value} onChange={onChange} placeholder={placeholder} rows={5} className={cls("short", field.secret && "masked")} mono />;
  return <TextField tip={fieldHelp(field, L)} label={name} value={value} onChange={onChange} placeholder={placeholder} masked={Boolean(field.secret)} />;
}
