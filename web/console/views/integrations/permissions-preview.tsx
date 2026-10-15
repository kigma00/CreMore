"use client";

/* What each feature needs from the provider, read from the catalog alone (permissionsFor, label): before sign-in, at
 * feature and target choice, and after a check with what it found. The server's check still decides access. */
import { Ic } from "@/console/icons";
import { type Say, useL } from "@/console/text";
import { cls } from "@/console/ui";
import { featureName } from "@/console/views/integrations/copy";
import { applies, detailText, label, permissionsFor, planFields, valuesOf, type Descriptor, type Method, type Permission, type Purpose,
  type PurposeCheck, type Values } from "@/console/views/integrations/model";
import type { Answer, Missing } from "@/console/views/integrations/outcomes";

export type PreviewTarget = { id: string; label?: string; target: Record<string, unknown> };
/** ``optional``: not required, or not needed with the plan being chosen (else the edition's defaults); ``conditional``:
 * only for targets its ``when`` names (shown before targets are known); ``shared``: an earlier feature needs it too. */
export type PreviewRow = { permission: Permission; optional: boolean; conditional: boolean; shared: boolean };

export function checkWord(status: string, L: Say) {
  return ({ GRANTED: L("있음", "Granted"), MISSING: L("없음", "Missing"), NOT_REPORTED: L("확인하지 못함", "Not reported"),
    ERROR: L("확인 실패", "Check failed") } as Record<string, string>)[status] ?? status;
}

/** The rows of each feature, in the order given; ``targets`` per feature once they are chosen, else ``target``. */
export function previewRows(d: Descriptor, method: string, purposes: Purpose[], target: Record<string, unknown> | undefined,
  targets: Partial<Record<Purpose, PreviewTarget[]>> | undefined, plans: Partial<Record<Purpose, Values>> | undefined,
  edition = d.editions[0]?.id ?? "") {
  const seen = new Set<string>();
  return purposes.map(p => {
    const chosen = targets?.[p]?.length ? targets[p]! : null;
    const places = (chosen ?? [{ id: "", target: target ?? {} }]).map(t => t.target);
    // One row per permission, even where the catalog declares it under several options (GCP's getIamPolicy).
    const listed = [...new Map(places.flatMap(t => permissionsFor(d, p, method, t, plans?.[p])).map(item => [item.id, item])).values()];
    // Before targets are listed, a permission for some targets only is still shown, marked as such.
    const conditional = chosen || (target && Object.keys(target).length) ? [] : [...new Map((d.purposes[p]?.permissions ?? [])
      .filter(item => item.when && (!item.methods?.length || item.methods.includes(method)) && !applies(item, target ?? {})
        && !listed.some(other => other.id === item.id)).map(item => [item.id, item])).values()];
    // Needed with the plan being chosen, else with the edition's defaults (an ``unless`` off, an option on by default).
    const needed = (item: Permission, at: Record<string, unknown>) => permissionsFor(d, p, method, at,
      plans?.[p] ?? valuesOf(planFields(d, p, edition, at), {})).some(other => other.id === item.id);
    const rows: PreviewRow[] = [
      ...listed.map(item => ({ item, conditional: false, places })),
      // A target-dependent permission is judged for a target its ``when`` names.
      ...conditional.map(item => ({ item, conditional: true, places: [{ ...(target ?? {}), ...Object.fromEntries(Object.entries(item.when ?? {})
        .map(([name, values]) => [name, values.find(value => value !== "*") ?? "*"])) }] })),
    ].map(({ item, conditional: dependent, places: at }) => ({ permission: item, optional: item.required === false || !at.some(t => needed(item, t)),
      conditional: dependent, shared: seen.has(item.id) }));
    for (const row of rows) seen.add(row.permission.id);
    return { purpose: p, rows };
  });
}

const TONE: Record<string, { tone: string; icon: "checkCircle" | "minusCircle" | "xCircle" }> = {
  GRANTED: { tone: "ok", icon: "checkCircle" }, NOT_REPORTED: { tone: "none", icon: "minusCircle" },
  MISSING: { tone: "bad", icon: "xCircle" }, ERROR: { tone: "bad", icon: "xCircle" },
};
const wraps = { whiteSpace: "normal", height: "auto", overflowWrap: "anywhere" } as const;

export function PermissionPreview({ d, method, purposes, edition, target, targets, plans, results, collapsed = false }: {
  d: Descriptor; method: Method; purposes: Purpose[]; edition?: string; target?: Record<string, unknown>;
  targets?: Partial<Record<Purpose, PreviewTarget[]>>; plans?: Partial<Record<Purpose, Values>>;
  /** Result mode: the draft's check answers, one mark per permission and target or subject. */
  results?: Partial<Record<Purpose, PurposeCheck>>; collapsed?: boolean;
}) {
  const L = useL();
  const groups = previewRows(d, method.id, purposes, target, targets, plans, edition);
  const tag = (key: string, row: PreviewRow, answer: Answer | null, detailed: boolean, p: Purpose) => {
    const shown = answer ? TONE[answer.status] ?? TONE.ERROR : null;
    const where = detailed && answer ? [targets?.[p]?.find(t => t.id === answer.target_id)?.label, answer.subject].filter(Boolean).join(" · ") : "";
    const notes = [row.optional ? L("선택", "Optional") : "", row.conditional ? L("대상에 따라", "Depends on target") : "",
      row.shared ? L("위와 같음", "Same as above") : ""].filter(Boolean);
    const tip = [row.permission.id, answer ? checkWord(answer.status, L) : "", answer?.detail ? detailText(answer.detail, L) : "", where].filter(Boolean).join(" · ");
    return <span key={key} className={cls("tag", shown && `perm-${shown.tone}`)} style={wraps} data-tip={tip}>
      {shown ? <Ic name={shown.icon} size={13} /> : null}
      {label(row.permission, L)}{where ? ` · ${where}` : ""}{notes.length ? <span className="subtle"> · {notes.join(" · ")}</span> : null}</span>;
  };
  const marks = (p: Purpose, row: PreviewRow) => {
    if (!results) return [tag(row.permission.id, row, null, false, p)];
    const answers = (results[p]?.items ?? []).filter(item => item.permission === row.permission.id) as Answer[];
    // A required permission nobody answered for is unverified; an optional one simply was not asked.
    if (!answers.length) return [tag(row.permission.id, row, row.optional ? null : { permission: row.permission.id, status: "NOT_REPORTED" }, false, p)];
    if (answers.every(answer => answer.status === answers[0].status)) return [tag(row.permission.id, row, answers[0], answers.length === 1, p)];
    return answers.map((answer, i) => tag(`${row.permission.id}:${i}`, row, answer, true, p));
  };
  return <>{groups.map(({ purpose: p, rows }) => {
    const body = <div className="ig-perms">{rows.length ? rows.flatMap(row => marks(p, row))
      : <span className="subtle">{L("따로 필요한 권한이 없습니다.", "No extra permission is needed.")}</span>}</div>;
    return collapsed
      ? <details className="ig-perm-group" key={p}><summary>{purposes.length > 1 ? featureName(p, L) : L("필요한 권한", "Permissions needed")}
          {` (${rows.length})`}</summary>{body}</details>
      : <div className="ig-perm-group" key={p}>{purposes.length > 1 ? <span className="ig-sub">{featureName(p, L)}</span> : null}{body}</div>;
  })}</>;
}

/** What a held feature lacks, one line each: the permission, then where (target, subject), then why. */
export function MissingList({ d, purpose, method, missing, targets }: {
  d: Descriptor; purpose: Purpose; method: string; missing: Missing[]; targets?: PreviewTarget[];
}) {
  const L = useL();
  const declared = d.purposes[purpose]?.permissions ?? [];
  return <ul className="perm-notes">{missing.map((item, i) => {
    const permission = declared.find(p => p.id === item.permission && (!p.methods?.length || p.methods.includes(method)))
      ?? declared.find(p => p.id === item.permission);
    const where = [targets?.find(t => t.id === item.target_id)?.label, item.subject].filter(Boolean).join(" · ");
    return <li key={i}>{[permission ? label(permission, L) : item.permission, where,
      item.detail ? detailText(item.detail, L) : checkWord(item.status, L)].filter(Boolean).join(" · ")}</li>;
  })}</ul>;
}
