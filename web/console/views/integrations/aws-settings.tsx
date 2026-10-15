"use client";

/* The AWS parts of the common connect wizard (AWS is one provider: these are its panes in the wizard's own steps, the
 * way Google's consent is Google's). They hold the installation's AWS settings, shared by every AWS integration:
 *   what to collect   the automatic issuance inventory, and the investigations each feature offers
 *                     (the key's use and potential access with the inventory, Secrets Manager metadata with vault)
 *   sign in (setup)   the member role across AWS Organizations, the accounts an IAM Identity Center permission set
 *                     is assigned in, and the identity approved key actions run as, next to the scanning identity.
 * A settings change is audited by the API (INSTALLATION_SETTING_CHANGED); an identity approval keeps who approved it
 * and when on the approval itself. */

import { useEffect, useRef, useState } from "react";

import { useLocale } from "@/components/locale";
import { codeText, reasonText, send, useApi, useSaved } from "@/console/data";
import { Ic } from "@/console/icons";
import { actorLabel } from "@/console/labels";
import { useToast } from "@/console/layer";
import { rel, type Say, useL } from "@/console/text";
import { Banner, Check, ErrorLine, Loading, MultiSelectField, SelectField, StateChip, Switch, TextField } from "@/console/ui";
import { kindName, refusalText } from "@/console/views/integrations/aws-identity";
import { type Changed, Row, switchLocked, type Toggle, useSave, whoChanged } from "@/console/views/settings";
import { api } from "@/lib/dashboard-api";

export type OrgView = Changed & {
  enabled: boolean; installation_allows: boolean; effective: boolean; interval_minutes: number;
  external_id: string | null; external_id_locked: boolean; ou_ids: string[]; ou_ids_locked: boolean;
  excludes: string[]; excludes_locked: boolean; auto_validate: boolean;
  control_tower_enabled: boolean; control_tower_region: string; lifecycle_queue_url: string; lifecycle_queue_acknowledged: boolean;
};
type OrgDeployment = {
  region: string; stack_set_name: string; template_file: string; template_path: string; parameters_file: string;
  parameters: { ParameterKey: string; ParameterValue: string }[]; targets: string[]; excludes: string[]; commands: string[];
};
// A probe that answered carries its reason code; one that failed carries the refusal in words (text).
type Probe = { available: boolean; reason: string | null; total: number; available_permission_sets?: { name: string; accounts: number }[]; text?: string };
type Sweep = { registered: unknown[] | null; changed: unknown[] | null; skipped: number | null; error: string | null; adopted: number };
type IdentityCenterView = {
  permission_set: string | null; locked: boolean; source: string | null; permission_set_updated_by: string | null; permission_set_updated_at: string | null;
  discovery: Toggle; interval_minutes: number; excluded_accounts: string[];
};
export type InventoryView = Changed & {
  enabled: boolean; interval_minutes: number; account_ids: string[]; cloudtrail_enabled: boolean; cloudtrail_source: string;
  window_days: number; regions: string[]; trail_bucket: string; trail_prefixes: string[]; installation_allows: boolean;
  effective: boolean; reason: string | null;
};
export type Investigations = Record<"usage_lookup" | "potential_access" | "secrets_inventory", Toggle>;
export type InvestigationEdits = Partial<Record<keyof Investigations, { enabled: boolean; expected: boolean }>>;

export function investigationKeys(purposes: string[]): (keyof Investigations)[] {
  return [
    ...(purposes.some(p => p === "exposure" || p === "inventory") ? ["usage_lookup", "potential_access"] as const : []),
    ...(purposes.includes("vault") ? ["secrets_inventory"] as const : []),
  ];
}

export function investigationRequest(edits: InvestigationEdits, purposes: string[]) {
  const entries = investigationKeys(purposes).flatMap(key => edits[key] ? [[key, edits[key]!] as const] : []);
  return entries.length ? {
    changes: Object.fromEntries(entries.map(([key, edit]) => [key, edit.enabled])),
    expected: Object.fromEntries(entries.map(([key, edit]) => [key, edit.expected])),
  } : undefined;
}
type Runtime = { state: string; kind?: string | null; account_id?: string | null; principal_arn?: string | null; permission_set?: string | null; requires?: string | null; error_code?: string | null };
type RemediationView = {
  identity_source?: "api" | "remediator";
  api: Runtime; profile: string | null; approvable: string | null; same_as_scanner: boolean; remediation_role_name: string; policy: unknown;
  approved: { kind?: string | null; account_id?: string | null; principal_arn?: string | null; permission_set?: string | null; approved_by?: string | null; approved_at?: string | null } | null;
};
type Account = { account_id: string; name: string; discovery_context?: { organization?: { organization_id?: string } } };

// What each value is, as AWS and the member role template accept it (cremore_aws_provider/aws_org_settings.py,
// deploy/cloudformation/member-account-role.yaml).
export const TEMPLATE_EXTERNAL_ID = /^[A-Za-z0-9+=,.@:/_-]{16,128}$/;
/** An unguessable ExternalId from the side that assumes the roles, as AWS advises: 128 random bits in hex. */
export function randomExternalId() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return "cremore-" + Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}
export const OU_ID = /^(ou-[0-9a-z]{4,32}-[0-9a-z]{8,32}|r-[0-9a-z]{4,32})$/;
export const ACCOUNT_ID = /^[0-9]{12}$/;
export const ORGANIZATION_ID = /^o-[a-z0-9]{10,32}$/;
export const REGION = /^[a-z]{2,4}(-[a-z]+)+-[0-9]+$/;
export const PERMISSION_SET = /^[A-Za-z0-9+=,.@_-]{1,32}$/;

/** A list typed as text: split on commas, spaces and lines, empty entries dropped. */
export function words(text: string): string[] {
  return text.split(/[\s,]+/).map(item => item.trim()).filter(Boolean);
}

/** The Organizations save body: only what changed, and never a field the installation pins (the API refuses a
 * pinned field that is present at all). */
export function orgChanges(view: OrgView, form: OrgForm): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const same = (a: string[], b: string[]) => [...a].sort().join(",") === [...b].sort().join(",");
  if (!view.external_id_locked && form.external_id.trim() !== (view.external_id ?? "")) out.external_id = form.external_id.trim();
  if (!view.ou_ids_locked && !same(words(form.ou_ids), view.ou_ids)) out.ou_ids = words(form.ou_ids);
  if (!view.excludes_locked && !same(words(form.excludes), view.excludes)) out.excludes = words(form.excludes);
  if (form.auto_validate !== view.auto_validate) out.auto_validate = form.auto_validate;
  if (form.control_tower_enabled !== view.control_tower_enabled) out.control_tower_enabled = form.control_tower_enabled;
  if (form.control_tower_region.trim() !== view.control_tower_region) out.control_tower_region = form.control_tower_region.trim();
  if (form.lifecycle_queue_url.trim() !== view.lifecycle_queue_url) out.lifecycle_queue_url = form.lifecycle_queue_url.trim();
  if (form.lifecycle_queue_acknowledged !== view.lifecycle_queue_acknowledged) out.lifecycle_queue_acknowledged = form.lifecycle_queue_acknowledged;
  return out;
}
export type OrgForm = {
  external_id: string; ou_ids: string; excludes: string; auto_validate: boolean; control_tower_enabled: boolean;
  control_tower_region: string; lifecycle_queue_url: string; lifecycle_queue_acknowledged: boolean;
};
const orgForm = (view: OrgView): OrgForm => ({
  external_id: view.external_id ?? "", ou_ids: view.ou_ids.join(", "), excludes: view.excludes.join(", "), auto_validate: view.auto_validate,
  control_tower_enabled: view.control_tower_enabled, control_tower_region: view.control_tower_region,
  lifecycle_queue_url: view.lifecycle_queue_url, lifecycle_queue_acknowledged: view.lifecycle_queue_acknowledged,
});

/** What is wrong with the Organizations form, in words; null when it can be saved. A new ExternalId must suit the
 * role template (16-128 characters); one already saved is not the form's to refuse, since roles deployed with it
 * trust exactly it. The Control Tower fields follow the API: a Region is a Region name even while off, and the
 * lifecycle queue lives in that Region. */
export function orgProblem(view: OrgView, form: OrgForm, L: Say): string | null {
  const external = form.external_id.trim();
  if (!view.external_id_locked && external && external !== (view.external_id ?? "") && !TEMPLATE_EXTERNAL_ID.test(external)) {
    return L("ExternalId는 역할 템플릿이 받는 16~128자(영문·숫자와 +=,.@:/_-)로 넣습니다.", "The ExternalId is 16 to 128 characters the role template takes (letters, digits and +=,.@:/_-).");
  }
  if (!view.ou_ids_locked && words(form.ou_ids).some(id => !OU_ID.test(id))) return L("OU는 ou-로, 조직 루트는 r-로 시작하는 ID로 넣습니다.", "Enter OU IDs (ou-…) or the organization root ID (r-…).");
  if (!view.excludes_locked && words(form.excludes).some(id => !ACCOUNT_ID.test(id))) return L("제외할 계정은 12자리 계정 ID로 넣습니다.", "Enter excluded accounts as 12-digit account IDs.");
  const region = form.control_tower_region.trim();
  if ((form.control_tower_enabled || region) && !REGION.test(region)) return L("Control Tower 홈 리전을 넣습니다(예: ap-northeast-2).", "Enter the Control Tower home Region (for example ap-northeast-2).");
  const queue = form.lifecycle_queue_url.trim();
  const host = (() => { try { return new URL(queue).hostname; } catch { return ""; } })();
  if (queue && host !== `sqs.${region}.amazonaws.com${region.startsWith("cn-") ? ".cn" : ""}`) {
    return L("수명주기 큐는 Control Tower 홈 리전의 SQS 큐 URL로 넣습니다.", "Enter a lifecycle queue URL in the Control Tower home Region.");
  }
  return null;
}

/** An inventory save body from the form, and what is wrong with it (null when it can be saved). */
export type InventoryForm = {
  enabled: boolean; interval: string; all: boolean; accounts: string[]; cloudtrail: boolean; source: string; window: string;
  regions: string; bucket: string; prefixes: string;
};
/** With CloudTrail off its fields are hidden, so they are left out and keep what was saved (the API merges the saved
 * setting). A saved setting that cannot be read is rewritten whole (`complete`). Event History takes no bucket. */
export function inventoryBody(form: InventoryForm, complete = false): Record<string, unknown> {
  const body: Record<string, unknown> = { enabled: form.enabled, interval_minutes: Number(form.interval), account_ids: form.all ? [] : form.accounts,
    cloudtrail_enabled: form.cloudtrail };
  if (!form.cloudtrail && !complete) return body;
  const s3 = form.source === "s3";
  return { ...body, cloudtrail_source: form.source, window_days: Number(form.window), regions: words(form.regions),
    trail_bucket: s3 ? form.bucket.trim() : "", trail_prefixes: s3 ? form.prefixes.split("\n").map(line => line.trim()).filter(Boolean) : [] };
}
export function inventoryProblem(form: InventoryForm, L: Say, complete = false): string | null {
  const whole = (value: string, min: number, max: number) => /^\d+$/.test(value.trim()) && Number(value) >= min && Number(value) <= max;
  if (!whole(form.interval, 5, 10080)) return L("수집 간격은 5분부터 10,080분(7일)까지입니다.", "The interval is 5 to 10,080 minutes (7 days).");
  if (!form.all && !form.accounts.length) return L("수집할 계정을 하나 이상 고르거나 모든 계정을 고릅니다.", "Choose at least one account, or every account.");
  if (!form.cloudtrail && !complete) return null;  // hidden and left out; a rewrite sends them, so they are checked
  const s3 = form.source === "s3";
  if (!whole(form.window, 1, s3 ? 3650 : 90)) return s3 ? L("S3 로그의 조회 기간은 1일부터 3,650일까지입니다.", "An S3 log window is 1 to 3,650 days.") : L("Event History의 조회 기간은 1일부터 90일까지입니다.", "An Event History window is 1 to 90 days.");
  const regions = words(form.regions);
  if (!regions.length || regions.length > 50 || regions.some(region => !REGION.test(region))) return L("CloudTrail을 읽을 리전을 넣습니다(예: ap-northeast-2, us-east-1).", "Enter the Regions to read CloudTrail in (for example ap-northeast-2, us-east-1).");
  if (s3 && (!form.bucket.trim() || !form.prefixes.trim())) return L("기존 Trail 버킷과 읽을 로그 prefix를 넣습니다.", "Enter the existing trail bucket and the log prefixes to read.");
  return null;
}
const inventoryForm = (view: InventoryView): InventoryForm => ({
  enabled: view.enabled, interval: String(view.interval_minutes), all: !view.account_ids.length, accounts: view.account_ids,
  cloudtrail: view.cloudtrail_enabled, source: view.cloudtrail_source || "event_history", window: String(view.window_days),
  regions: view.regions.join(", "), bucket: view.trail_bucket, prefixes: view.trail_prefixes.join("\n"),
});

/** Why the AWS discovery probe could not read (cremore/api/aws_support.py role check codes). */
export function probeText(probe: Probe, L: Say): string {
  if (probe.text) return probe.text;
  const code = (probe.reason ?? "").split(/[\s:]/, 1)[0];
  return codeText(code, L) ?? L(`AWS에서 읽지 못했습니다 (${code || "알 수 없음"})`, `AWS could not be read (${code || "unknown"})`);
}

// A sweep that could not start answers with a code of its own (aws_org_discovery.py, aws_sso_discovery.py).
const SWEEP_ERRORS: Record<string, string> = { no_external_id: "EXTERNAL_ID_NOT_SET", no_permission_set: "PERMISSION_SET_NOT_CHOSEN",
  bad_permission_set: "PERMISSION_SET_INVALID" };

/** What an import did, and whether it failed. */
export function sweepText(sweep: Sweep, L: Say): [string, "bad" | undefined] {
  if (sweep.error) return [codeText(SWEEP_ERRORS[sweep.error], L) ?? L(`계정을 가져오지 못했습니다 (${sweep.error})`, `The accounts were not imported (${sweep.error})`), "bad"];
  const n = (value: unknown[] | null) => value?.length ?? 0;
  return [L(`등록 ${n(sweep.registered)} · 갱신 ${n(sweep.changed)} · 건너뜀 ${sweep.skipped ?? 0} · 연동에 추가 ${sweep.adopted}`,
    `${n(sweep.registered)} registered · ${n(sweep.changed)} updated · ${sweep.skipped ?? 0} skipped · ${sweep.adopted} added to integrations`), undefined];
}

/** Copy text and say whether it was copied; a browser without clipboard access says so rather than doing nothing. */
function copy(text: string, toast: (text: string, tone?: "ok" | "bad") => void, L: Say) {
  if (!navigator.clipboard) { toast(L("이 브라우저에서는 복사할 수 없습니다", "This browser cannot copy"), "bad"); return; }
  navigator.clipboard.writeText(text).then(() => toast(L("복사했습니다", "Copied")), () => toast(L("복사하지 못했습니다", "Could not copy"), "bad"));
}

/** A refused sweep reads by its code: "<CODE>: the discovery sweep could not be completed" otherwise shows English. */
function sweepRefusal(reason: unknown, L: Say) {
  const text = reason instanceof Error ? reason.message : "";
  if (text.endsWith("the discovery sweep could not be completed")) return L(`계정 발견을 마치지 못했습니다 (${text.split(":", 1)[0]})`, `The discovery sweep did not finish (${text.split(":", 1)[0]})`);
  return reasonText(reason, L);
}

/** The note under each part: these settings are the installation's, whichever AWS integration shows them, and a save
 * applies at once rather than when the wizard finishes. */
function Shared({ changed }: { changed?: Changed }) {
  const L = useL();
  const locale = useLocale();
  return <p className="meta aws-set-shared">{L("이 설치의 모든 AWS 연동에 바로 적용됩니다.", "Applies at once to every AWS integration of this installation.")}
    {changed?.updated_by ? ` ${whoChanged(changed, L, locale, "")}` : ""}</p>;
}

/** Which AWS parts the connect wizard shows (an Admin's, and none for the CreMore CLI in the customer's environment):
 * the issuance inventory's schedule with that feature, the investigations of discovered credentials with any, and in
 * the sign-in the member role across Organizations, the permission set's assigned accounts, and the key action
 * identity. */
export function awsParts(provider: string, admin: boolean, method: string | undefined, purposes: readonly string[]) {
  const on = provider === "aws" && admin && method !== "customer_cli";
  return { inventory: on && purposes.includes("inventory"), investigations: on, organization: on && method === "role",
    assigned: on && method === "sso", keyActions: on };
}

/* ---------- AWS Organizations: the member role across the organization (setup, member-role sign-in) ---------- */

export function AwsOrganizations({ regionOptions }: { regionOptions: { id: string; label: string }[] }) {
  const L = useL();
  const toast = useToast();
  const saved = useSaved();
  const view = useApi<OrgView>("settings/aws-organizations");
  const accounts = useApi<Account[]>("aws/accounts");
  const { busy, save } = useSave<OrgView>(view.replace);
  const [form, setForm] = useState<OrgForm | null>(null);
  // The view the form was filled from: a change is what this form changed, not what another save did meanwhile.
  const [base, setBase] = useState<OrgView | null>(null);
  // The next view becomes the form: on load and after a save, without dropping the form (and its focus) meanwhile.
  const [fresh, setFresh] = useState(true);
  const [orgId, setOrgId] = useState("");
  const [deployment, setDeployment] = useState<OrgDeployment | null>(null);
  const [probe, setProbe] = useState<Probe | null>(null);
  const [working, setWorking] = useState<"" | "deploy" | "probe" | "sweep">("");
  useEffect(() => { if (view.data && fresh) { setForm(orgForm(view.data)); setBase(view.data); setFresh(false); } }, [view.data, fresh]);
  // The organization an account's discovery context names, so the StackSet command does not ask for it again.
  useEffect(() => {
    const known = (accounts.data ?? []).map(account => account.discovery_context?.organization?.organization_id).find(id => id && ORGANIZATION_ID.test(id));
    if (known) setOrgId(current => current || known);
  }, [accounts.data]);
  if (view.error) return <ErrorLine onRetry={view.reload}>{reasonText(view.error, L)}</ErrorLine>;
  if (!view.data || !form || !base) return <Loading />;
  const v = view.data;
  const set = (change: Partial<OrgForm>) => {
    setForm(current => current ? { ...current, ...change } : current);
    // The commands are made from what is saved; an edit to what they carry makes them stale.
    if ("external_id" in change || "ou_ids" in change || "excludes" in change) setDeployment(null);
  };
  const problem = orgProblem(base, form, L);
  const changes = orgChanges(base, form);
  const fixed = L("설치 설정에 고정되어 있습니다.", "Fixed by the installation's configuration.");
  const idSaved = Boolean(v.external_id) || v.external_id_locked;
  // The commands carry the saved values, and the role template takes an ExternalId of 16-128 characters.
  const deployBlock = !idSaved ? L("ExternalId를 먼저 저장합니다.", "Save the ExternalId first.")
    : ["external_id", "ou_ids", "excludes"].some(name => name in changes) ? L("바꾼 ExternalId·OU·제외 계정을 먼저 저장합니다.", "Save the changed ExternalId, OUs or excluded accounts first.")
      : TEMPLATE_EXTERNAL_ID.test(v.external_id ?? "") ? null
        : v.external_id_locked ? L("설치 설정 AWS_ORG_DISCOVERY_EXTERNAL_ID의 값이 역할 템플릿이 받는 16~128자가 아닙니다. 배포 담당자가 값을 바꿉니다.",
          "The installation's AWS_ORG_DISCOVERY_EXTERNAL_ID is not the 16 to 128 characters the role template takes; whoever deploys CreMore changes it.")
          : codeText("EXTERNAL_ID_TEMPLATE_LENGTH", L);
  const orgIdOk = ORGANIZATION_ID.test(orgId.trim());
  const importing = working === "sweep" ? L("가져오는 중", "Importing") : L("지금 가져오기", "Import now");
  const store = async () => { if (await save("settings/aws-organizations", changes)) { setFresh(true); setDeployment(null); } };
  const commands = async () => {
    setWorking("deploy");
    try { setDeployment(await api<OrgDeployment>(`aws/onboarding/organization?organization_id=${encodeURIComponent(orgId.trim())}`)); }
    catch (reason) { toast(reasonText(reason, L), "bad"); } finally { setWorking(""); }
  };
  const check = async () => {
    setWorking("probe");
    try { setProbe(await api<Probe>("aws/accounts/discoverable?source=org")); }
    catch (reason) { setProbe({ available: false, reason: null, total: 0, text: reasonText(reason, L) }); } finally { setWorking(""); }
  };
  const sweep = async () => {
    setWorking("sweep");
    try { const result = await send<Sweep>("aws/accounts/discover?source=org", "POST", {}); saved(); accounts.reload(); toast(...sweepText(result, L)); }
    catch (reason) { toast(sweepRefusal(reason, L), "bad"); } finally { setWorking(""); }
  };
  return <div className="aws-set-part">
    <Shared changed={v} />

    <h4 className="aws-set-step">{L("조직 정보", "The organization")}</h4>
    <div className="row2">
      <TextField label={L("StackSet의 공유 ExternalId", "The StackSet's shared ExternalId")} value={form.external_id} onChange={value => set({ external_id: value })}
        disabled={busy || v.external_id_locked} placeholder="cremore-…" maxLength={128}
        hint={v.external_id_locked ? fixed : <>{L("모든 계정의 역할이 이 값을 함께 보낸 요청만 받습니다(16~128자). AWS 권고대로 추측할 수 없는 무작위 값을 씁니다.",
          "Every account's role accepts only requests that carry it (16 to 128 characters). As AWS advises, use an unguessable random value.")}{" "}
          <button type="button" className="link-btn" disabled={busy} onClick={() => set({ external_id: randomExternalId() })}>{L("무작위 값 넣기", "Fill a random value")}</button></>} />
      <TextField label={L("대상 OU (선택, 하위 OU 포함)", "Organizational units (optional; nested OUs included)")} value={form.ou_ids} onChange={value => set({ ou_ids: value })}
        disabled={busy || v.ou_ids_locked} placeholder="ou-abcd-11111111, r-abcd"
        hint={v.ou_ids_locked ? fixed : L("비우면 조직 전체를 봅니다. 배포 명령에는 조직 루트 ID(r-…)나 OU가 필요합니다.", "Empty reads the whole organization. The deployment command needs the root ID (r-…) or OUs.")} />
      <TextField label={L("제외할 계정 (쉼표 구분)", "Excluded accounts (comma separated)")} value={form.excludes} onChange={value => set({ excludes: value })}
        disabled={busy || v.excludes_locked} placeholder="111111111111"
        hint={v.excludes_locked ? fixed : L("제외한 계정은 이미 등록돼 있어도 수집을 멈추고, 배포 명령에서도 빠집니다.", "An excluded account stops being collected even if registered, and is left out of the deployment command.")} />
    </div>
    <label className="set-check"><input type="checkbox" checked={form.auto_validate} disabled={busy} onChange={event => set({ auto_validate: event.target.checked })} />
      <span>{L("새로 등록한 계정의 역할을 바로 확인합니다(스택이 아직 배포 중이면 꺼 둡니다).", "Check each newly registered account's role at once (leave off while stacks are still deploying).")}</span></label>
    <details className="aws-set-more">
      <summary>{L("Control Tower 정보와 수명주기 큐 (선택)", "Control Tower context and lifecycle queue (optional)")}</summary>
      <label className="set-check"><input type="checkbox" checked={form.control_tower_enabled} disabled={busy} onChange={event => set({ control_tower_enabled: event.target.checked })} />
        <span>{L("Control Tower 기준(baseline) 정보를 읽습니다.", "Read the Control Tower baseline context.")}</span></label>
      <div className="row2">
        <SelectField label={L("Control Tower 홈 리전", "Control Tower home Region")} value={form.control_tower_region} onChange={value => set({ control_tower_region: value })} disabled={busy}
          options={[{ id: "", label: L("리전을 선택하세요", "Select a region") }, ...regionOptions,
            ...form.control_tower_region && !regionOptions.some(option => option.id === form.control_tower_region) ? [{ id: form.control_tower_region, label: form.control_tower_region }] : []]} />
        <TextField label={L("전용 수명주기 SQS 큐 URL (선택)", "Dedicated lifecycle SQS queue URL (optional)")} value={form.lifecycle_queue_url}
          onChange={value => set({ lifecycle_queue_url: value, lifecycle_queue_acknowledged: false })} disabled={busy} placeholder="https://sqs.<region>.amazonaws.com/<account>/<queue>" />
      </div>
      <label className="set-check"><input type="checkbox" checked={form.lifecycle_queue_acknowledged} disabled={busy || !form.lifecycle_queue_url.trim()}
        onChange={event => set({ lifecycle_queue_acknowledged: event.target.checked })} />
        <span>{L("이 큐는 CreMore 전용이며, 처리한 메시지는 CreMore가 지웁니다. 스캔 트리거의 SQS 큐와 다른 큐여야 합니다.", "This queue is CreMore's own and CreMore deletes the messages it handles. It must differ from the scan trigger's SQS queue.")}</span></label>
      <p className="ig-sub">{L("수명주기 이벤트가 오면 조직의 계정 목록을 바로 다시 읽습니다.", "A lifecycle event makes CreMore read the organization's account list again at once.")}</p>
    </details>
    {problem ? <div className="ig-result bad"><Ic name="alert" size={16} />{problem}</div> : null}
    <div className="aws-set-acts">
      <button type="button" className="primary-btn" disabled={busy || Boolean(problem) || !Object.keys(changes).length} onClick={() => void store()}>{busy ? L("저장 중", "Saving") : L("조직 정보 저장", "Save the organization details")}</button>
    </div>

    <h4 className="aws-set-step">{L("조직 전체에 배포 (한 번)", "Deploy across the organization (once)")}</h4>
    <ul className="aws-set-notes">
      <li>{L("조직의 관리 계정이나 위임된 관리자 계정에서 실행합니다(위임된 관리자는 명령에 --call-as DELEGATED_ADMIN을 붙입니다).", "Run it from the organization's management account or a delegated administrator (add --call-as DELEGATED_ADMIN as a delegated administrator).")}</li>
      <li>{L("AWS Organizations에서 CloudFormation StackSets의 신뢰할 수 있는 액세스를 먼저 켭니다.", "Turn on trusted access for CloudFormation StackSets in AWS Organizations first.")}</li>
      <li>{L("서비스 관리형 StackSet은 관리 계정 자신에는 배포하지 않습니다. 관리 계정은 AWS 연동의 계정 목록에 넣어 따로 역할을 만듭니다.", "A service-managed StackSet never deploys to the management account itself; add that account to an AWS integration's list and create its role there.")}</li>
      <li>{L("역할은 CreMore가 승인한 AWS 신원만 믿고, 조직 ID와 위 ExternalId로 한 번 더 좁힙니다. IAM 역할은 전역이라 한 리전에만 배포합니다.", "The role trusts only the AWS identity CreMore approved, narrowed by the organization ID and the ExternalId above. IAM roles are global, so one Region is enough.")}</li>
    </ul>
    <div className="aws-set-inline">
      <TextField label={L("조직 ID", "Organization ID")} value={orgId} onChange={value => { setOrgId(value); setDeployment(null); }} placeholder="o-abcd123456" />
      <button type="button" className="ghost-btn" disabled={Boolean(working) || Boolean(deployBlock) || !orgIdOk} onClick={() => void commands()}>
        <Ic name="bolt" size={15} />{working === "deploy" ? L("만드는 중", "Making") : L("배포 명령 만들기", "Make the commands")}</button>
      <a className="ghost-btn" href="/api/backend/aws/onboarding/template" download="member-account-role.yaml"><Ic name="download" size={15} />{L("템플릿 받기", "Download template")}</a>
    </div>
    {deployBlock || (orgId.trim() && !orgIdOk) ? <p className="ig-sub">{deployBlock ?? codeText("AWS_ORGANIZATION_ID_INVALID", L)}</p> : null}
    {deployment ? <div className="aws-set-deploy">
      {!deployment.targets.length ? <Banner tone="warn" icon="alert">{L("배포할 OU가 없어 명령에 r-xxxx가 들어 있습니다. 위 OU 칸에 조직 루트 ID(r-…)나 OU를 넣고 저장한 뒤 다시 만듭니다.",
        "No OU is set, so the command holds r-xxxx. Put the root ID (r-…) or OUs above, save, and make the commands again.")}</Banner> : null}
      {deployment.excludes.length ? <p className="ig-sub">{L(`제외한 계정 ${deployment.excludes.length}개는 배포 명령에서 뺐습니다. AWS 자동 배포는 이 제외를 따르지 않아, 나중에 대상 OU로 들어오거나 대상 OU 사이를 옮긴 계정에는 역할이 만들어집니다. 역할이 없어야 하는 계정은 대상 OU 밖에 둡니다.`,
        `The ${deployment.excludes.length} excluded account${deployment.excludes.length === 1 ? " is" : "s are"} left out of the deployment command. AWS automatic deployment does not follow this exclusion: an account that joins a target OU, or moves between target OUs, later gets the role. Keep an account that must have no role outside the target OUs.`)}</p> : null}
      <p className="ig-sub">{L(`매개변수 파일(${deployment.parameters_file})과 템플릿(${deployment.template_file})을 같은 폴더에 받고, 그 폴더에서 명령을 차례로 실행합니다.`,
        `Put the parameters file (${deployment.parameters_file}) and the template (${deployment.template_file}) in one folder and run the commands there in order.`)}</p>
      <div className="aws-set-acts">
        <a className="ghost-btn" href={`data:application/json;charset=utf-8,${encodeURIComponent(JSON.stringify(deployment.parameters, null, 2))}`} download={deployment.parameters_file}>
          <Ic name="download" size={15} />{L("매개변수 파일 받기", "Download the parameters file")}</a>
        <button type="button" className="ghost-btn" onClick={() => void copy(deployment.commands.join("\n"), toast, L)}><Ic name="copy" size={15} />{L("명령 복사", "Copy the commands")}</button>
      </div>
      <pre className="aws-set-code mono">{deployment.commands.join("\n\n")}</pre>
    </div> : null}

    <h4 className="aws-set-step">{L("자동 등록", "Automatic registration")}</h4>
    <Row title={L("조직의 새 계정 자동 등록", "Register the organization's new accounts")}
      text={v.effective ? L(`켜져 있습니다. 워커가 ${v.interval_minutes}분마다 조직의 계정 목록을 읽습니다.`, `On: the worker reads the organization's account list every ${v.interval_minutes} minutes.`)
        : L("켜면 워커가 조직의 계정 목록을 주기적으로 읽어 새 계정을 등록하고, 조직을 떠난 계정은 멈춥니다.", "When on, the worker reads the account list regularly, registers new accounts and stops those that left the organization.")}
      state={!v.installation_allows ? L("설치 설정 AWS_ORG_DISCOVERY_MODE=disabled로 꺼 두었습니다.", "The installation's AWS_ORG_DISCOVERY_MODE=disabled keeps it off.")
        : !idSaved ? L("ExternalId를 저장해야 켤 수 있습니다.", "Save the ExternalId to turn it on.") : undefined}
      control={<Switch checked={v.enabled} label={L("조직 계정 자동 등록", "Organization account registration")}
        disabled={busy || switchLocked(v.installation_allows, v.enabled) || (!v.enabled && !idSaved)} onChange={enabled => void save("settings/aws-organizations", { enabled })} />} />
    <div className="aws-set-acts">
      <button type="button" className="ghost-btn" disabled={Boolean(working)} onClick={() => void check()}><Ic name="shield" size={15} />{working === "probe" ? L("확인 중", "Checking") : L("조직 접근 확인", "Check organization access")}</button>
      <button type="button" className="ghost-btn" disabled={Boolean(working) || !idSaved} aria-label={L(`${importing}: 조직 계정`, `${importing}: organization accounts`)} onClick={() => void sweep()}>
        <Ic name="refresh" size={15} />{importing}</button>
      {probe ? probe.available ? <StateChip tone="ok">{L(`조직 계정 ${probe.total}개가 보입니다`, `${probe.total} organization accounts are listed`)}</StateChip>
        : <span className="ig-result bad"><Ic name="alert" size={15} />{probeText(probe, L)}</span> : null}
    </div>
  </div>;
}

/* ---------- IAM Identity Center: the accounts a permission set is assigned in (setup, permission-set sign-in) ---------- */

export function AwsIdentityCenter() {
  const L = useL();
  const locale = useLocale();
  const toast = useToast();
  const saved = useSaved();
  const view = useApi<IdentityCenterView>("settings/aws-identity-center");
  const { busy, save } = useSave<IdentityCenterView>(view.replace);
  const [typed, setTyped] = useState<string | null>(null);
  const [probe, setProbe] = useState<Probe | null>(null);
  const [working, setWorking] = useState<"" | "probe" | "sweep">("");
  if (view.error) return <ErrorLine onRetry={view.reload}>{reasonText(view.error, L)}</ErrorLine>;
  if (!view.data) return <Loading />;
  const v = view.data;
  const current = v.permission_set ?? "";  // null until one is chosen
  const name = typed ?? current;
  const nameOk = !name.trim() || PERMISSION_SET.test(name.trim());
  const read = async () => {
    setWorking("probe");
    try { setProbe(await api<Probe>("aws/accounts/discoverable?source=sso")); }
    catch (reason) { setProbe({ available: false, reason: null, total: 0, text: reasonText(reason, L) }); } finally { setWorking(""); }
  };
  const sweep = async () => {
    setWorking("sweep");
    try { const result = await send<Sweep>("aws/accounts/discover?source=sso", "POST", {}); saved(); toast(...sweepText(result, L)); }
    catch (reason) { toast(sweepRefusal(reason, L), "bad"); } finally { setWorking(""); }
  };
  const choose = async () => { if (await save("settings/aws-identity-center", { permission_set: name.trim() })) setTyped(null); };
  const options = probe?.available_permission_sets ?? [];
  const importing = working === "sweep" ? L("가져오는 중", "Importing") : L("지금 가져오기", "Import now");
  return <div className="aws-set-part">
    <Shared />
    <div className="aws-set-inline">
      <div className="field">
        <label htmlFor="aws-ps">{L("기본 권한 세트", "Default permission set")}</label>
        <input id="aws-ps" list="aws-ps-options" value={name} disabled={busy || v.locked} maxLength={32} spellCheck={false} autoComplete="off"
          aria-invalid={!nameOk || undefined} onChange={event => setTyped(event.target.value)} />
        <datalist id="aws-ps-options">{options.map(option => <option key={option.name} value={option.name}>{L(`계정 ${option.accounts}개`, `${option.accounts} account${option.accounts === 1 ? "" : "s"}`)}</option>)}</datalist>
        <span className="meta">{v.locked ? L("설치 설정 AWS_SSO_DISCOVERY_PERMISSION_SET에 고정되어 있습니다.", "Fixed by the installation's AWS_SSO_DISCOVERY_PERMISSION_SET.")
          : !nameOk ? L("권한 세트 이름은 32자 이내의 영문·숫자와 +=,.@_-입니다.", "A permission set name is up to 32 letters, digits and +=,.@_-.")
            : v.permission_set_updated_by ? whoChanged({ updated_by: v.permission_set_updated_by, updated_at: v.permission_set_updated_at }, L, locale, "")
              : L("자동 등록과 '지금 가져오기'는 이 권한 세트가 할당된 계정을 등록하고, 이미 등록된 Identity Center 계정도 이 권한 세트가 할당돼 있으면 이 권한 세트로 맞춥니다.",
                "Registration and Import now register the accounts this permission set is assigned in, and move registered Identity Center accounts it is assigned in onto it.")}</span>
      </div>
      <button type="button" className="ghost-btn" disabled={Boolean(working)} onClick={() => void read()}><Ic name="refresh" size={15} />{working === "probe" ? L("읽는 중", "Reading") : L("Identity Center에서 목록 읽기", "Read the list from Identity Center")}</button>
      <button type="button" className="primary-btn" disabled={busy || v.locked || !nameOk || name.trim() === current} onClick={() => void choose()}>{L("권한 세트 저장", "Save the permission set")}</button>
    </div>
    {probe && !probe.available ? <div className="ig-result bad"><Ic name="alert" size={16} />{probeText(probe, L)}</div> : null}
    {probe?.available && !options.length ? <p className="ig-sub">{L("이 로그인으로 읽을 수 있는 권한 세트가 없습니다.", "This sign-in holds no permission set CreMore can read.")}</p> : null}
    <Row title={L("할당된 계정 자동 등록", "Register assigned accounts")}
      text={v.discovery.enabled ? L(`켜져 있습니다. 워커가 ${v.interval_minutes}분마다 할당을 읽습니다.`, `On: the worker reads the assignments every ${v.interval_minutes} minutes.`)
        : L("켜면 워커가 이 권한 세트가 할당된 계정을 주기적으로 읽어 등록합니다.", "When on, the worker regularly registers the accounts this permission set is assigned in.")}
      state={!v.discovery.installation_allows ? L("설치 설정 AWS_SSO_DISCOVERY_MODE=disabled로 꺼 두었습니다.", "The installation's AWS_SSO_DISCOVERY_MODE=disabled keeps it off.")
        : !v.permission_set ? L("권한 세트를 저장해야 켤 수 있습니다.", "Save a permission set to turn it on.")
          : v.excluded_accounts.length ? L(`설치 설정에서 제외한 계정: ${v.excluded_accounts.join(", ")}`, `Excluded by the installation: ${v.excluded_accounts.join(", ")}`) : undefined}
      control={<Switch checked={v.discovery.switch} label={L("할당된 계정 자동 등록", "Assigned account registration")}
        disabled={busy || switchLocked(v.discovery.installation_allows, v.discovery.switch) || (!v.discovery.switch && !v.permission_set)}
        onChange={enabled => void save("settings/aws-identity-center", { discovery_enabled: enabled })} />} />
    <div className="aws-set-acts">
      <button type="button" className="ghost-btn" disabled={Boolean(working) || !v.permission_set} aria-label={L(`${importing}: 할당된 계정`, `${importing}: assigned accounts`)} onClick={() => void sweep()}>
        <Ic name="refresh" size={15} />{importing}</button>
    </div>
  </div>;
}

/* ---------- automatic credential inventory (what to collect: issuance inventory) ---------- */

export function AwsInventory({ regionOptions }: { regionOptions: { id: string; label: string }[] }) {
  const L = useL();
  const view = useApi<InventoryView>("settings/aws-credential-inventory");
  const accounts = useApi<Account[]>("aws/accounts");
  const { busy, save } = useSave<InventoryView>(view.replace);
  const [form, setForm] = useState<InventoryForm | null>(null);
  const [fresh, setFresh] = useState(true);  // as in Organizations: the next view becomes the form
  useEffect(() => { if (view.data && fresh) { setForm(inventoryForm(view.data)); setFresh(false); } }, [view.data, fresh]);
  if (view.error) return <ErrorLine onRetry={view.reload}>{reasonText(view.error, L)}</ErrorLine>;
  if (!view.data || !form) return <Loading />;
  const v = view.data;
  const set = (change: Partial<InventoryForm>) => setForm(current => current ? { ...current, ...change } : current);
  const problem = inventoryProblem(form, L, Boolean(v.reason));
  const known = accounts.data ?? [];
  const unknown = form.accounts.filter(id => !known.some(account => account.account_id === id));
  const s3 = form.source === "s3";
  const store = async () => { if (await save("settings/aws-credential-inventory", inventoryBody(form, Boolean(v.reason)))) setFresh(true); };
  return <div className="aws-set-part">
    <Shared changed={v} />
    {!v.installation_allows ? <Banner tone="warn" icon="alert">{L("설치 설정 SCAN_SCHEDULES_MODE=disabled로 자동 수집을 꺼 두었습니다.", "The installation's SCAN_SCHEDULES_MODE=disabled keeps automatic collection off.")}</Banner> : null}
    {v.reason ? <Banner tone="warn" icon="alert">{L("저장된 설정을 읽지 못해 기본값을 보여 줍니다. 다시 저장합니다.", "The saved settings could not be read, so defaults are shown. Save again.")}</Banner> : null}
    <label className="set-check"><input type="checkbox" checked={form.enabled} disabled={busy || (!v.installation_allows && !form.enabled)} onChange={event => set({ enabled: event.target.checked })} />
      <span>{L("AWS 발급 목록을 정기 수집합니다.", "Collect the AWS inventory on a schedule.")}</span></label>
    <div className="row2">
      <TextField label={L("수집 간격 (분)", "Interval (minutes)")} type="number" inputMode="numeric" value={form.interval} onChange={value => set({ interval: value })} min="5" max="10080" />
      <div className="field">
        <label htmlFor="aws-inv-scope">{L("계정 범위", "Accounts")}</label>
        <select id="aws-inv-scope" value={form.all ? "all" : "some"} onChange={event => set({ all: event.target.value === "all" })}>
          <option value="all">{L("앞으로 추가되는 계정까지 모든 승인된 계정", "Every approved account, including ones added later")}</option>
          <option value="some">{L("고른 계정만", "Only the chosen accounts")}</option>
        </select>
      </div>
    </div>
    {!form.all ? <div className="aws-set-accounts">
      {known.map(account => { const on = form.accounts.includes(account.account_id); return <button type="button" key={account.account_id} className="ig-feat-card" role="checkbox" aria-checked={on}
        onClick={() => set({ accounts: on ? form.accounts.filter(id => id !== account.account_id) : [...form.accounts, account.account_id] })}>
        <Check on={on} /><span className="ig-feat-text"><span className="t">{account.name}</span><span className="d mono">{account.account_id}</span></span></button>; })}
      {!known.length ? <p className="ig-sub">{L("등록된 AWS 계정이 없습니다.", "No AWS account is registered.")}</p> : null}
      {unknown.map(id => <button type="button" key={id} className="ig-feat-card" role="checkbox" aria-checked
        onClick={() => set({ accounts: form.accounts.filter(account => account !== id) })}>
        <Check on /><span className="ig-feat-text"><span className="t">{L("지금 목록에 없는 계정", "Not listed now")}</span><span className="d mono">{id}</span></span></button>)}
    </div> : null}
    <label className="set-check"><input type="checkbox" checked={form.cloudtrail} disabled={busy} onChange={event => set({ cloudtrail: event.target.checked })} />
      <span>{L("CloudTrail에서 관측된 세션도 수집합니다.", "Also collect sessions observed in CloudTrail.")}</span></label>
    {form.cloudtrail ? <>
      <div className="row2">
        <div className="field">
          <label htmlFor="aws-inv-source">{L("CloudTrail 수집 경로", "CloudTrail source")}</label>
          <select id="aws-inv-source" value={form.source} onChange={event => set({ source: event.target.value, window: event.target.value === "event_history" && Number(form.window) > 90 ? "90" : form.window })}>
            <option value="event_history">{L("Event History · 리전별 관리 이벤트(최근 90일)", "Event History · regional management events (last 90 days)")}</option>
            <option value="s3">{L("S3에 쌓인 기존 CloudTrail 로그", "Existing CloudTrail logs in S3")}</option>
          </select>
        </div>
        <TextField label={L("조회 기간 (일)", "Window (days)")} type="number" inputMode="numeric" value={form.window} onChange={value => set({ window: value })} min="1" max={s3 ? "3650" : "90"} />
      </div>
      <MultiSelectField label={L("리전", "Regions")} value={words(form.regions)} options={regionOptions} onChange={value => set({ regions: value.join(", ") })}
        hint={L("계정에서 활성화한 리전을 선택하세요. 전체 선택은 리전 활성화나 권한 승인이 아닙니다.", "Choose regions enabled in the account. Select all does not enable regions or grant access.")} />
      {s3 ? <div className="row2">
        <TextField label={L("기존 Trail 버킷", "Existing trail bucket")} value={form.bucket} onChange={value => set({ bucket: value })} />
        <div className="field">
          <label htmlFor="aws-inv-prefixes">{L("읽을 로그 prefix (줄마다 하나)", "Log prefixes to read (one per line)")}</label>
          <textarea id="aws-inv-prefixes" className="short mono" value={form.prefixes} onChange={event => set({ prefixes: event.target.value })} placeholder="AWSLogs/o-abcd123456/111111111111/CloudTrail/" />
        </div>
      </div> : null}
      <p className="ig-sub">{s3 ? L("승인된 계정 역할로, 적은 prefix 안의 기존 로그만 읽습니다.", "Reads existing logs only under the listed prefixes, with the approved account role.")
        : L("Event History는 리전별 관리 이벤트를 최근 90일까지만 줍니다.", "Event History gives regional management events for the last 90 days only.")}</p>
    </> : null}
    {problem ? <div className="ig-result bad"><Ic name="alert" size={16} />{problem}</div> : null}
    <div className="aws-set-acts">
      <button type="button" className="primary-btn" disabled={busy || Boolean(problem)} onClick={() => void store()}>{busy ? L("저장 중", "Saving") : L("수집 설정 저장", "Save the collection settings")}</button>
      {v.effective ? <StateChip tone="ok">{L("정기 수집 중", "Collecting on schedule")}</StateChip> : <StateChip>{L("정기 수집 꺼짐", "Not scheduled")}</StateChip>}
    </div>
  </div>;
}

/* ---------- read-only investigations ---------- */

// What each investigation reads, in the account a discovered credential belongs to (investigation_switches.py).
export const INVESTIGATIONS: { key: keyof Investigations; env: string; title: [string, string]; text: [string, string] }[] = [
  { key: "usage_lookup", env: "AWS_USAGE_LOOKUP_MODE", title: ["발견한 키의 실제 사용 내역", "Observed use of a discovered key"],
    text: ["CloudTrail 이벤트 기록과 iam:GetAccessKeyLastUsed로, 계정의 사용 중인 리전에서 발견한 액세스 키가 최근 90일 동안 한 일을 봅니다.",
      "CloudTrail event history and iam:GetAccessKeyLastUsed show what a discovered access key did in the last 90 days, across the account's enabled Regions."] },
  { key: "potential_access", env: "IAM_POTENTIAL_ACCESS_MODE", title: ["잠재 접근 권한 시뮬레이션", "Potential access simulation"],
    text: ["발견한 주체의 정해진 작업 목록을 시뮬레이션하며 실제 접근 권한 검증은 아닙니다. 발급 목록의 정책 메타데이터는 연결의 수집 옵션에서 설정합니다. 아직 해당 옵션을 저장하지 않은 기존 연결만 이 스위치를 따릅니다.",
      "Simulates a fixed action list for discovered principals; not effective access verification. Set inventory policy metadata in the connection's collection options. Only legacy connections without that saved option still follow this switch."] },
  { key: "secrets_inventory", env: "AWS_SECRETS_INVENTORY_MODE", title: ["Secrets Manager 인벤토리·메타데이터", "Secrets Manager inventory and metadata"],
    text: ["ListSecrets·DescribeSecret·ListSecretVersionIds로 비밀의 메타데이터를 읽습니다.",
      "ListSecrets, DescribeSecret and ListSecretVersionIds read the secrets' metadata."] },
];

/** The investigations a feature offers: the discovered key's use and potential access with the issuance inventory,
 * the Secrets Manager metadata with the secret comparison. Each reads, when on, in the account the discovered
 * credential belongs to, with the scanner identity. */
export function AwsInvestigations({ keys }: { keys: (keyof Investigations)[] }) {
  const L = useL();
  const view = useApi<Investigations>("settings/aws-investigations");
  const { busy, save } = useSave<Investigations>(view.replace);
  if (view.error) return <ErrorLine onRetry={view.reload}>{reasonText(view.error, L)}</ErrorLine>;
  if (!view.data) return <Loading />;
  return <div className="aws-set-part">
    <AwsInvestigationFields data={view.data} keys={keys} disabled={busy}
      onChange={(key, enabled) => void save("settings/aws-investigations", { [key]: enabled })} />
    <Shared />
  </div>;
}

export function AwsInvestigationFields({ data, keys, edits = {}, disabled, onChange }: {
  data: Investigations; keys: (keyof Investigations)[]; edits?: InvestigationEdits; disabled?: boolean;
  onChange: (key: keyof Investigations, enabled: boolean) => void;
}) {
  const L = useL();
  const locale = useLocale();
  return <>
    {INVESTIGATIONS.filter(item => keys.includes(item.key)).map(item => { const one = data[item.key]; return <Row key={item.key} title={L(...item.title)} text={L(...item.text)}
      state={!one.installation_allows ? L(`설치 설정 ${item.env}=disabled로 꺼 두었습니다.`, `The installation's ${item.env}=disabled keeps it off.`) : whoChanged(one, L, locale, L("기본값: 꺼짐", "Off by default"))}
      control={<Switch checked={edits[item.key]?.enabled ?? one.switch} label={L(...item.title)} disabled={disabled || switchLocked(one.installation_allows, one.switch)}
        onChange={enabled => onChange(item.key, enabled)} />} />; })}
  </>;
}

/* ---------- the identity approved key actions run as (sign in: next to the scanning identity) ---------- */

export function AwsKeyActionIdentity({ regionOptions }: { regionOptions: { id: string; label: string }[] }) {
  const L = useL();
  const locale = useLocale();
  const toast = useToast();
  const saved = useSaved();
  const view = useApi<RemediationView>("aws/remediation-identity", { every: 0 });
  const [roleArn, setRoleArn] = useState("");
  const [region, setRegion] = useState("");
  const [busy, setBusy] = useState(false);
  // Approving again replaces the approval key actions run under, so it is asked twice. The question takes focus and
  // hands it back to the approve button when answered.
  const [confirming, setConfirming] = useState(false);
  const approveButton = useRef<HTMLButtonElement>(null);
  const [refocus, setRefocus] = useState(false);
  useEffect(() => { if (refocus) { approveButton.current?.focus(); setRefocus(false); } }, [refocus]);
  if (view.error) return <ErrorLine onRetry={view.reload}>{reasonText(view.error, L)}</ErrorLine>;
  if (!view.data) return <Loading />;
  const v = view.data;
  const needs = v.api.requires ?? null;
  const ready = v.api.state === "READY" && (v.approvable === null || Boolean(needs));
  const missing = (needs === "ROLE_ARN" && !roleArn.trim()) || (needs === "IDENTITY_CENTER_REGION" && !REGION.test(region.trim()));
  const approve = async () => {
    setBusy(true);
    try {
      view.replace(await send<RemediationView>("aws/remediation-identity", "PUT", { confirm: true, ...(roleArn.trim() ? { role_arn: roleArn.trim() } : {}), ...(region.trim() ? { sso_region: region.trim() } : {}) }));
      saved(); toast(L("키 조치 신원을 승인했습니다", "Approved the key action identity"));
    } catch (reason) { toast(refusalText(reason instanceof Error ? reason.message : "", L, v.identity_source) || reasonText(reason, L), "bad"); } finally {
      setBusy(false);
      if (confirming) { setConfirming(false); setRefocus(true); }
    }
  };
  const who = (kind: string | null | undefined, set: string | null | undefined, account: string | null | undefined) => `${kindName(kind, set, L)} · ${account ?? ""}`;
  const by = v.approved?.approved_by;
  const approvedBy = !by ? "" : by === "local operator" ? L("로컬 관리자", "Local admin") : actorLabel(by, L);
  return <div className="aws-set-part">
    <p className="ig-sub">{v.identity_source === "remediator"
      ? L(`독립 실행 승인을 받은 키 조치는 전용 조치 프로세스가 각 계정의 조치 역할(${v.remediation_role_name})을 맡아 실행합니다. 아래에는 그 프로세스가 보고한 신원이 표시됩니다.`,
        `Key actions with independent execution approval run in the dedicated remediation process, assuming each account's action role (${v.remediation_role_name}). Its reported identity appears below.`)
      : L(`승인된 키 조치(비활성화·삭제)는 API가 ${v.profile ? `AWS 프로필 ${v.profile}` : "기본 AWS 로그인"}으로 계정마다의 조치 역할(${v.remediation_role_name})을 맡아 실행합니다. 스캔과 다른 신원(AWS_REMEDIATION_PROFILE)을 권장합니다.`,
        `Approved key actions (disable, delete) run in the API with ${v.profile ? `the AWS profile ${v.profile}` : "the default AWS sign-in"}, assuming each account's action role (${v.remediation_role_name}). A separate identity from scanning (AWS_REMEDIATION_PROFILE) is recommended.`)}</p>
    {v.same_as_scanner ? <Banner tone="warn" icon="alert">{L("스캔 신원이 키 조치에도 쓰입니다. 가능하면 별도 권한 세트나 프로필을 씁니다.", "The scanning identity also runs key actions. Use a separate permission set or profile where you can.")}</Banner> : null}
    <dl className="kv set-kv">
      <dt>{v.identity_source === "remediator" ? L("조치 프로세스", "Remediation process") : L("API 프로세스", "API process")}</dt>
      <dd>{v.api.state === "READY" ? <>{who(v.api.kind, v.api.permission_set, v.api.account_id)}{v.api.principal_arn ? <div className="mono wrap-t ig-sub">{v.api.principal_arn}</div> : null}</>
        : <span className="ig-result bad"><Ic name="alert" size={15} />{refusalText(v.api.error_code ?? v.api.state, L, v.identity_source)}</span>}</dd>
      <dt>{L("승인된 신원", "Approved identity")}</dt>
      <dd>{v.approved ? <>{who(v.approved.kind, v.approved.permission_set, v.approved.account_id)}
        {approvedBy ? <div className="ig-sub">{L(`승인: ${approvedBy}`, `Approved by ${approvedBy}`)}{v.approved.approved_at ? ` · ${rel(v.approved.approved_at, locale)}` : ""}</div> : null}</>
        : <span className="subtle">{L("아직 승인하지 않았습니다", "Not approved yet")}</span>}</dd>
    </dl>
    {v.approvable && !needs ? <div className="ig-result bad"><Ic name="alert" size={16} />{refusalText(v.approvable, L, v.identity_source)}</div> : null}
    {ready && needs === "ROLE_ARN" ? <TextField label={L("키 조치 신원이 맡은 IAM 역할의 정확한 ARN (경로 포함)", "The exact IAM role ARN (with path) the key action identity runs as")} value={roleArn} onChange={setRoleArn} placeholder="arn:aws:iam::111111111111:role/path/RoleName" /> : null}
    {ready && needs === "IDENTITY_CENTER_REGION" ? <SelectField label={L("키 조치 신원의 IAM Identity Center 리전", "IAM Identity Center Region of the key action identity")} value={region} onChange={setRegion}
      options={[{ id: "", label: L("리전을 선택하세요", "Select a region") }, ...regionOptions]} /> : null}
    <div role="status">{confirming ? <Banner tone="warn" icon="alert">{v.identity_source === "remediator"
      ? L("승인된 신원을 위 조치 프로세스의 신원으로 바꿉니다. 이후 승인된 키 조치는 이 신원으로 실행됩니다.", "The approved identity is replaced by the remediation process's identity above; approved key actions then run as it.")
      : L("승인된 신원을 위 API 프로세스의 신원으로 바꿉니다. 이후 키 조치는 이 신원으로 실행됩니다.",
        "The approved identity is replaced by the API process's identity above; key actions then run as it.")}</Banner> : null}</div>
    <div className="aws-set-acts">
      {confirming ? <>
        <button type="button" className="primary-btn" disabled={busy} onClick={() => void approve()}>{L("승인 바꾸기", "Replace the approval")}</button>
        <button type="button" className="ghost-btn" disabled={busy} autoFocus onClick={() => { setConfirming(false); setRefocus(true); }}>{L("취소", "Cancel")}</button>
      </> : <button type="button" className="primary-btn" ref={approveButton} disabled={busy || !ready || missing} onClick={() => { if (v.approved) setConfirming(true); else void approve(); }}>
        {v.approved ? L("지금 신원으로 다시 승인", "Approve the current identity") : L("이 신원 승인", "Approve this identity")}</button>}
      <button type="button" className="ghost-btn" disabled={busy} onClick={view.reload}><Ic name="refresh" size={15} />{L("다시 확인", "Check again")}</button>
      <button type="button" className="ghost-btn" onClick={() => copy(JSON.stringify(v.policy, null, 2), toast, L)}>
        <Ic name="copy" size={15} />{L("이 신원에 필요한 정책 복사", "Copy the policy this identity needs")}</button>
    </div>
    <Shared />
  </div>;
}
