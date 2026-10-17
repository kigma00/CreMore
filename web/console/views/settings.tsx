"use client";

/* Settings: how this installation behaves, for an Admin. How people sign in (settings/sign-in, set in the
 * installation's configuration) and this device's display timezone; whether discovered credentials are verified and
 * what a verified token may be used for; what starts a scan (schedules, change feeds, the customer's own queues);
 * auto-triage by learned false-positive profiles; and what this installation holds itself (settings/local-credentials).
 * The API records every change in the audit trail. ?section= picks login | verification | triggers | triage | local. */

import { type ReactNode, useState } from "react";

import { credentialTypeLabel } from "@/components/labels";
import { type DisplayTimezone, setDisplayTimezone, useDisplayTimezone } from "@/components/display-timezone";
import { useLocale } from "@/components/locale";
import { reasonText, send, useApi, useSaved } from "@/console/data";
import { Modal, useToast } from "@/console/layer";
import { actorLabel } from "@/console/labels";
import { Logo, serviceName } from "@/console/logos";
import type { ViewProps } from "@/console/shell";
import { NotionWebhooks } from "@/console/views/notion-webhooks";
import { DetectionAlerts } from "@/console/views/settings-alerts";
import { clock, FULL_SCHEDULES, fullScanText, shiftMinute, zoneName, zoneOffset } from "@/console/views/integrations/targets-model";
import { fmtDT, type Say, useL } from "@/console/text";
import { Banner, Card, CardBody, EmptyRow, ErrorLine, Loading, PageHead, Seg, StateChip, Switch, Tabs } from "@/console/ui";

type Section = "login" | "verification" | "triggers" | "triage" | "local";
const SECTIONS: Section[] = ["login", "verification", "triggers", "triage", "local"];

export type Changed = { updated_by: string | null; updated_at: string | null };
export type Toggle = Changed & { enabled: boolean; switch: boolean; installation_allows: boolean };
type Role = "viewer" | "analyst" | "remediator" | "admin";
/** Google sign-in carries no groups: the worker reads the role groups from Google Workspace (cremore.identity.sign_in_groups). */
export type RoleGroups = { source: "WORKSPACE_GROUPS"; domain: string | null; read_at: string | null; tried_at: string | null;
  code: string | null; groups: Partial<Record<Role, { group: string; members: number | null; code?: string | null }>> };
export type SignInView = { mode: string; issuer: string | null; audience: string | null; groups_claim: string | null;
  groups: Record<Role, string | null> | null; role_groups?: RoleGroups | null };

const ROLE_GROUP_PROBLEMS: Record<string, [string, string]> = {
  GOOGLE_WORKSPACE_PEOPLE_DIRECTORY_REQUIRED: ["역할 그룹은 Google Workspace 사람 목록 연결로 읽습니다. 연동 서비스의 디렉터리 동기화에서 연결하세요.",
    "Role groups are read through the Google Workspace people connection. Connect it from Directory sync on the Integrations page."],
  GOOGLE_WORKSPACE_DELEGATION_NOT_ALLOWED: ["최고 관리자가 관리 콘솔 > 보안 > 액세스 및 데이터 관리 > API 제어 > 도메인 전체 위임 관리에서 그 연결의 클라이언트 ID에 https://www.googleapis.com/auth/admin.directory.group.member.readonly 범위를 더하세요. 적용까지 최대 24시간 걸릴 수 있습니다.",
    "A super admin adds https://www.googleapis.com/auth/admin.directory.group.member.readonly to that connection's client ID under Admin console > Security > Access and data control > API controls > Manage Domain Wide Delegation. It can take up to 24 hours to apply."],
  GOOGLE_WORKSPACE_HTTP_404: ["Workspace에 없는 그룹 주소가 있습니다. 역할별 그룹(OIDC_ADMIN_GROUP 등)을 확인하세요.",
    "A group address is not in Workspace. Check the role groups (OIDC_ADMIN_GROUP and the rest)."],
  SECRET_UNAVAILABLE: ["Google Workspace 연결의 자격증명을 열지 못했습니다. 그 연결의 자격증명을 다시 저장하세요.",
    "The Google Workspace connection's credential could not be opened. Save that connection's credential again."],
};

/** What stops the role groups from being read, in words; null when nothing does. */
export function roleGroupProblem(code: string | null | undefined, L: Say): string | null {
  if (!code) return null;
  const known = ROLE_GROUP_PROBLEMS[code];
  return known ? L(known[0], known[1]) : L(`역할 그룹을 읽지 못했습니다(${code}). 워커가 몇 분 뒤 다시 읽습니다.`, `The role groups could not be read (${code}). The worker reads them again in a few minutes.`);
}
export type QueueKind = "sqs";
export type Queue = { enabled: boolean; switch: boolean; installation_allows: boolean; profile_id: string; profile_id_locked: boolean;
  dedicated_acknowledged: boolean; dedicated_acknowledged_locked: boolean; blocked_by: string | null } & Record<string, unknown>;
export type Triggers = Changed & {
  schedules: { enabled: boolean; switch: boolean; installation_allows: boolean; full_scan_default_minutes: number; full_scan_start_minute: number };
  change_feeds: { enabled: boolean; switch: boolean; installation_allows: boolean; minutes: Record<string, number> };
} & Record<QueueKind, Queue>;
type Bindable = { id: string; name: string; version: number; connection: string; schedule_minutes: number };
export type Triage = Changed & { enabled: boolean; switch: boolean; installation_allows: boolean; threshold: number; threshold_locked: boolean;
  min_samples: number; min_samples_locked: boolean; max_confidence: string; max_confidence_locked: boolean; confidence_levels: string[];
  min_sample_floor: number };
type Profile = { id: string; account_name: string; source_type: string; detector_name: string; credential_type: string; sample_count: number;
  distinct_actors: number; contradictions: number; min_samples: number; active: boolean; threshold: number; updated_at: string };

// Each queue CreMore may read: the field holding its address, what arrives there and the one role its reader needs.
export const QUEUES: Record<QueueKind, { address: string; name: string; placeholder: string; text: [string, string] }> = {
  sqs: { address: "queue_url", name: "Amazon SQS", placeholder: "https://sqs.<region>.amazonaws.com/<account>/<queue>",
    text: ["S3 이벤트 알림(EventBridge·CloudTrail 포함)이나 코드 저장소 push 웹훅을 전달한 메시지를 읽어 바뀐 곳만 검사합니다. worker에는 이 큐의 ReceiveMessage·DeleteMessage·ChangeMessageVisibility 권한만 필요합니다.",
      "Reads S3 event notifications (EventBridge and CloudTrail included) and relayed code host push webhooks, and scans only what changed. The worker needs ReceiveMessage, DeleteMessage and ChangeMessageVisibility on this queue alone."] },
};
// Why a queue switched on is not read yet (cremore/scanning/trigger_settings.py blocked_by).
export function blockedText(code: string | null, L: Say): string | null {
  if (!code) return null;
  if (code.endsWith("_NOT_ACKNOWLEDGED")) return L("이 큐가 CreMore 전용임을 확인해야 읽습니다. 업무용 공용 큐는 읽지 않습니다.", "Confirm the queue is CreMore's own before it is read. A shared business queue is never read.");
  if (code.endsWith("_PROFILE_NOT_BOUND")) return L("승인된 범위 프로필을 고르면 그 범위의 알림만 받습니다.", "Choose an approved scope profile; only its notifications are accepted.");
  if (code.endsWith("_MISSING")) return L("정확한 주소를 넣습니다. CreMore는 큐를 스스로 찾지 않습니다.", "Enter the exact address. CreMore never looks for a queue.");
  return code;
}
// Providers whose change feed an Admin can pace (cremore/scanning/trigger_settings.py CHANGE_FEED_PROVIDERS).
export const FEED_PROVIDERS = ["github", "notion"];

/** The start times an Admin chooses from: each hour of the day on the display zone's clock, stored as the UTC minute it
 * is now (plus the saved minute when it is not on the hour there), in the order the clock reads. */
export function startChoices(saved: number, zone: DisplayTimezone, at = new Date()): { id: string; label: string }[] {
  const offset = zoneOffset(zone, at);
  const minutes = new Set([...Array.from({ length: 24 }, (_, hour) => shiftMinute(hour * 60, -offset)), saved]);
  return [...minutes].sort((a, b) => shiftMinute(a, offset) - shiftMinute(b, offset))
    .map(minute => ({ id: String(minute), label: clock(shiftMinute(minute, offset)) }));
}
export const CONFIDENCE: Record<string, [string, string]> = { low: ["낮음까지", "Up to low"], medium: ["보통까지", "Up to medium"], high: ["높음까지", "Up to high"] };

export function whoChanged(view: Changed, L: Say, locale: "ko" | "en", fallback: string) {
  if (!view.updated_by) return fallback;
  const by = view.updated_by === "local operator" ? L("로컬 관리자", "Local admin") : actorLabel(view.updated_by, L);
  return L(`마지막 변경: ${by}${view.updated_at ? ` · ${fmtDT(view.updated_at, locale)}` : ""}`, `Last changed by ${by}${view.updated_at ? ` · ${fmtDT(view.updated_at, locale)}` : ""}`);
}

/** A switch the installation locks off still turns off: an Admin can clear a choice before the lock is lifted. */
export function switchLocked(allows: boolean, on: boolean) {
  return !allows && !on;
}

/** What a typed number does when its field is left: nothing typed or the saved value -> "keep"; outside the range
 * -> "invalid" (the typed text stays, marked, until corrected); else "save". */
export function typedNumber(typed: string | null, saved: number, min: number, max: number): "keep" | "invalid" | "save" {
  if (typed === null) return "keep";
  const value = Number(typed.trim());
  if (!/^\d+$/.test(typed.trim()) || value < min || value > max) return "invalid";
  return value === saved ? "keep" : "save";
}

export function Row({ title, text, state, control, children }: { title: ReactNode; text: ReactNode; state?: ReactNode; control?: ReactNode; children?: ReactNode }) {
  return <div className="set-row">
    <div className="set-text"><b>{title}</b><p>{text}</p>{state ? <div className="set-state">{state}</div> : null}{children}</div>
    {control}
  </div>;
}

/** A PUT whose answer is the new view: shown at once, the rest of the console told, a refusal in words. */
export function useSave<T>(replace: (value: T) => void) {
  const L = useL();
  const toast = useToast();
  const saved = useSaved();
  const [busy, setBusy] = useState(false);
  const save = async (path: string, body: unknown, done?: string) => {
    setBusy(true);
    try {
      replace(await send<T>(path, "PUT", body));
      saved();
      toast(done ?? L("저장했습니다", "Saved"));
      return true;
    } catch (reason) {
      toast(reasonText(reason, L), "bad");
      return false;
    } finally { setBusy(false); }
  };
  return { busy, save };
}

export function Settings({ route, setParams }: ViewProps) {
  const L = useL();
  const asked = route.params.get("section") ?? "";
  const section: Section = (SECTIONS as string[]).includes(asked) ? asked as Section : "login";
  return <>
    <PageHead title={L("환경 설정", "Settings")} meta={L("이 설치가 어떻게 동작하는지", "How this installation behaves")} />
    <Tabs value={section} label={L("설정 영역", "Settings area")} onChange={next => setParams({ section: next === "login" ? null : next })}
      items={[{ id: "login" as const, label: L("로그인·표시", "Sign-in and display") }, { id: "verification" as const, label: L("검증", "Verification") },
        { id: "triggers" as const, label: L("스캔 시작 조건", "What starts a scan") }, { id: "triage" as const, label: L("자동 오탐 처리", "Auto-triage") },
        { id: "local" as const, label: L("설치가 보유한 키", "Keys held here") }]} />
    {section === "login" ? <SignIn /> : section === "verification" ? <Verification /> : section === "triggers" ? <ScanTriggers />
      : section === "triage" ? <AutoTriage /> : <HeldHere />}
  </>;
}

/* ---------- sign-in and display ---------- */

function SignIn() {
  const L = useL();
  const view = useApi<SignInView>("settings/sign-in");
  const zone = useDisplayTimezone();
  const locale = useLocale();
  const data = view.data;
  const oidc = data?.mode === "oidc";
  const workspace = data?.role_groups ?? null;
  const problem = roleGroupProblem(workspace?.code, L);
  const roles: [Role, string][] = [["admin", L("관리자", "Admin")], ["remediator", L("조치 담당자", "Remediator")],
    ["analyst", L("분석가", "Analyst")], ["viewer", L("조회자", "Viewer")]];
  return <>
    <Card title={L("CreMore 로그인", "CreMore sign-in")} id="set-login" className="list-card">
      <CardBody>
        {view.error ? <ErrorLine onRetry={view.reload}>{reasonText(view.error, L)}</ErrorLine> : !data ? <Loading /> : <>
          <Row title={L("로그인 방식", "Sign-in method")}
            text={workspace ? L("직원이 회사 Google 계정으로 로그인합니다. Google 토큰에는 그룹이 없어, 워커가 Google Workspace 역할 그룹의 구성원을 몇 분마다 읽고 API가 토큰의 확인된 회사 주소로 역할을 정합니다. 어느 그룹에도 없는 사람은 들어오지 못합니다.",
              "Staff sign in with their company Google account. Google tokens carry no groups, so the worker reads the Google Workspace role groups' members every few minutes and the API takes the role from the token's verified company address; someone in no role group gets no access.")
              : oidc ? L("직원이 회사 IdP 계정으로 로그인합니다. API가 토큰의 발급자·서명·대상·만료를 직접 확인하고, 그룹 클레임의 그룹으로 역할을 정합니다. 맞는 그룹이 없는 사람은 들어오지 못합니다.",
              "Staff sign in with their company IdP account. The API checks each token's issuer, signature, audience and expiry itself and takes the role from the groups claim; someone in no mapped group gets no access.")
              : L("이 설치의 API 토큰으로 로그인하는 단독 운영 방식입니다. 모든 작업이 로컬 관리자 한 사람의 이름으로 기록됩니다.",
                "A single operator signs in with this installation's API token. Every action is recorded under the one local admin.")}
            control={<StateChip tone={oidc ? "ok" : undefined}>{oidc ? L("회사 계정(OIDC)", "Company account (OIDC)") : L("로컬 로그인", "Local sign-in")}</StateChip>} />
          {oidc ? <dl className="kv set-kv">
            <dt>{L("발급자", "Issuer")}</dt><dd className="mono wrap-t">{data.issuer}</dd>
            <dt>{L("대상(audience)", "Audience")}</dt><dd className="mono wrap-t">{data.audience}</dd>
            {workspace ? <><dt>{L("역할 그룹", "Role groups")}</dt>
              <dd>{L(`Google Workspace${workspace.domain ? ` (${workspace.domain})` : ""}의 그룹 구성원 · `, `Members of Google Workspace${workspace.domain ? ` (${workspace.domain})` : ""} groups · `)}
                {workspace.read_at ? L(`마지막으로 읽음 ${fmtDT(workspace.read_at, locale)}`, `last read ${fmtDT(workspace.read_at, locale)}`)
                  : L("아직 읽지 않음", "not read yet")}</dd></>
              : <><dt>{L("그룹 클레임", "Groups claim")}</dt><dd className="mono">{data.groups_claim}</dd></>}
            {roles.map(([role, name]) => <RoleGroup key={role} name={name} group={data.groups?.[role] ?? null}
              members={workspace ? workspace.groups[role]?.members ?? null : undefined} unread={Boolean(workspace?.groups[role]?.code)} />)}
          </dl> : null}
          {problem ? <Banner tone="warn" icon="alert">{problem}</Banner> : null}
          <p className="set-note">{L("로그인 방식은 설치 설정에서 정합니다. 회사 계정으로 바꾸려면 API에 AUTH_MODE=oidc와 OIDC_ISSUER_URL·OIDC_AUDIENCE·역할별 그룹(OIDC_ADMIN_GROUP 등)을, 웹에 CREMORE_AUTH_MODE=oidc를 넣습니다. Compose는 deploy/compose/reverse-proxy의 oauth2-proxy 구성을, Kubernetes는 Helm 차트의 auth.oidc를 씁니다.",
            "The sign-in method is set in the installation's configuration. For company accounts, give the API AUTH_MODE=oidc with OIDC_ISSUER_URL, OIDC_AUDIENCE and the role groups (OIDC_ADMIN_GROUP and the rest), and the web CREMORE_AUTH_MODE=oidc. Compose uses the oauth2-proxy setup in deploy/compose/reverse-proxy, Kubernetes the Helm chart's auth.oidc.")}</p>
        </>}
      </CardBody>
    </Card>
    <Card title={L("화면 표시", "Display")} className="list-card">
      <CardBody>
        <Row title={L("표시 시간대", "Display timezone")}
          text={L("이 기기에서 시각을 보여 줄 시간대입니다. 저장된 시각과 예약의 시간대는 바뀌지 않습니다.", "The timezone this device shows times in. Stored times and schedules are unchanged.")}
          control={<Seg value={zone} label={L("표시 시간대", "Display timezone")} onChange={setDisplayTimezone}
            options={[{ id: "Asia/Seoul", label: "KST" }, { id: "UTC", label: "UTC" }, { id: "LOCAL", label: L("기기 시간", "Device") }]} />} />
      </CardBody>
    </Card>
  </>;
}

/** ``members``: how many people the worker last found in a Workspace role group (undefined: the token names the groups). */
function RoleGroup({ name, group, members, unread }: { name: string; group: string | null; members?: number | null; unread?: boolean }) {
  const L = useL();
  return <><dt>{name}</dt><dd>{group ? <><span className="mono">{group}</span>
    {members === undefined ? null : <span className="subtle">{unread ? L(" · 읽지 못함 · 이 그룹으로 들어오는 사람이 없습니다", " · could not be read · nobody signs in with it")
      : members === null ? L(" · 아직 읽지 않음", " · not read yet") : L(` · ${members}명`, ` · ${members} ${members === 1 ? "person" : "people"}`)}</span>}</>
    : <span className="subtle">{L("지정 안 함 · 이 역할로 들어오는 사람이 없습니다", "Not set · nobody signs in with this role")}</span>}</dd></>;
}

/* ---------- verification ---------- */

function Verification() {
  const L = useL();
  const locale = useLocale();
  const verify = useApi<Toggle>("settings/credential-verification");
  const probe = useApi<Toggle>("settings/capability-probe");
  const cross = useApi<Toggle>("settings/cross-host-verification");
  const saves = { verify: useSave<Toggle>(verify.replace), probe: useSave<Toggle>(probe.replace), cross: useSave<Toggle>(cross.replace) };
  const failed = verify.error || probe.error || cross.error;
  if (failed) return <ErrorLine onRetry={() => { verify.reload(); probe.reload(); cross.reload(); }}>{reasonText(failed, L)}</ErrorLine>;
  if (!verify.data || !probe.data || !cross.data) return <Loading />;
  const on = verify.data.enabled;
  const extra = (view: Toggle, lock: string) => !view.installation_allows ? lock
    : view.switch && !on ? L("검증이 꺼져 있어 지금은 하지 않습니다.", "Verification is off, so this does not run now.")
      : whoChanged(view, L, locale, L("기본값: 꺼짐", "Off by default"));
  return <Card title={L("발견한 자격증명 검증", "Verifying discovered credentials")} id="set-verification" className="list-card">
    <CardBody>
      <Row title={L("공급자에 유효한지 확인", "Check with the provider whether it works")}
        text={L("노출된 자격증명이 지금 쓸 수 있는지 발급한 공급자에 읽기 전용으로 물어 위험도와 조치 순서에 씁니다.", "Asks the issuing provider, read-only, whether an exposed credential works now; the answer sets its risk and what to do first.")}
        state={!verify.data.installation_allows ? L("설치 설정 CREDENTIAL_VERIFICATION_MODE=disabled로 꺼 두었습니다.", "The installation's CREDENTIAL_VERIFICATION_MODE=disabled keeps it off.")
          : whoChanged(verify.data, L, locale, L("기본값: 켜짐", "On by default"))}
        control={<Switch checked={verify.data.switch} label={L("공급자 검증", "Provider verification")} disabled={saves.verify.busy || switchLocked(verify.data.installation_allows, verify.data.switch)}
          onChange={enabled => void saves.verify.save("settings/credential-verification", { enabled })} />} />
      <Row title={L("검증된 토큰이 닿는 범위 확인", "Record what a verified token reaches")}
        text={L("공급자가 권한을 알려 주지 않는 토큰(GitHub 세분화 PAT, Notion 통합)으로 읽기 전용 호출을 몇 번 해 닿는 범위를 기록합니다.", "Makes a few read-only calls with a token whose provider does not report its permissions (GitHub fine-grained PATs, Notion integrations) to record what it reaches.")}
        state={extra(probe.data, L("설치 설정에서 잠겨 있습니다. 검증과 CREDENTIAL_CAPABILITY_PROBE_MODE가 켜져 있어야 합니다.", "Locked by the installation: it needs verification and CREDENTIAL_CAPABILITY_PROBE_MODE."))}
        control={<Switch checked={probe.data.switch} label={L("접근 범위 확인", "Reach probe")} disabled={saves.probe.busy || switchLocked(probe.data.installation_allows, probe.data.switch)}
          onChange={enabled => void saves.probe.save("settings/capability-probe", { enabled })} />} />
      <Row title={L("다른 GitHub 호스트에서도 확인", "Also check other GitHub hosts")}
        text={L("GitHub 토큰이 발견된 호스트에서 거부되면 등록한 다른 GitHub 호스트(Enterprise Server 포함)에도 물어 봅니다. 토큰을 서버 한 곳에 더 보냅니다.", "When the host a GitHub token was found on rejects it, also asks the other registered GitHub hosts (Enterprise Server included). The token goes to one more server.")}
        state={extra(cross.data, L("설치 설정에서 잠겨 있습니다. 검증과 CREDENTIAL_CROSS_HOST_VERIFICATION이 켜져 있어야 합니다.", "Locked by the installation: it needs verification and CREDENTIAL_CROSS_HOST_VERIFICATION."))}
        control={<Switch checked={cross.data.switch} label={L("교차 호스트 확인", "Cross-host check")} disabled={saves.cross.busy || switchLocked(cross.data.installation_allows, cross.data.switch)}
          onChange={enabled => void saves.cross.save("settings/cross-host-verification", { enabled })} />} />
    </CardBody>
  </Card>;
}

/* ---------- what starts a scan ---------- */

function ScanTriggers() {
  const L = useL();
  const locale = useLocale();
  const zone = useDisplayTimezone();
  const view = useApi<Triggers>("settings/scan-triggers");
  const bindable = useApi<Bindable[]>("settings/scan-triggers/bindable-profiles");
  const { busy, save } = useSave<Triggers>(view.replace);
  if (view.error) return <ErrorLine onRetry={view.reload}>{reasonText(view.error, L)}</ErrorLine>;
  if (!view.data) return <Loading />;
  const t = view.data;
  const put = (body: Record<string, unknown>) => save("settings/scan-triggers", body);
  // One record holds every trigger, so who changed it last is said once. Schedules and change feeds are on until an
  // Admin switches them off here; a queue is off until switched on.
  const state = (allows: boolean, name: string, on: boolean, onByDefault = false) => !allows
    ? L(`설치 설정 SCAN_${name}_MODE=disabled로 꺼 두었습니다.`, `The installation's SCAN_${name}_MODE=disabled keeps it off.`)
    : on ? undefined : onByDefault ? L("관리자가 껐습니다. 켤 때까지 실행하지 않습니다.", "An Admin switched it off. Nothing runs until it is switched on.")
      : L("기본값: 꺼짐", "Off by default");
  // Not known until read: a bound profile is never called "no longer bindable" while the list loads or fails.
  const profiles = Array.isArray(bindable.data) ? bindable.data : null;
  return <>
    <Card title={L("예약과 변경 감지", "Schedules and change feeds")} id="set-triggers" className="list-card" meta={t.updated_by ? whoChanged(t, L, locale, "") : undefined}
      info={L("관리자가 승인한 범위 프로필만 실행하며, 어떤 조건도 범위를 넓히지 않습니다.", "Only scope profiles an Admin approved run, and no trigger widens a scope.")}>
      <CardBody>
        <Row title={L("예약 검사", "Scheduled scans")}
          text={L("로그인한 사람이 없어도 서버가 승인된 모든 범위를 아래 기본 주기로 전체 검사하고, 검사 대상에 정한 변경분 주기로 바뀐 곳을 검사합니다. 검사 대상에 전체 검사 주기를 따로 정한 범위는 그 주기를 씁니다. 끄면 예약 검사는 실행하지 않습니다.",
            "Without anyone signed in, the server scans every approved scope in full at the default cadence below and checks what changed at the incremental schedule set on its targets. A scope with its own full-scan cadence uses that. Off, no scheduled scan runs.")}
          state={state(t.schedules.installation_allows, "SCHEDULES", t.schedules.switch, true)}
          control={<Switch checked={t.schedules.switch} label={L("예약 검사", "Scheduled scans")} disabled={busy || switchLocked(t.schedules.installation_allows, t.schedules.switch)}
            onChange={next => void put({ schedules_enabled: next })} />}>
          {t.schedules.switch ? <>
            <div className="set-grid">
              <div className="field">
                <label htmlFor="full-scan-default">{L("전체 검사 기본 주기", "Default full scan")}</label>
                <select id="full-scan-default" value={String(t.schedules.full_scan_default_minutes)} disabled={busy}
                  onChange={event => void put({ full_scan_default_minutes: Number(event.target.value) })}>
                  {FULL_SCHEDULES.map(minutes => <option key={minutes} value={minutes}>{fullScanText(minutes, L)}</option>)}
                </select>
              </div>
              <div className="field">
                <label htmlFor="full-scan-start">{L(`시작 시각 (${zoneName(zone, L)})`, `Start time (${zoneName(zone, L)})`)}</label>
                <select id="full-scan-start" value={String(t.schedules.full_scan_start_minute)} disabled={busy}
                  onChange={event => void put({ full_scan_start_minute: Number(event.target.value) })}>
                  {startChoices(t.schedules.full_scan_start_minute, zone).map(choice => <option key={choice.id} value={choice.id}>{choice.label}</option>)}
                </select>
              </div>
            </div>
            <p className="set-note">{L("전체 검사는 시작 시각부터 주기마다 실행합니다. 하루 2회면 시작 시각과 12시간 뒤에 실행합니다. 한꺼번에 몰리지 않도록 범위마다 정해진 시각에, 시작 시각부터 최대 4시간 뒤(주기가 8시간보다 짧으면 주기의 절반) 사이에 시작하며 이 시각은 매번 같습니다. 검사 대상에 전체 검사 주기를 따로 정한 범위도 같은 시작 시각부터 셉니다. 시각은 이 기기의 표시 시간대로 보이고 서버에는 UTC로 저장됩니다.",
              "Full scans run from the start time at every interval: twice a day runs at the start time and 12 hours later. So they do not all start at once, each scope starts at its own fixed time between the start time and up to 4 hours later (half the interval when it is shorter than 8 hours), the same every time. A scope with its own full-scan cadence counts from the same start time. Times show in this device's display timezone and are stored in UTC.")}</p>
          </> : null}
        </Row>
        <Row title={L("변경 감지", "Change feeds")}
          text={L("GitHub·Notion의 바뀐 곳을 공급자별 주기로 확인해 그곳만 검사합니다. 새 연동의 범위는 ‘변경되면 검사’가 켜진 채 저장됩니다.",
            "Checks GitHub and Notion for changes at each provider's interval and scans only what changed. A new integration's scopes are saved with 'Scan when it changes' on.")}
          state={state(t.change_feeds.installation_allows, "CHANGE_FEEDS", t.change_feeds.switch, true)}
          control={<Switch checked={t.change_feeds.switch} label={L("변경 감지", "Change feeds")} disabled={busy || switchLocked(t.change_feeds.installation_allows, t.change_feeds.switch)}
            onChange={next => void put({ change_feeds_enabled: next })} />}>
          {t.change_feeds.switch ? <div className="set-grid">
            {FEED_PROVIDERS.map(provider => <FeedMinutes key={provider} provider={provider} value={t.change_feeds.minutes[provider] ?? 5} disabled={busy}
              onSave={minutes => put({ change_feed_minutes: { ...t.change_feeds.minutes, [provider]: minutes } })} />)}
          </div> : null}
        </Row>
        <p className="set-note">{L("서로 다른 연결의 검사는 worker 동시 실행 수만큼 함께 진행합니다. 한 연결 안에서는 변경 알림 검사가 진행 중인 전체 검사와 나란히 돌고, 같은 버킷·저장소·페이지를 동시에 두 번 읽지 않습니다.",
          "Scans of different connections run at the same time, up to the worker concurrency. Within one connection a change-event scan runs beside a full scan in progress, and the same bucket, repository or page is never read twice at once.")}</p>
      </CardBody>
    </Card>
    <NotionWebhooks />
    <Card title={L("고객 큐의 알림", "Notifications from your queue")} className="list-card"
      info={L("CreMore 전용으로 만든 큐 하나만 읽고, 결과 작업이 모두 저장된 뒤에만 메시지를 처리 완료합니다.", "Only a queue made for CreMore is read; a message is settled only after every resulting job is stored.")}>
      <CardBody>
        {bindable.error ? <ErrorLine onRetry={bindable.reload}>{reasonText(bindable.error, L)}</ErrorLine> : null}
        {(Object.keys(QUEUES) as QueueKind[]).map(kind => <QueueRow key={kind} kind={kind} queue={t[kind]} profiles={profiles} busy={busy}
          state={state(t[kind].installation_allows, kind.toUpperCase(), t[kind].switch)} put={put} />)}
        {profiles && !profiles.length ? <p className="set-note">{L("큐에 묶을 수 있는 범위 프로필이 없습니다. 연동 서비스의 검사 대상에서 ‘변경되면 검사’를 켜고 저장하면 여기에 나타납니다.",
          "No scope profile can be bound yet. Turn on 'Scan when it changes' in an integration's scan targets and save; it appears here.")}</p> : null}
      </CardBody>
    </Card>
    <DetectionAlerts />
  </>;
}

function FeedMinutes({ provider, value, disabled, onSave }: { provider: string; value: number; disabled: boolean; onSave: (minutes: number) => Promise<boolean> }) {
  const L = useL();
  const [typed, setTyped] = useState<string | null>(null);
  const verdict = typedNumber(typed, value, 1, 1440);
  // What was typed stays until it is saved: a refusal or an out-of-range number is not silently put back.
  const commit = async () => {
    if (verdict === "keep") setTyped(null);
    else if (verdict === "save" && await onSave(Number(typed))) setTyped(null);
  };
  const id = `feed-${provider}`;
  return <label className="set-feed" htmlFor={id}>
    <Logo id={provider} size={22} /><span className="set-feed-name">{serviceName(provider)}</span>
    <input id={id} type="number" inputMode="numeric" min={1} max={1440} step={1} value={typed ?? String(value)} disabled={disabled}
      aria-invalid={verdict === "invalid" || undefined} onChange={event => setTyped(event.target.value)} onBlur={() => void commit()}
      onKeyDown={event => { if (event.key === "Enter") event.currentTarget.blur(); }} />
    {verdict === "invalid" ? <span className="set-warn">{L("1~1440분", "1-1440 min")}</span> : <span className="subtle">{L("분마다", "min")}</span>}
  </label>;
}

function QueueRow({ kind, queue, profiles, busy, state, put }: {
  kind: QueueKind; queue: Queue; profiles: Bindable[] | null; busy: boolean; state: string | undefined; put: (body: Record<string, unknown>) => Promise<boolean>;
}) {
  const L = useL();
  const spec = QUEUES[kind];
  const address = String(queue[spec.address] ?? "");
  const [typed, setTyped] = useState<string | null>(null);
  const listed = profiles ?? [];
  const bound = queue.profile_id && !listed.some(p => p.id === queue.profile_id)
    ? profiles === null ? L("고른 프로필", "The chosen profile") : L("더 이상 묶을 수 없는 프로필", "A profile no longer bindable") : null;
  const fixed = L("설치 설정에 고정되어 있습니다.", "Fixed by the installation's configuration.");
  const commit = async () => {
    if (typed === null || typed.trim() === address) { setTyped(null); return; }
    if (await put({ [`${kind}_${spec.address}`]: typed.trim() })) setTyped(null);
  };
  const blocked = queue.switch ? blockedText(queue.blocked_by, L) : null;
  return <Row title={spec.name} text={L(...spec.text)} state={blocked ? <span className="set-warn">{blocked}</span> : state}
    control={<Switch checked={queue.switch} label={spec.name} disabled={busy || switchLocked(queue.installation_allows, queue.switch)} onChange={next => void put({ [`${kind}_enabled`]: next })} />}>
    {queue.switch ? <div className="set-grid wide">
      <div className="field">
        <label htmlFor={`${kind}-profile`}>{L("승인된 범위 프로필", "Approved scope profile")}</label>
        <select id={`${kind}-profile`} value={queue.profile_id} disabled={busy || queue.profile_id_locked}
          onChange={event => void put({ [`${kind}_profile_id`]: event.target.value })}>
          <option value="">{L("프로필 고르기", "Choose a profile")}</option>
          {bound ? <option value={queue.profile_id}>{bound}</option> : null}
          {listed.map(p => <option key={p.id} value={p.id}>{p.connection ? `${p.connection} · ` : ""}{p.name} · v{p.version}</option>)}
        </select>
        {queue.profile_id_locked ? <span className="meta">{fixed}</span> : null}
      </div>
      <div className="field">
        <label htmlFor={`${kind}-address`}>{L("정확한 주소", "Exact address")}</label>
        <input id={`${kind}-address`} className="mono" value={typed ?? address} placeholder={spec.placeholder} maxLength={512} autoComplete="off" spellCheck={false}
          disabled={busy || Boolean(queue[`${spec.address}_locked`])} onChange={event => setTyped(event.target.value)} onBlur={() => void commit()}
          onKeyDown={event => { if (event.key === "Enter") event.currentTarget.blur(); }} />
        {queue[`${spec.address}_locked`] ? <span className="meta">{fixed}</span> : null}
      </div>
      <label className="set-check">
        <input type="checkbox" checked={queue.dedicated_acknowledged} disabled={busy || queue.dedicated_acknowledged_locked}
          onChange={event => void put({ [`${kind}_dedicated_acknowledged`]: event.target.checked })} />
        <span>{L("이 큐는 CreMore 전용이며 업무 시스템이 쓰는 큐가 아닙니다.", "This queue exists only for CreMore, not for a business workload.")}</span>
      </label>
    </div> : null}
  </Row>;
}

/* ---------- auto-triage ---------- */

function AutoTriage() {
  const L = useL();
  const locale = useLocale();
  const view = useApi<Triage>("settings/learned-false-positives");
  const profiles = useApi<Profile[]>("rules/learned-fp");
  const { busy, save } = useSave<Triage>(view.replace);
  const toast = useToast();
  const saved = useSaved();
  const [acting, setActing] = useState<string | null>(null);
  const [clearing, setClearing] = useState<Profile | null>(null);
  const [threshold, setThreshold] = useState<string | null>(null);
  const [samples, setSamples] = useState<string | null>(null);
  if (view.error) return <ErrorLine onRetry={view.reload}>{reasonText(view.error, L)}</ErrorLine>;
  if (!view.data) return <Loading />;
  const v = view.data;
  const put = (body: Record<string, unknown>) => save("settings/learned-false-positives", body);
  const fixed = (locked: boolean) => (locked ? L("설치 설정에 고정되어 있습니다.", "Fixed by the installation's configuration.") : undefined);
  const savedPercent = Math.round(v.threshold * 100);
  const percentVerdict = typedNumber(threshold, savedPercent, 1, 100);
  const countVerdict = typedNumber(samples, v.min_samples, v.min_sample_floor, 1000);
  // What was typed stays until it is saved: a refusal or an out-of-range number is not silently put back.
  const commitThreshold = async () => {
    if (percentVerdict === "keep") setThreshold(null);
    else if (percentVerdict === "save" && await put({ threshold: Number(threshold) / 100 })) setThreshold(null);
  };
  const commitSamples = async () => {
    if (countVerdict === "keep") setSamples(null);
    else if (countVerdict === "save" && await put({ min_samples: Number(samples) })) setSamples(null);
  };
  const act = async (profile: Profile, action: "deactivate" | "reset") => {
    setActing(profile.id);
    try {
      await send(`rules/learned-fp/${encodeURIComponent(profile.id)}/${action}`, "POST");
      saved(); profiles.reload();
      toast(action === "reset" ? L("표본을 비웠습니다", "Samples cleared") : L("자동 처리를 멈췄습니다", "Auto-triage stopped"));
    } catch (reason) { toast(reasonText(reason, L), "bad"); } finally { setActing(null); }
  };
  const list = Array.isArray(profiles.data) ? profiles.data : [];
  return <>
    <Card title={L("학습한 오탐으로 자동 처리", "Auto-triage by learned false positives")} id="set-triage" className="list-card">
      <CardBody>
        <Row title={L("자동 오탐 처리", "Auto-triage")}
          text={L("분석가가 오탐으로 확정한 결과에서 위치·가려진 줄 모양만 배워, 같은 범위에서 같은 맥락이 다시 나오면 오탐으로 닫습니다. 값은 배우지 않고, 닫은 결과는 다시 열 수 있습니다.",
            "Learns only the location and masked line shape of results analysts confirmed as false positives, and closes a repeat of the same context in the same scope. No value is learned, and a closed result can be reopened.")}
          state={!v.installation_allows ? L("설치 설정 LEARNED_FP_MODE=disabled로 꺼 두었습니다.", "The installation's LEARNED_FP_MODE=disabled keeps it off.") : whoChanged(v, L, locale, L("기본값: 꺼짐", "Off by default"))}
          control={<Switch checked={v.switch} label={L("자동 오탐 처리", "Auto-triage")} disabled={busy || switchLocked(v.installation_allows, v.switch)} onChange={enabled => void put({ enabled })} />} />
        <div className="set-grid">
          <div className="field">
            <label htmlFor="fp-threshold">{L("닮은 정도 기준(%)", "Similarity needed (%)")}</label>
            <input id="fp-threshold" type="number" inputMode="numeric" min={1} max={100} value={threshold ?? String(savedPercent)} disabled={busy || v.threshold_locked}
              aria-invalid={percentVerdict === "invalid" || undefined} onChange={event => setThreshold(event.target.value)} onBlur={() => void commitThreshold()}
              onKeyDown={event => { if (event.key === "Enter") event.currentTarget.blur(); }} />
            {percentVerdict === "invalid" ? <span className="meta set-warn">{L("1부터 100까지의 정수로 넣습니다.", "Enter a whole number from 1 to 100.")}</span>
              : <span className="meta">{fixed(v.threshold_locked) ?? L("배운 맥락과 이만큼 닮아야 닫습니다.", "A result closes only when it is at least this similar.")}</span>}
          </div>
          <div className="field">
            <label htmlFor="fp-samples">{L("필요한 확정 수", "Confirmations needed")}</label>
            <input id="fp-samples" type="number" inputMode="numeric" min={v.min_sample_floor} max={1000} value={samples ?? String(v.min_samples)} disabled={busy || v.min_samples_locked}
              aria-invalid={countVerdict === "invalid" || undefined} onChange={event => setSamples(event.target.value)} onBlur={() => void commitSamples()}
              onKeyDown={event => { if (event.key === "Enter") event.currentTarget.blur(); }} />
            {countVerdict === "invalid" ? <span className="meta set-warn">{L(`${v.min_sample_floor}부터 1,000까지의 정수로 넣습니다.`, `Enter a whole number from ${v.min_sample_floor} to 1,000.`)}</span>
              : <span className="meta">{fixed(v.min_samples_locked) ?? L(`${v.min_sample_floor}건 이상, 서로 다른 분석가 2명 이상이 확정해야 켜집니다.`, `At least ${v.min_sample_floor}, from at least two different analysts.`)}</span>}
          </div>
          <div className="field">
            <label htmlFor="fp-confidence">{L("닫을 수 있는 탐지 신뢰도", "Detections it may close")}</label>
            <select id="fp-confidence" value={v.max_confidence} disabled={busy || v.max_confidence_locked} onChange={event => void put({ max_confidence: event.target.value })}>
              {v.confidence_levels.map(level => <option key={level} value={level}>{L(...(CONFIDENCE[level] ?? [level, level]))}</option>)}
            </select>
            <span className="meta">{fixed(v.max_confidence_locked) ?? L("이보다 신뢰도가 높은 탐지는 닫지 않습니다.", "A detection more confident than this is never closed.")}</span>
          </div>
        </div>
      </CardBody>
    </Card>
    <Card title={L("학습한 오탐 프로필", "Learned profiles")} className="list-card" meta={list.length ? L(`켜짐 ${list.filter(p => p.active).length} · 전체 ${list.length}`, `${list.filter(p => p.active).length} active · ${list.length} in all`) : undefined}>
      {profiles.error ? <CardBody><ErrorLine onRetry={profiles.reload}>{reasonText(profiles.error, L)}</ErrorLine></CardBody> : <div className="table-wrap"><table className="tbl set-tbl">
        <thead><tr><th>{L("유형·범위", "Type and scope")}</th><th>{L("확정", "Confirmed")}</th><th>{L("상태", "State")}</th><th className="col-sm">{L("바뀐 때", "Updated")}</th><th><span className="sr">{L("작업", "Actions")}</span></th></tr></thead>
        <tbody>
          {list.length ? list.map(p => <tr key={p.id}>
            <td><div className="cred-cell"><Logo id={p.source_type} size={26} /><div className="cred-text"><div className="cred-name">{credentialTypeLabel(p.credential_type, locale)}</div>
              <div className="cred-hint">{p.account_name} · {p.detector_name}</div></div></div></td>
            <td className="num">{L(`${p.sample_count}/${p.min_samples}건 · 분석가 ${p.distinct_actors}명`, `${p.sample_count}/${p.min_samples} · ${p.distinct_actors} analyst${p.distinct_actors === 1 ? "" : "s"}`)}</td>
            <td>{p.active ? <StateChip tone="ok">{L("자동 처리 중", "Auto-triaging")}</StateChip>
              : <StateChip tip={p.contradictions ? L("분석가가 자동으로 닫은 결과를 다시 열었거나 관리자가 멈췄습니다. 다음 확정부터 다시 배웁니다.",
                "An analyst reopened a result it closed, or an Admin stopped it. It learns again from the next confirmation.") : undefined}>
                {p.contradictions ? L("멈춤", "Stopped") : L("배우는 중", "Learning")}</StateChip>}</td>
            <td className="col-sm">{fmtDT(p.updated_at, locale)}</td>
            <td><div className="dm-acts">
              {p.active ? <button type="button" className="ghost-btn" disabled={acting === p.id} onClick={() => void act(p, "deactivate")}>{L("멈추기", "Stop")}</button> : null}
              <button type="button" className="ghost-btn" disabled={acting === p.id || !p.sample_count} onClick={() => setClearing(p)}>{L("표본 비우기", "Clear samples")}</button>
            </div></td>
          </tr>) : <EmptyRow colSpan={5}>{v.enabled ? L("아직 프로필이 없습니다. 분석가가 오탐으로 확정하면 범위별로 배웁니다.", "No profile yet. Analysts' confirmed false positives are learned per scope.")
            : L("자동 오탐 처리를 켜면 분석가의 오탐 확정에서 배우기 시작합니다.", "Once auto-triage is on, it learns from analysts' confirmed false positives.")}</EmptyRow>}
        </tbody>
      </table></div>}
    </Card>
    {clearing ? <Modal onClose={() => setClearing(null)} labelledBy="fp-clear-title" size="narrow" dismissable={acting !== clearing.id}>
      <h2 id="fp-clear-title">{L("표본 비우기", "Clear samples")} <small>{credentialTypeLabel(clearing.credential_type, locale)}</small></h2>
      <p className="ig-sub">{L(`이 프로필이 배운 확정 ${clearing.sample_count}건을 지웁니다. 자동 처리는 멈추고, 다음 확정부터 처음부터 다시 배웁니다.`,
        `Deletes the ${clearing.sample_count} confirmation${clearing.sample_count === 1 ? "" : "s"} this profile learned from. Auto-triage stops, and it learns from scratch from the next confirmation.`)}</p>
      <div className="modal-foot">
        <button type="button" className="ghost-btn" disabled={acting === clearing.id} onClick={() => setClearing(null)}>{L("취소", "Cancel")}</button>
        <button type="button" className="primary-btn" disabled={acting === clearing.id} onClick={async () => { await act(clearing, "reset"); setClearing(null); }}>{L("비우기", "Clear")}</button>
      </div>
    </Modal> : null}
  </>;
}

/* ---------- what this installation holds ---------- */

export type LocalCredentialItem = { name: string; where: string; held_here: boolean; rotatable: boolean; reason: string };
export type LocalCredentials = {
  sealing: { root: string; held_here: boolean; key_id: string | null; openers: number | null; unreachable: string | null };
  items: LocalCredentialItem[]; reasons: string[];
};
const ROOTS: Record<string, [string, string]> = {
  VAULT: ["Vault", "금고"], KMS: ["AWS KMS", "AWS KMS"], PASSPHRASE: ["Configured passphrase", "설정된 패스프레이즈"],
  ENVIRONMENT: ["This installation's environment", "이 설치의 환경변수"], FINGERPRINT_KEY: ["Derived from the fingerprint key", "지문 키에서 파생"],
  WORKLOAD_IDENTITY: ["Workload identity", "워크로드 신원"],
};
const REASONS: Record<string, [string, string]> = {
  SEALING_MASTER_CANNOT_ROTATE: ["No sealing key is set, so the master is derived from the fingerprint key — which cannot rotate.", "봉인 키가 설정되지 않아 마스터가 지문 키에서 파생됩니다 — 지문 키는 회전할 수 없습니다."],
  SEALING_MASTER_HELD_HERE: ["The current sealing master is derived from secret material in this installation's configuration.", "현재 봉인 마스터는 이 설치의 설정에 있는 비밀값에서 파생됩니다."],
  SEALING_KEY_HELD_HERE: ["A displaced sealing key remains configured as an opener.", "이전 봉인 키가 복호화용으로 설정에 남아 있습니다."],
  SEALING_PASSPHRASE_HELD_HERE: ["A displaced passphrase remains configured as an opener.", "이전 패스프레이즈가 복호화용으로 설정에 남아 있습니다."],
  SEALING_KEY_PREVIOUS_HELD_HERE: ["Previous sealing keys remain in configuration.", "이전 봉인 키들이 설정에 남아 있습니다."],
  SEALING_PASSPHRASE_PREVIOUS_HELD_HERE: ["Previous passphrases remain in configuration.", "이전 패스프레이즈들이 설정에 남아 있습니다."],
  SEALING_ROOT_UNREACHABLE: ["The configured root could not be reached, so the key in use could not be named.", "설정된 뿌리에 닿지 못해 현재 사용 중인 키를 확인하지 못했습니다."],
  SECRET_STORE_TOKEN_HELD_HERE: ["A static secret store token is in configuration; SECRET_STORE_AUTH_MODE=kubernetes removes it.", "비밀 저장소의 고정 토큰이 설정에 있습니다. SECRET_STORE_AUTH_MODE=kubernetes로 바꾸면 없어집니다."],
};
// Why each input is listed, in Korean; the API's own sentence is the English (cremore/secretstore/stored_locally.py).
const MASTER_WHY: Record<string, string> = {
  VAULT: "설정에는 참조만 있고, 받아 온 마스터는 프로세스 메모리에서 씁니다.",
  KMS: "설정에는 암호문이 있고, 여는 데 kms:Decrypt가 필요하며 프로세스 메모리에서 씁니다.",
  PASSPHRASE: "설정한 패스프레이즈로 프로세스 메모리에서 마스터를 만듭니다. 그 원본이 디스크에 남았는지는 이 프로세스가 알 수 없습니다.",
  ENVIRONMENT: "마스터 자체가 이 설치의 환경변수에 있습니다.",
  FINGERPRINT_KEY: "봉인 원본을 정하지 않아 FINGERPRINT_KEY에서 마스터를 만듭니다. 이 키는 회전하면 저장된 지문이 모두 끊겨 회전할 수 없습니다.",
};
const ITEM_WHY: Record<string, string> = {
  FINGERPRINT_KEY: "저장된 지문의 키입니다. 회전하면 기록된 일치가 모두 끊기므로 그대로 둡니다.",
  API_TOKEN: "이 설치가 인증에 쓰는 공유 토큰입니다. 시작할 때마다 만들어 환경변수로 넘기거나, AUTH_MODE=oidc로 바꾸면 없어집니다.",
  DATABASE_URL: "데이터베이스 연결 문자열입니다. 자격증명을 담을 수 있고, 네트워크상 위치를 뜻하지는 않습니다.",
};
export function itemWhy(item: LocalCredentialItem, root: string, locale: "ko" | "en"): string {
  if (locale !== "ko") return item.reason;
  if (item.name === "sealing master") return MASTER_WHY[root] ?? item.reason;
  if (item.name === "SECRET_STORE_TOKEN") return item.held_here ? "비밀 저장소의 고정 토큰입니다. SECRET_STORE_AUTH_MODE=kubernetes로 바꾸면 없어집니다." : "투영된 서비스 계정 토큰으로 임대를 받아 씁니다.";
  if (item.name.startsWith("SEALING_")) return item.held_here ? "이전 자격증명을 열기 위해 남은 값입니다. 디스크 저장 여부는 알 수 없습니다." : "외부 원본을 가리키는 이전 열쇠입니다. 받아 온 값은 프로세스 메모리에서 씁니다.";
  return ITEM_WHY[item.name] ?? item.reason;
}

/** A recorded value, never a guess: the API reports one of a fixed set. */
export function rootLabel(value: string, locale: "ko" | "en") {
  return ROOTS[value]?.[locale === "ko" ? 1 : 0] ?? value;
}
export function localCredentialReason(code: string, locale: "ko" | "en") {
  return REASONS[code]?.[locale === "ko" ? 1 : 0] ?? code;
}
/** How many values this installation holds itself, rather than pointing at. */
export function keptLocally(view: LocalCredentials) {
  return view.items.filter(item => item.held_here).length;
}
const localItem = (value: unknown): LocalCredentialItem | null => {
  const one = value as LocalCredentialItem;
  return one && typeof one.name === "string" && typeof one.where === "string" && typeof one.held_here === "boolean"
    && typeof one.rotatable === "boolean" && typeof one.reason === "string" ? one : null;
};
/** The payload, or null when it is not one this API could have produced: an empty list would read as "nothing is
 * stored here", the opposite of the truth for a default install. */
export function projectLocalCredentials(value: unknown): LocalCredentials | null {
  const view = value as LocalCredentials;
  if (!view || typeof view !== "object" || Array.isArray(view)) return null;
  if (!view.sealing || typeof view.sealing.root !== "string" || typeof view.sealing.held_here !== "boolean") return null;
  if (!Array.isArray(view.items) || !Array.isArray(view.reasons)) return null;
  const items = view.items.map(localItem);
  if (items.some(one => one === null)) return null;
  if (view.reasons.some(reason => typeof reason !== "string")) return null;
  return { sealing: view.sealing, items: items as LocalCredentialItem[], reasons: view.reasons };
}

function HeldHere() {
  const L = useL();
  const locale = useLocale();
  const raw = useApi<unknown>("settings/local-credentials");
  if (raw.error) return <ErrorLine onRetry={raw.reload}>{reasonText(raw.error, L)}</ErrorLine>;
  if (raw.data === undefined) return <Loading />;
  const view = projectLocalCredentials(raw.data);
  if (!view) return <ErrorLine onRetry={raw.reload}>{L("설치의 설정을 읽지 못했습니다.", "The installation's configuration could not be read.")}</ErrorLine>;
  const held = keptLocally(view);
  return <>
    {view.reasons.length ? <Banner tone="warn" icon="alert"><span className="set-reasons">{view.reasons.map(code => <span key={code}>{localCredentialReason(code, locale)}</span>)}</span></Banner> : null}
    <Card title={L("이 설치가 직접 보유하는 것", "What this installation holds itself")} className="list-card" id="set-local"
      meta={<>{L("봉인 마스터", "Sealing master")}: <b>{rootLabel(view.sealing.root, locale)}</b>{view.sealing.key_id ? <> · <span className="mono">{view.sealing.key_id}</span></> : null}</>}>
      <div className="table-wrap"><table className="tbl set-tbl">
        <thead><tr><th>{L("입력", "Input")}</th><th>{L("어디서 오는지", "Where it comes from")}</th><th>{L("보유", "Held")}</th></tr></thead>
        <tbody>
          {view.items.length ? view.items.map(item => <tr key={item.name}>
            <td>{item.name === "sealing master" ? <b>{L("봉인 마스터", "Sealing master")}</b> : <b className="mono">{item.name}</b>}
              <div className="ig-sub">{itemWhy(item, view.sealing.root, locale)}</div></td>
            <td>{rootLabel(item.where, locale)}</td>
            <td>{item.held_here ? <StateChip tone="warn">{L("이 설치가 보유", "Held here")}</StateChip> : <StateChip tone="ok">{L("외부 원본", "External source")}</StateChip>}</td>
          </tr>) : <EmptyRow colSpan={3}>{L("설정에 값을 직접 둔 입력이 없습니다.", "No input keeps its value in the configuration.")}</EmptyRow>}
        </tbody>
      </table></div>
      <CardBody><p className="set-note">{L(`표시된 ${view.items.length}개 입력 중 ${held}개는 설정에서 값을 직접 보유합니다. 디스크 저장 여부는 알 수 없습니다. 외부 원본도 사용할 때 프로세스 메모리로 읽으며, 현재 키를 옮겨도 이전 복호화 키는 남습니다. docs/CREDENTIAL_ROOTS.md를 참고하세요.`,
        `${held} of the ${view.items.length} listed inputs are held directly in configuration. Disk persistence is unknown. External roots also resolve into process memory, and moving the current root does not remove previous openers. See docs/CREDENTIAL_ROOTS.md.`)}</p></CardBody>
    </Card>
  </>;
}
