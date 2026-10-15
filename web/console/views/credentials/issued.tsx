"use client";

/* An issued item as its service reported it (GET /api/v2/coverage/inventory/{entity}): what the issuance inventory
 * holds about one object -- a token, a key, a certificate, an app installation -- in the credential panel's
 * language: where it was collected, its state as the service gave it, the collections that saw it, its permissions and
 * the fields of the latest observation. Opened from a credential's issuance links, its menu and search. */

import { failureCodeLabel } from "@/components/labels";
import { type Locale, useLocale } from "@/components/locale";
import { reasonText, useApi } from "@/console/data";
import { Modal } from "@/console/layer";
import { Logo, serviceName } from "@/console/logos";
import { fmtDT, type Say, useL } from "@/console/text";
import { ErrorLine, Fact, Facts, Loading, StateChip } from "@/console/ui";

type Value = string | number | boolean | null;
export type IssuedFact = { name: string; state: "PRESENT" | "NULL" | "MISSING" | "INVALID"; value?: Value | Value[]; container?: "object" | "array" | null; children: IssuedFact[]; reason?: string | null };
type Permission = { kind: string; name: string; resource_kind: string; resource_id: string; effect: string; actions: string[]; conditions?: IssuedFact[] };
export type IssuedBody = {
  facts: IssuedFact[]; omissions: { path: string; reason: string }[]; permissions?: Permission[];
  provider_state?: string; normalized_state?: string; state_basis?: string;
};
type Collection = { connection_id: string; name: string; status: string; started_at?: string | null; finished_at?: string | null; reasons: string[] };
export type IssuedDetail = {
  entity: { id: string; provider: string; origin: string; tenant: string; tenant_confirmed: boolean; object_kind: string; object_id: string; purpose: string;
    observed_at: string | null; first_observed_at: string; summary: IssuedBody | null };
  collections: Collection[]; current_record?: { id: string; body: IssuedBody } | null; last_success_record?: { id: string; body: IssuedBody } | null;
};

const KINDS: Record<string, [string, string]> = {
  credential: ["Credential", "Credential"], principal: ["주체", "Principal"], installation: ["앱 설치", "App installation"], policy: ["정책", "Policy"],
  request: ["요청", "Request"], context: ["맥락", "Context"], public_key: ["공개 키", "Public key"], trust: ["신뢰 관계", "Trust"],
  vault_item: ["Secret 항목", "Secret item"], vault_version: ["Secret 버전", "Secret version"], runner: ["러너", "Runner"], resource: ["리소스", "Resource"],
  unknown: ["알 수 없는 항목", "Unknown object"],
};
const PURPOSES: Record<string, [string, string]> = {
  issuer_inventory: ["발급 목록 수집", "Issuance inventory"], vault_metadata: ["Secret 저장소", "Secret stores"],
  usage: ["사용 기록", "Usage"], identity_status: ["IdP 디렉터리(사람·앱)", "IdP directory (people, apps)"],
};
const STATES: Record<string, [string, string]> = {
  ACTIVE: ["활성", "Active"], INACTIVE: ["비활성", "Inactive"], EXPIRED: ["만료", "Expired"], REVOKED: ["폐기됨", "Revoked"],
  DELETED: ["삭제됨", "Deleted"], DISABLED: ["사용 중지", "Disabled"], PENDING: ["대기", "Pending"],
};
const BASES: Record<string, [string, string]> = { PROVIDER_REPORTED: ["서비스가 보고", "Reported by the service"], OBSERVED: ["관측으로 판단", "Judged from observation"] };
const PERMISSION_KINDS: Record<string, [string, string]> = {
  scope: ["범위", "Scope"], permission: ["권한", "Permission"], role: ["역할", "Role"], repository_grant: ["저장소 권한", "Repository grant"], restriction: ["제한", "Restriction"],
};
const EFFECTS: Record<string, [string, string]> = { ALLOW: ["허용", "Allow"], DENY: ["거부", "Deny"], UNKNOWN: ["알 수 없음", "Unknown"] };
// A permission's evaluation facts (GCP effective_access, Azure app_permissions): Google's answer replaces the effect,
// and what the answer rested on replaces a count of facts.
const VERDICTS: Record<string, [string, string]> = {
  can_access: ["접근 가능", "Can access"], cannot_access: ["접근 불가", "Cannot access"],
  unknown_info: ["정보 부족으로 판정 불가", "Undecided: missing information"],
  unknown_conditional: ["요청 조건에 따라 다름", "Depends on the request's conditions"], not_evaluated: ["판정하지 못함", "Not evaluated"],
};
// The codes a failed evaluation call keeps (gcp metadata/transport.py, azure entra/permissions.py).
const EVALUATION_ERRORS: Record<string, [string, string]> = {
  api_disabled: ["API가 꺼져 있음", "The API is off"],
  permission_denied_or_api_disabled: ["권한이 없거나 API가 꺼져 있음", "No permission, or the API is off"],
  permission_denied: ["권한 없음", "No permission"], authentication_failed: ["인증 실패", "Sign-in failed"],
  request_failed: ["요청 실패", "The request failed"], oversized_response: ["응답이 너무 큼", "The answer was too large"],
  invalid_response: ["응답 형식이 예상과 다름", "The answer did not have the expected shape"],
  invalid_pagination: ["다음 페이지가 목록 밖을 가리킴", "The next page pointed outside the listing"],
  permission_page_limit: ["페이지 한도 도달", "Reached the page limit"],
  permissions_truncated: ["권한이 250개를 넘어 나머지는 보관하지 않음", "More than 250 permissions; the rest were not kept"],
};
function evidence(facts: IssuedFact[] | undefined, L: Say, locale: Locale): string[] {
  const value = (name: string) => facts?.find(fact => fact.name === name && fact.state === "PRESENT")?.value;
  const error = value("error_code");
  return [value("deny_policies") === "denied" ? L("거부 정책 적용", "A deny policy applies") : "",
    value("membership_resolution") === "group_member" ? L("그룹으로 받음", "Through a group") : "",
    value("condition_present") === true ? L("조건부 할당", "Conditional assignment") : "",
    typeof error === "string" ? (EVALUATION_ERRORS[error] ? L(...EVALUATION_ERRORS[error])
      : error.startsWith("invalid_") ? L(...EVALUATION_ERRORS.invalid_response) : failureCodeLabel(error.toUpperCase(), locale)) : ""]
    .filter(Boolean);
}
const RUNS: Record<string, [string, string, "ok" | "partial" | "bad" | "running"]> = {
  COMPLETE: ["완료", "Complete", "ok"], PARTIAL: ["일부", "Partial", "partial"], FAILED: ["실패", "Failed", "bad"],
  RUNNING: ["수집 중", "Collecting", "running"], WAITING: ["대기", "Waiting", "running"], NOT_COLLECTED: ["수집 전", "Not collected", "partial"],
  UNKNOWN: ["알 수 없음", "Unknown", "partial"],
};
// Why a collection's view of the item may be out of date, as the store says it (metadata_store._collections_for_entities);
// its run's own reasons read as the collection screens word them (components/labels.tsx).
const COLLECTION_REASONS: Record<string, [string, string]> = {
  CONNECTION_DISABLED: ["수집이 꺼져 있음", "Collection is off"], CONNECTION_SCOPE_CHANGED: ["설정을 바꾼 뒤 아직 수집하지 않음", "Not collected since its settings changed"],
  STALE_COLLECTION: ["마지막 수집이 오래됨", "The last collection is stale"],
};
const label = (table: Record<string, [string, string]>, key: string, L: Say) => table[key] ? L(...table[key]) : key;

/** A collection's last run in words, with the chip's tone; an unknown status reads as itself. */
export function runText(status: string, L: Say): [string, "ok" | "partial" | "bad" | "running" | undefined] {
  const known = RUNS[status];
  return known ? [L(known[0], known[1]), known[2]] : [status, undefined];
}

/** The object's state: the normalized one, and the service's own word for it when that says more. */
export function stateText(body: IssuedBody | null | undefined, L: Say): string | null {
  if (!body) return null;
  const normal = STATES[body.normalized_state ?? ""];
  const own = body.provider_state && body.provider_state !== "UNKNOWN" && body.provider_state.toUpperCase() !== body.normalized_state ? body.provider_state : "";
  return [normal ? L(...normal) : "", own].filter(Boolean).join(" · ") || null;
}

/** One field of an observation as the service returned it: a value, a nested set, or why there is none. */
export function factValue(fact: IssuedFact, L: Say, locale: Locale): string | null {
  if (fact.state === "NULL") return L("값 없음", "No value");
  if (fact.state === "MISSING") return L("응답에 없음", "Not returned");
  if (fact.state !== "PRESENT") return L("형식 오류", "Malformed") + (fact.reason ? ` · ${failureCodeLabel(fact.reason, locale)}` : "");
  if (fact.children.length) return null;
  if (fact.container) return fact.container === "array" ? L("빈 목록", "Empty list") : L("빈 항목", "Empty object");
  if (fact.value === null || fact.value === undefined) return "—";
  return Array.isArray(fact.value) ? fact.value.map(String).join(", ") : String(fact.value);
}

function FactTree({ facts }: { facts: IssuedFact[] }) {
  const L = useL();
  const locale = useLocale();
  return <ul className="issued-facts">
    {facts.map((fact, index) => { const value = factValue(fact, L, locale); return <li key={`${fact.name}:${index}`}>
      <span className="issued-fact-name">{fact.name}</span>
      {value === null ? <FactTree facts={fact.children} />
        : <span className={fact.state === "PRESENT" ? "mono issued-fact-value" : "subtle issued-fact-value"}>{value}</span>}
    </li>; })}
  </ul>;
}

/** What the modal shows of one item, from the API's detail alone. */
export function IssuedDetailView({ d }: { d: IssuedDetail }) {
  const L = useL();
  const locale = useLocale();
  const current = d.current_record, success = d.last_success_record;
  const body = current?.body ?? d.entity.summary;
  const state = stateText(body, L);
  const permissions = current?.body.permissions ?? [];
  return <>
    <Facts>
      {/* Tenancy the service did not confirm is not shown as tenancy; the origin is where it was collected. */}
      <Fact label={L("서비스·수집 위치", "Service and origin")}>{serviceName(d.entity.provider)} · <span className="cell-wrap">{d.entity.tenant_confirmed && d.entity.tenant ? d.entity.tenant : d.entity.origin}</span></Fact>
      <Fact label={L("상태", "State")}>{state ?? <span className="subtle">{L("알 수 없음", "Unknown")}</span>}
        {body?.state_basis && BASES[body.state_basis] ? <span className="subtle"> · {L(...BASES[body.state_basis])}</span> : null}</Fact>
      <Fact label={L("처음 관측", "First observed")}>{fmtDT(d.entity.first_observed_at, locale)}</Fact>
      <Fact label={L("마지막 관측", "Last observed")}>{d.entity.observed_at ? fmtDT(d.entity.observed_at, locale) : <span className="subtle">{L("현재 관측 없음", "No current observation")}</span>}</Fact>
    </Facts>
    {d.collections.length ? <div className="ig-section">
      <div className="ig-section-head"><h3>{L("이 항목을 관측한 수집", "Collections that observed it")}</h3></div>
      <ul className="issued-runs">{d.collections.map(item => { const [text, tone] = runText(item.status, L); return <li key={item.connection_id}>
        <b>{item.name}</b> <StateChip tone={tone}>{text}</StateChip>
        <span className="subtle num"> {fmtDT(item.finished_at ?? item.started_at ?? null, locale)}</span>
        {item.reasons.length ? <div className="ig-sub">{item.reasons.map(code => COLLECTION_REASONS[code] ? L(...COLLECTION_REASONS[code]) : failureCodeLabel(code, locale)).join(" · ")}</div> : null}</li>; })}</ul>
    </div> : null}
    {permissions.length ? <div className="ig-section">
      <div className="ig-section-head"><h3>{L("권한과 범위", "Permissions and scopes")}</h3></div>
      <div className="sub-scroll"><table className="sub-tbl">
        <thead><tr><th>{L("이름", "Name")}</th><th>{L("효과", "Effect")}</th><th>{L("동작·리소스", "Actions and resource")}</th></tr></thead>
        <tbody>{permissions.map((item, index) => { const verdict = item.conditions?.find(fact => fact.name === "effective_access")?.value;
          return <tr key={`${item.name}:${index}`}>
          <td data-label={L("이름", "Name")}><code className="mono cell-wrap">{item.name}</code> <span className="subtle small">{label(PERMISSION_KINDS, item.kind, L)}</span></td>
          <td className="nowrap" data-label={L("효과", "Effect")}>{typeof verdict === "string" && VERDICTS[verdict] ? L(...VERDICTS[verdict]) : label(EFFECTS, item.effect, L)}</td>
          <td className="cell-wrap" data-label={L("동작·리소스", "Actions and resource")}>{[item.actions.join(", "), item.resource_id ? `${item.resource_kind || L("리소스", "Resource")}: ${item.resource_id}` : "",
            ...evidence(item.conditions, L, locale)].filter(Boolean).join(" · ") || "—"}</td>
        </tr>; })}</tbody>
      </table></div>
    </div> : null}
    {current ? <div className="ig-section">
      <div className="ig-section-head"><h3>{L("현재 관측", "Current observation")}</h3></div>
      <FactTree facts={current.body.facts} />
      {current.body.omissions.length ? <p className="ig-sub">{L("저장하지 않은 필드: ", "Fields not stored: ")}{current.body.omissions.map(item => `${item.path} (${failureCodeLabel(item.reason, locale)})`).join(", ")}</p> : null}
    </div> : null}
    {success && success.id !== current?.id ? <div className="ig-section">
      <div className="ig-section-head"><h3>{L("마지막 성공 관측", "Last successful observation")}</h3></div>
      <FactTree facts={success.body.facts} />
    </div> : null}
  </>;
}

export function IssuedItemModal({ entityId, onClose }: { entityId: string; onClose: () => void }) {
  const L = useL();
  const view = useApi<IssuedDetail>(`v2/coverage/inventory/${encodeURIComponent(entityId)}?limit=1`);
  const d = view.data;
  return <Modal onClose={onClose} labelledBy="issued-title" className="integ">
    <h2 id="issued-title">{d ? <Logo id={d.entity.provider} size={26} /> : null}<span className="mono cell-wrap">{d?.entity.object_id ?? L("발급 항목", "Issued item")}</span>
      {d ? <small>{label(KINDS, d.entity.object_kind, L)} · {label(PURPOSES, d.entity.purpose, L)}</small> : null}</h2>
    {view.error ? <ErrorLine onRetry={view.reload}>{reasonText(view.error, L)}</ErrorLine> : !d ? <Loading /> : <IssuedDetailView d={d} />}
    <div className="modal-foot"><button type="button" className="ghost-btn" onClick={onClose}>{L("닫기", "Close")}</button></div>
  </Modal>;
}
