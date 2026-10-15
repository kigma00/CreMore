"use client";

import { useState } from "react";

import { useLocale } from "@/components/locale";
import { Ic } from "@/console/icons";
import { Modal } from "@/console/layer";
import { serviceName } from "@/console/logos";
import { accessPeople, accessRows, type FindingContext, locationAccess, locationAccessStatus, repositoryPeople } from "@/console/people";
import type { CredentialRecord } from "@/console/records";
import { downloadCsv, fmtDT, useL } from "@/console/text";
import { Fact, Facts, Pager, Pill, SelectField, TextField } from "@/console/ui";
import { accessBasis } from "@/console/views/credentials/risk";

type Say = (ko: string, en: string) => string;
const GAPS: Record<string, [string, string]> = {
  FORBIDDEN: ["연결한 계정에 저장소 구성원을 읽을 권한이 없습니다.", "The connected account can't read the repository's members."],
  NOT_FOUND_OR_NOT_VISIBLE: ["연결한 계정으로 저장소를 찾지 못했습니다.", "The connected account can't see the repository."],
  UNAVAILABLE: ["공급자가 목록을 반환하지 못했습니다.", "The provider could not return the list."],
  UNSUPPORTED: ["현재 이 위치의 접근 목록 수집은 지원하지 않습니다.", "Access-list collection is not currently supported for this location."],
  BLOCKED: ["연결 또는 승인된 검사 범위를 확인해야 합니다.", "The connection or approved scan scope needs attention."],
  LIMIT_REACHED: ["이번 조회의 위치 한도에 도달해 확인하지 못했습니다.", "This location was not queried because the request reached its location limit."],
  REFRESH_REQUIRED: ["이전 관측에는 연결 식별 정보가 없습니다. 다시 확인해 위치별 목록을 갱신하세요.", "This older observation has no connection identity. Check again to refresh the list for each location."],
};
const LIMITATIONS: Record<string, [string, string]> = {
  PUBLIC_ACCESS_NOT_ENUMERATED: ["공개 위치입니다. 익명 이용자를 목록으로 열거할 수 없습니다.", "This location is public. Anonymous readers cannot be enumerated."],
  INTERNAL_ACCESS_NOT_ENUMERATED: ["내부 공개 위치입니다. 조직 전체 접근자는 이 목록보다 많을 수 있습니다.", "This internal location may be readable by more organization members than this list shows."],
  PUBLIC_OR_LINK_ACCESS_NOT_ENUMERATED: ["공개·링크 공유로 접근하는 사람은 포함하지 않습니다.", "People using public or shared-link access are not enumerated."],
  TOKENS_AND_APPS_NOT_ENUMERATED: ["앱·토큰으로 접근하는 모든 주체를 열거한 목록은 아닙니다.", "This is not an enumeration of every principal using apps or tokens."],
  MEMBERSHIP_NOT_EFFECTIVE_READ_ACCESS: ["구성원 목록은 실제 파일 읽기 권한을 모두 증명하지 않습니다.", "Membership alone does not prove effective read access to every file."],
  MEMBERSHIP_IS_NOT_REPOSITORY_READ: ["일부 구성원의 역할은 저장소 읽기를 보장하지 않습니다.", "Some member roles do not guarantee repository read access."],
  REPOSITORY_READ_NOT_CONFIRMED: ["일부 계정의 저장소 읽기 권한은 확인되지 않았습니다.", "Repository read access is not confirmed for some accounts."],
  VISIBILITY_UNAVAILABLE: ["공개 범위를 확인하지 못했습니다.", "Visibility could not be confirmed."],
  MALFORMED_MEMBER_ROWS: ["공급자 응답의 일부 계정 항목을 해석하지 못했습니다.", "Some account rows in the provider response could not be read."],
  MEMBER_PAGE_UNAVAILABLE: ["목록의 다음 페이지 조회에 실패했습니다.", "The next page of the list could not be read."],
  MEMBER_PAGE_LIMIT: ["목록 페이지 한도에 도달했습니다.", "The member page limit was reached."],
  MEMBER_PAGINATION_INVALID: ["공급자의 다음 페이지 정보가 올바르지 않아 목록 조회를 멈췄습니다.", "Collection stopped because the provider returned invalid pagination information."],
  ACCESS_PAGINATION_INVALID: ["공급자의 다음 페이지 정보가 올바르지 않아 권한 조회를 멈췄습니다.", "Permission collection stopped because the provider returned invalid pagination information."],
  PAGED_LIST_NOT_ATOMIC: ["여러 페이지를 읽는 동안 구성원이 바뀔 수 있습니다. 한 시점의 고정된 목록은 아닙니다.", "Membership can change while pages are read. This is not an atomic snapshot."],
  ACCESS_LIST_PARTIAL: ["접근 관련 목록이 부분 수집됐습니다.", "The access evidence list is partial."],
  ACCESS_LIST_PERMISSION_REQUIRED: ["접근 목록 조회에 추가 권한이 필요합니다.", "Additional permission is required to read the access list."],
  ACCESS_LIST_UNAVAILABLE: ["접근 목록 조회를 완료하지 못했습니다.", "The access list could not be fully read."],
  ANCESTOR_PERMISSIONS_NOT_EVALUATED: ["상위 위치의 권한을 평가하지 않았습니다.", "Ancestor permissions were not evaluated."],
  AWS_APPROVED_SCANNER_REQUIRED: ["승인된 AWS 수집 역할이 필요합니다.", "An approved AWS scanner role is required."],
  AWS_AUTHORIZATION_CHANGED: ["조회 중 AWS 접근 승인이 변경됐습니다.", "AWS authorization changed during the lookup."],
  BRANCH_PERMISSIONS_NOT_EVALUATED: ["브랜치별 권한을 평가하지 않았습니다.", "Branch-specific permissions were not evaluated."],
  BUCKET_ACL_IS_NOT_OBJECT_READ: ["버킷 ACL이 개체 읽기 권한을 뜻하지 않습니다.", "A bucket ACL does not prove object read access."],
  CONDITIONAL_GRANTS_NOT_EVALUATED: ["조건부 권한의 조건을 평가하지 않았습니다.", "Conditions on grants were not evaluated."],
  CONTAINER_PUBLIC_CONFIGURATION_ONLY: ["컨테이너의 공개 설정만 확인한 근거입니다.", "Only the container's public-access configuration was observed."],
  CURRENT_POLICY_NOT_HISTORICAL: ["현재 정책이며 과거 열람 시점의 정책이 아닙니다.", "This is the current policy, not the policy at a past access time."],
  GRANT_IS_NOT_EFFECTIVE_PERMISSION: ["권한 부여 항목은 실효 권한의 확정이 아닙니다.", "A grant is not confirmation of effective permission."],
  GROUP_MEMBERS_NOT_EXPANDED: ["그룹의 구성원을 펼쳐 조회하지 않았습니다.", "Group members were not expanded."],
  IAM_POLICIES_NOT_EVALUATED: ["IAM 정책을 종합 평가하지 않았습니다.", "IAM policies were not jointly evaluated."],
  INHERITED_PERMISSIONS_NOT_EVALUATED: ["상속된 권한을 종합 평가하지 않았습니다.", "Inherited permissions were not jointly evaluated."],
  NEGATED_POLICY_NOT_EVALUATED: ["제외 조건이 있는 정책을 평가하지 않았습니다.", "Negated policy conditions were not evaluated."],
  NETWORK_AND_ACCOUNT_POLICY_NOT_EVALUATED: ["네트워크·계정 정책을 평가하지 않았습니다.", "Network and account policies were not evaluated."],
  NETWORK_AND_KMS_NOT_EVALUATED: ["네트워크·KMS 제한을 평가하지 않았습니다.", "Network and KMS restrictions were not evaluated."],
  POLICY_RESOURCE_NOT_EVALUATED: ["정책의 리소스 조건을 평가하지 않았습니다.", "Policy resource conditions were not evaluated."],
  PUBLIC_ACCESS_BLOCK_ENABLED: ["공개 접근 차단이 켜져 있습니다. 공개 grant만으로 접근을 확정할 수 없습니다.", "Public access blocking is enabled. A public grant alone does not confirm access."],
  PUBLIC_GRANT_NOT_EFFECTIVE_ACCESS: ["공개 grant는 실효 접근 권한의 확정이 아닙니다.", "A public grant is not confirmation of effective access."],
  RBAC_AND_ADLS_ACL_NOT_EVALUATED: ["RBAC·ADLS ACL을 평가하지 않았습니다.", "RBAC and ADLS ACLs were not evaluated."],
  RESTRICTION_IS_NOT_READ_PERMISSION: ["페이지 제한 목록은 읽기 권한의 확정이 아닙니다.", "Page restrictions are not confirmation of read permission."],
  RESTRICTION_LIST_PARTIAL: ["페이지 제한 목록이 부분 수집됐습니다.", "The page restriction list is partial."],
  SHARED_KEY_NOT_ENUMERATED: ["공유 키 이용자는 열거하지 않습니다.", "Shared-key users are not enumerated."],
  SIGNED_URLS_NOT_ENUMERATED: ["서명 URL 이용자는 열거하지 않습니다.", "Signed-URL users are not enumerated."],
  SPACE_PERMISSIONS_NOT_EVALUATED: ["스페이스 권한을 평가하지 않았습니다.", "Space permissions were not evaluated."],
  STORED_ACCESS_POLICY_NOT_AVAILABLE: ["저장된 접근 정책을 확인하지 못했습니다.", "Stored access policies were unavailable."],
  STORED_ACCESS_POLICIES_NOT_IDENTITIES: ["저장된 접근 정책은 정책 식별자이며 실제 이용자의 신원 목록이 아닙니다.", "Stored access policies identify policies, not the people using them."],
  POLICY_TIME_NOT_EVALUATED: ["정책의 시작·만료 시각에 따른 효력을 평가하지 않았습니다.", "Policy start and expiry times were not evaluated."],
  TFVC_PATH_ACL_NOT_SUPPORTED: ["TFVC 경로 ACL 수집은 현재 지원하지 않습니다.", "TFVC path ACL collection is not currently supported."],
  OBJECT_ACL_DISABLED_BY_UNIFORM_ACCESS: ["균일한 버킷 접근 설정으로 개체 ACL이 비활성화됐습니다.", "Uniform bucket-level access disables object ACLs."],
};

export function accessGap(status: string | undefined, L: Say): string {
  return L(...(GAPS[status ?? ""] ?? GAPS.UNAVAILABLE));
}

/** Provider evidence is an observation, never an access-history or IdP-identity claim. */
export function AccessList({ context, place }: { context: FindingContext; place: FindingContext["locations"][number] }) {
  const L = useL(), locale = useLocale();
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const [size, setSize] = useState(100);
  const repository = locationAccess(context, place);
  const people = repositoryPeople(repository);
  const filtered = people.filter(person => [person.login, person.name, person.role, person.principal_id, person.principal_kind, person.permission, person.effect]
    .filter(Boolean).join(" ").toLowerCase().includes(query.trim().toLowerCase()));
  const lastPage = Math.max(0, Math.ceil(filtered.length / size) - 1);
  const shownPage = Math.min(page, lastPage);
  const shown = filtered.slice(shownPage * size, (shownPage + 1) * size);
  const partial = repository?.completeness === "PARTIAL" || repository?.truncated;
  const status = locationAccessStatus(place, repository);
  const complete = repository?.status === "OBSERVED" && repository.completeness === "COMPLETE" && !partial;
  const observedAt = repository?.observed_at;
  const limits = new Set(repository?.limitations ?? []);
  if (repository?.visibility === "PUBLIC") limits.add("PUBLIC_ACCESS_NOT_ENUMERATED");
  if (repository?.visibility === "INTERNAL") limits.add("INTERNAL_ACCESS_NOT_ENUMERATED");
  if (repository) {
    limits.add("PUBLIC_OR_LINK_ACCESS_NOT_ENUMERATED");
    limits.add("TOKENS_AND_APPS_NOT_ENUMERATED");
  }
  return <div className="access-list">
    <Facts>
      <Fact label={L("연결", "Connection")}>{place.source_label ?? serviceName(place.source_type)}<div className="meta cell-wrap">{place.source_connection_id ?? L("식별 정보 없음", "Identity unavailable")}</div></Fact>
      <Fact label={L("발견 위치", "Discovered location")}><span className="cell-wrap">{place.repository} · {place.path}</span></Fact>
      <Fact label={L("관측 근거", "Evidence")}>{repository?.basis ? accessBasis(repository.basis, L) : L("미확인", "Unknown")}</Fact>
      <Fact label={L("공개 범위", "Visibility")}>{repository?.visibility === "PUBLIC" ? L("공개 · 익명 접근자 미열거", "Public · anonymous readers not enumerated")
        : repository?.visibility === "INTERNAL" ? L("조직 내부 · 추가 접근자 가능", "Internal · additional readers possible")
          : repository?.visibility === "PRIVATE" ? L("비공개", "Private") : L("미확인", "Unknown")}</Fact>
      <Fact label={L("관측 시각", "Observed at")}>{observedAt ? fmtDT(observedAt, locale) : L("미확인", "Unknown")}</Fact>
    </Facts>
    <p className="meta">{L("조회 시점에 공급자가 보고한 주체와 권한 관련 근거입니다. 실제 열람 여부·열람 이력이나 회사 IdP 신원 매핑을 뜻하지 않습니다.", "Principals and permission evidence reported by the provider at the observation time. This is not proof of actual viewing, access history or a company IdP identity match.")}</p>
    {observedAt ? <p className="meta">{L("저장된 관측 이후 권한이 바뀔 수 있습니다. 관측 시각은 현재 접근 가능 여부를 보장하지 않습니다.", "Permissions may have changed since this saved observation. Its timestamp does not guarantee access now.")}</p> : null}
    {(context.job_status === "QUEUED" || context.job_status === "RUNNING") && partial ? <p className="meta" role="status">{L(
      `전체 조회 작업이 진행 중입니다. 이 위치에 저장된 근거 ${people.length}건입니다.`,
      `The collection job is in progress. ${people.length} evidence rows have been saved for this location.`)}</p> : null}
    {status !== "OBSERVED" ? <p className="meta tone-warn">{accessGap(status, L)}</p> : null}
    {partial ? <p className="meta tone-warn">{L("부분 목록입니다. 확인된 항목만 표시하며 빠진 계정을 접근 불가로 판단하지 않습니다.", "This is a partial list. Only observed rows are shown; an absent account is not evidence of no access.")}</p> : null}
    {limits.size ? <details className="safety"><summary>{L("공개·그룹·수집 한계", "Public access, groups and collection limits")}</summary>
      <ul>{[...limits].filter(code => code !== "NOT_ACCESS_HISTORY").map(code => <li key={code}>{L(...(LIMITATIONS[code] ?? [code, code]))}</li>)}</ul>
    </details> : null}
    {people.length ? <>
      <TextField label={L("계정·그룹 검색", "Search accounts and groups")} value={query} onChange={value => { setQuery(value); setPage(0); }} placeholder={L("이름·로그인·역할", "Name, login or role")} />
      <p className="meta" role="status">{L(`${people.length}개 관측 항목 중 ${filtered.length}개 표시`, `${filtered.length} of ${people.length} observed principals shown`)}</p>
      <div className="table-wrap" style={{ maxHeight: 360, overflow: "auto" }} tabIndex={0} aria-label={L("관측된 공급자 계정 목록", "Observed provider accounts")}>
        <table className="sub-tbl" style={{ tableLayout: "fixed" }}><thead><tr>
          <th>{L("접근 관련 주체", "Access principal")}</th><th>{L("역할·권한 근거", "Role or permission evidence")}</th><th>{L("읽기 권한", "Read access")}</th>
        </tr></thead><tbody>{shown.map((person, index) => <tr key={`${person.principal_id ?? person.login}:${person.permission ?? person.role}:${person.effect}:${index}`}>
          <td className="cell-wrap">{person.name ?? person.login}{person.name ? <div className="meta cell-wrap">{person.login}</div> : null}
            {person.principal_id && person.principal_id !== person.login ? <div className="meta cell-wrap">{person.principal_id}</div> : null}
            {person.principal_kind ? <div className="meta">{person.principal_kind === "USER" ? L("사용자", "User") : person.principal_kind === "GROUP" ? L("그룹 · 구성원 미열거", "Group · members not enumerated")
              : person.principal_kind === "SERVICE_PRINCIPAL" ? L("서비스 주체", "Service principal") : person.principal_kind === "PUBLIC" ? L("공개 주체", "Public principal")
                : person.principal_kind === "AUTHENTICATED" ? L("인증된 주체 집합", "Authenticated principals") : person.principal_kind === "POLICY" ? L("정책", "Policy") : L("주체 유형 미확인", "Principal type unknown")}</div> : null}</td>
          <td className="cell-wrap">{person.permission ?? person.role ?? L("미확인", "Unknown")}{person.effect && person.effect !== "UNKNOWN" ? <div className="meta">{
            person.effect === "DENY" ? L("거부 항목", "Deny entry") : person.effect === "RESTRICT" ? L("제한 항목", "Restriction entry") : L("허용 항목", "Allow entry")}</div> : null}</td>
          <td className="cell-wrap">{person.read_access === "REPORTED" ? L("공급자 보고", "Provider reported") : L("미확인", "Unknown")}</td>
        </tr>)}</tbody></table>
      </div>
      {filtered.length > 25 ? <Pager page={shownPage} pages={lastPage + 1} size={size} total={filtered.length}
        onPage={setPage} onSize={value => { setSize(value); setPage(0); }} /> : null}
      {!filtered.length ? <p className="meta">{L("검색 결과가 없습니다.", "No matching accounts.")}</p> : null}
    </> : complete ? <p className="meta">{L("공급자가 반환한 계정이 없습니다. 공개·링크 공유 접근자의 부재를 뜻하지 않습니다.", "The provider returned no accounts. This does not rule out public or shared-link access.")}</p> : null}
  </div>;
}

function AccessModal({ context, findingId, onClose }: { context: FindingContext; findingId: string; onClose: () => void }) {
  const L = useL();
  const [index, setIndex] = useState("0");
  const place = context.locations[Number(index)] ?? context.locations[0];
  return <Modal onClose={onClose} labelledBy="location-access-title" className="integ">
    <h2 id="location-access-title">{L("발견 위치별 접근 목록", "Access by discovered location")}</h2>
    <SelectField label={L("발견 위치 선택", "Choose discovered location")} value={index} onChange={setIndex}
      options={context.locations.map((location, i) => ({ id: String(i), label: `${location.source_label ?? serviceName(location.source_type)} · ${location.source_connection_id?.slice(0, 8) ?? "—"} · ${location.repository} · ${location.path}` }))} />
    {context.unqueried_locations ? <p className="meta tone-warn">{L(`${context.location_count}곳 중 ${context.unqueried_locations}곳은 조회되지 않았습니다.`, `${context.unqueried_locations} of ${context.location_count} locations were not queried.`)}</p> : null}
    {context.omitted_locations ? <p className="meta tone-warn">{L(`위치 표시 한도로 ${context.omitted_locations}곳을 생략했습니다.`, `${context.omitted_locations} locations were omitted by the display limit.`)}</p> : null}
    {place ? <AccessList key={`${place.exposure_id}:${place.access_key ?? index}`} context={context} place={place} /> : null}
    <div className="modal-foot">
      <button type="button" className="ghost-btn" onClick={() => downloadCsv(`cremore-access-${findingId}.csv`, accessRows(context))}>{L("CSV 내보내기", "Export CSV")}</button>
      <button type="button" className="primary-btn" onClick={onClose}>{L("닫기", "Close")}</button>
    </div>
  </Modal>;
}

export function AccessCard({ c, context, canEdit, onNotify, onRecheck }: {
  c: CredentialRecord; context?: FindingContext; canEdit: boolean; onNotify: () => void; onRecheck?: () => void;
}) {
  const L = useL();
  const [open, setOpen] = useState(false);
  const people = accessPeople(context);
  const pending = context?.job_status === "QUEUED" || context?.job_status === "RUNNING";
  const repositories = context?.repositories ?? [];
  const gap = repositories.find(repository => repository.status !== "OBSERVED");
  const legacy = repositories.some(repository => !repository.access_key);
  const meta = pending ? L("공급자에서 확인하고 있습니다.", "Checking with the provider.")
    : legacy ? accessGap("REFRESH_REQUIRED", L)
      : repositories.length ? people.length || repositories.some(repository => repository.status === "OBSERVED")
        ? L(`발견 위치 ${context?.location_count ?? context?.locations.length ?? 0}곳 · 주체 관측 ${people.length}건`, `${context?.location_count ?? context?.locations.length ?? 0} locations · ${people.length} observed principal rows`)
        : L("확인된 계정 목록이 없습니다. 위치별 수집 상태를 확인하세요.", "No account list has been confirmed. Review each location's collection status.")
        : c.access ? L(`${c.access.repository} · 이전 요약 ${c.access.count}${c.access.truncated ? "+" : ""}건 · 목록은 다시 확인이 필요합니다.`, `${c.access.repository} · Previous summary: ${c.access.count}${c.access.truncated ? "+" : ""} rows · Refresh required for the list.`)
          : L("확인하지 못했습니다.", "Could not be confirmed.");
  return <>
    <section className="card person-card">
      <div className="pc-top"><span className="pc-ic"><Ic name="users" size={22} /></span>
        <div className="pc-main"><div className="pc-title">{L("발견 위치별 접근 목록", "Access by discovered location")}</div>
          {people.length ? <div className="pc-people">{people.slice(0, 6).map(person => <Pill key={`${person.access_key}:${person.login}`}
            tip={[person.repository, person.login, person.role].filter(Boolean).join(" · ")}>{person.name ?? person.login}</Pill>)}</div> : null}
          <div className="meta">{meta}</div>
          {gap ? <div className="meta tone-warn">{accessGap(gap.status, L)}</div> : null}
        </div>
        {context?.locations.length ? <button type="button" className="ghost-btn" onClick={() => setOpen(true)}>{L("목록 보기", "View list")}</button> : null}
        {canEdit && people.some(person => !person.principal_kind || person.principal_kind === "USER") ? <button type="button" className="link-btn" onClick={onNotify}><Ic name="send" size={15} />{L("알림 보내기", "Notify")}</button> : null}
        {onRecheck && context && context.status !== "UNSUPPORTED" ? <button type="button" className="icon-btn small-btn" disabled={pending} onClick={onRecheck}
          aria-label={L("다시 확인", "Check again")} data-tip={L("공급자에서 다시 확인", "Check again with the provider")}><Ic name="refresh" size={15} /></button> : null}
      </div>
    </section>
    {open && context ? <AccessModal context={context} findingId={c.finding_id ?? "locations"} onClose={() => setOpen(false)} /> : null}
  </>;
}
