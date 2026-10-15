"use client";

/* The five tabs of the credential panel. The design's cards come first on each tab; the evidence
 * CreMore keeps beyond them (original-source links, exposure stages, risk score, issuer links,
 * the ownership review) follows in the same card style. */

import { type ReactNode, useState } from "react";

import { useLocale } from "@/components/locale";
import { api, DashboardAPIError } from "@/lib/dashboard-api";
import type { OwnershipReviewResponse } from "@/lib/dashboard-types";
import { reasonText, send, useApi, useSaved } from "@/console/data";
import { Ic } from "@/console/icons";
import { actorLabel, typeLabel, visLabel } from "@/console/labels";
import { Menu, MenuItem, useMenu, useToast } from "@/console/layer";
import { Logo, serviceName } from "@/console/logos";
import { accessPeople, type FindingContext, type Person } from "@/console/people";
import { awsPermissionEvidence, type CredentialRecord, exposureService, lastUseGap, type StepId, type StepState } from "@/console/records";
import { sourceOriginalURL } from "@/console/source-links";
import { fmtDay, fmtDT, rel, time, useL } from "@/console/text";
import { Banner, Card, CardBody, cls, Fact, Facts, InfoTip, Pill, SelectField, TextField, VerifyTag } from "@/console/ui";
import { CreatorSummary, Expiry, RecentSources } from "@/console/views/credentials/cells";
import { AccessGraph, nextZoom, ZoomControl } from "@/console/views/credentials/graph";
import { GraphModal, GraphToggle, type Target, templateLabel } from "@/console/views/credentials/modals";
import { accessBasis, axisLevel, fillSteps, inHistory, missingEvidence, ownerBasis, plainSteps, type RemedItem, type Rule, scoreLine, usageBasis, usageGap, vaultWhere, verifyBasis } from "@/console/views/credentials/risk";
import { InventoryPermissions, LookupPermissions } from "@/console/views/credentials/permissions";
import { UsageCard, usageLookup } from "@/console/views/credentials/usage";
import { AccessCard } from "@/console/views/credentials/access";
import type { ManagementAction } from "@/console/views/approvals/model";

export type DetailExposure = {
  id: string; source_type: string; resource_name: string; location: string; line_number?: number | null; redacted_line?: string | null;
  status: string; first_seen_at?: string | null; last_seen_at?: string | null; removed_at?: string | null; metadata?: Record<string, unknown>;
  removal_pending?: boolean;
  source_location?: Parameters<typeof sourceOriginalURL>[0]; source_connection_ids?: string[];
  detection_details?: { risk_score?: number; risk_level?: string; risk_evidence?: string[]; risk_missing_evidence?: string[]; effective_severity?: string; custom_rule?: Record<string, unknown> };
};
export type Detail = {
  id: string; workflow_status: string; primary_exposure_id?: string; exposures: DetailExposure[];
  events?: { id: string; actor: string; event_type: string; from_status?: string | null; to_status?: string | null; note?: string | null; created_at: string }[];
  exposure_path?: { stages: { stage: string; state: string; locations?: number; level?: string; public_locations?: number; undetermined_locations?: number; outcome?: string; events?: number; denied_events?: number; removed_locations?: number; scopes?: number; source?: string; allows_every_action?: boolean; denies_every_action?: boolean; quarantine_policies?: string[]; allowed_actions?: number; collection_status?: string }[] };
  credential: { principal?: string; governance?: unknown };
  /** This finding's management actions. */
  management_actions?: ManagementAction[];
};

type ManagedLinks = { evidence: string; value_match_count?: number; identifier_match_count?: number; total: number; provider: string; object_kind: string;
  items: { entity_id: string; object_id: string; evidence?: string; match_basis?: string; origin: string; observed_at: string | null; usage_events: number; current_evidence?: boolean }[];
  token_activity?: { events: number; first_seen_at: string; last_seen_at: string; actions: string[]; repositories: string[]; actors: string[] } };

// What a well-known permission allows, for the permissions table.
const SCOPE_TEXT: Record<string, [string, string]> = {
  repo: ["비공개 저장소 전체 읽기·쓰기", "Read/write all private repositories"], workflow: ["GitHub Actions 워크플로 수정", "Modify GitHub Actions workflows"],
  "admin:org": ["조직 설정·구성원 관리", "Manage organization settings and members"], "read:org": ["조직·팀 정보 읽기", "Read organization and team info"],
  "write:packages": ["패키지 게시", "Publish packages"], "read:packages": ["패키지 내려받기", "Download packages"], gist: ["Gist 만들기·수정", "Create and edit gists"],
  api: ["그룹·프로젝트 API 전체 읽기·쓰기", "Full read/write API access to groups and projects"], read_api: ["API 읽기", "Read-only API access"],
  read_repository: ["저장소 읽기", "Read repositories"], write_repository: ["저장소에 코드 push", "Push code to repositories"],
  read_registry: ["컨테이너 레지스트리 읽기", "Read the container registry"], write_registry: ["컨테이너 레지스트리 쓰기", "Write to the container registry"],
  sudo: ["관리자 권한으로 다른 사용자처럼 요청", "Act as other users with admin rights"], "contents:read": ["저장소 파일 읽기", "Read repository files"],
  "contents:write": ["저장소 파일 쓰기", "Write repository files"], "metadata:read": ["저장소 정보 읽기", "Read repository metadata"],
  "pull_requests:write": ["풀 리퀘스트 만들기·병합", "Create and merge pull requests"], "issues:write": ["이슈 만들기·수정", "Create and edit issues"],
  "chat:write": ["채널에 메시지 게시", "Post messages to channels"], "incoming-webhook": ["지정 채널에 메시지 게시", "Post to the configured channel"],
  // GCP: what Policy Troubleshooter allowed a service account on its project (gcp metadata/effective_access.py).
  "iam.serviceAccountKeys.create": ["서비스 계정 키 새로 만들기", "Create service account keys"],
  "iam.serviceAccounts.actAs": ["서비스 계정을 붙여 리소스 실행", "Run resources as a service account"],
  "iam.serviceAccounts.getAccessToken": ["서비스 계정 액세스 토큰 발급", "Mint service account access tokens"],
  "resourcemanager.projects.setIamPolicy": ["프로젝트 IAM 정책 변경", "Change the project's IAM policy"],
  "secretmanager.versions.access": ["Secret Manager 비밀값 읽기", "Read Secret Manager secret values"],
  "cloudkms.cryptoKeyVersions.useToDecrypt": ["Cloud KMS 키로 복호화", "Decrypt with Cloud KMS keys"],
  "storage.objects.delete": ["Cloud Storage 객체 삭제", "Delete Cloud Storage objects"],
  "cloudfunctions.functions.update": ["Cloud Functions 코드·설정 변경", "Change Cloud Functions code and settings"],
  "run.services.update": ["Cloud Run 서비스 배포·변경", "Deploy or change Cloud Run services"],
  "compute.instances.create": ["Compute Engine VM 만들기", "Create Compute Engine VMs"],
  "storage.objects.get": ["Cloud Storage 객체 읽기", "Read Cloud Storage objects"],
};

export function OverviewTab({ c, detail, name, canLookup = false, openIssued }: {
  c: CredentialRecord; detail?: Detail; name: string; canLookup?: boolean; openIssued: (entityId: string) => void;
}) {
  const L = useL();
  const locale = useLocale();
  const [view, setView] = useState<"exposure" | "access">("exposure");
  const [open, setOpen] = useState(true);
  const [zoom, setZoom] = useState(1);
  const [big, setBig] = useState(false);
  const managed = useApi<ManagedLinks>(c.finding_id ? `v2/coverage/findings/${c.finding_id}` : null);
  const exposures = detail?.exposures ?? [];
  const rows = exposures.length ? exposures : c.exposures.map((e, index) => ({ id: String(index), source_type: e.source_type, resource_name: e.resource_name, location: e.location,
    line_number: e.line, redacted_line: e.snippet, status: e.current ? "OPEN" : "REMOVED", first_seen_at: e.first_seen_at, metadata: { exposure: e.visibility } } as DetailExposure));
  const current = rows.filter(e => e.status !== "REMOVED");
  const activity = managed.data?.token_activity;
  const lastUsed = c.last_used ?? (activity ? { at: activity.last_seen_at, basis: "GITHUB_AUDIT" } : null);
  const listed = (e: DetailExposure) => c.exposures.find(x => x.resource_name === e.resource_name && x.location === e.location);
  const vis = (e: DetailExposure) => String((e.metadata?.exposure as string | undefined) ?? listed(e)?.visibility ?? "unknown").toLowerCase();

  return <>
    <Card className="graph-card" level={3} headClass="wrap" title={L("접근 관계", "Access relationships")}
      info={L("노출 경로는 이 값이 어디에 적혀 있는지, 권한 범위는 이 값으로 무엇에 접근할 수 있는지 보여 줍니다. 점선은 확정되지 않은 연결입니다.", "Exposure path shows where the value is written. Access scope shows what it can reach. Dashed lines are unconfirmed links.")}
      right={<><GraphToggle view={view} setView={next => { setView(next); setZoom(1); }} />
        <button type="button" className="icon-btn" aria-label={L("크게 보기", "Expand")} data-tip={L("크게 보기", "Expand")} onClick={() => setBig(true)}><Ic name="expand" size={17} /></button>
        <button type="button" className="icon-btn" aria-label={open ? L("접기", "Collapse") : L("펼치기", "Expand section")} onClick={() => setOpen(value => !value)}><Ic name={open ? "up" : "down"} size={17} /></button></>}>
      {open ? <><div className="graph-box"><ZoomControl onZoom={direction => setZoom(value => nextZoom(value, direction))} /><AccessGraph c={c} view={view} big={false} zoom={zoom} name={name} /></div>
        <div className="hint-line">{L("노드에 마우스를 올리면 근거가 보입니다", "Hover a node to see its evidence")}</div></> : null}
    </Card>
    {big ? <GraphModal c={c} name={name} view={view} setView={setView} onClose={() => setBig(false)} /> : null}

    <Card level={3} headClass="wrap" title={L("노출 위치", "Exposure locations")} meta={L(`${current.length}곳 · 원문 대신 가린 값만 표시`, `${current.length} found · masked values only`)}>
      {rows.length ? <ul className="exposure-locations" aria-label={L("노출 위치 목록", "Exposure location list")} role="list">{rows.map(e => {
          const place = exposureService(e.source_type);
          const url = sourceOriginalURL(e.source_location);
          const author = listed(e)?.author;
          return <li key={e.id} className="exposure-location">
            <div className="exposure-location-head">
              <span className="loc-cell"><Logo id={place} size={24} /><span className="cell-wrap">{e.resource_name}</span></span>
              {url ? <a href={url} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer" className="link-btn small">
                {e.source_location?.original_link.historical_content ? L("탐지한 버전 열기", "Open detected revision") : L("원본 열기", "Open source")} <Ic name="ext" size={13} /></a> : null}
            </div>
            <div className="exposure-location-file">
              <div className="exposure-location-label"><span>{L("파일·페이지", "File or page")}</span>
                {e.line_number ? <span className="num">{L(`${e.line_number}번째 줄`, `line ${e.line_number}`)}</span> : null}</div>
              <p className="exposure-location-path">{e.location}</p>
            </div>
            <dl className="exposure-location-facts">
              <div><dt>{L("공개 범위", "Visibility")}</dt><dd><span className={`vis vis-${vis(e)}`}>{visLabel(vis(e), L)}</span>
                {inHistory(e.source_type) ? <span className="subtle small">{L("이력에 남음", "In history")}</span> : null}</dd></div>
              <div><dt>{L("처음 발견", "First found")}</dt><dd><span className="num">{fmtDT(e.first_seen_at, locale)}</span>
                {e.removal_pending || listed(e)?.removal_pending ? <span className="subtle small">{L("다른 연결의 제거 확인 대기", "Awaiting removal confirmation from other connections")}</span>
                  : e.status === "REMOVED" ? <span className="subtle small">{L("제거됨", "Removed")}{e.removed_at ? ` · ${fmtDay(e.removed_at, locale)}` : ""}</span> : null}</dd></div>
              <div><dt>{L("작성자", "Author")}</dt><dd>{author ?? <span className="subtle">—</span>}</dd></div>
            </dl>
            {e.redacted_line ? e.redacted_line === "[Credential material redacted]"
              ? <p className="exposure-location-masked"><Ic name="lock" size={13} />{L("자격증명은 숨김 처리되었습니다.", "Credential material is hidden.")}</p>
              : <code className="snippet mono">{e.redacted_line}</code> : null}
          </li>;
        })}</ul> : <div className="card-body muted">{L("연결한 위치를 검사한 범위에서 발견되지 않았습니다.", "Not found within the scanned locations.")}</div>}
    </Card>

    <Card level={3} headClass="wrap" title={L("권한과 접근 범위", "Permissions and access")}>
      {c.scopes?.length ? <div className="sub-scroll"><table className="sub-tbl">
        <thead><tr><th>{L("서비스", "Service")}</th><th>{L("권한", "Permission")}</th><th>{L("할 수 있는 일", "What it allows")}</th></tr></thead>
        <tbody>{c.scopes.map(scope => <tr key={scope.name}>
          <td className="nowrap" data-label={L("서비스", "Service")}>{serviceName(c.provider)}</td>
          <td data-label={L("권한", "Permission")}><code className="mono cell-wrap">{scope.name}</code>{scope.write ? <> <span className="vis vis-org small">{L("쓰기", "write")}</span></> : null}</td>
          <td className="cell-wrap" data-label={L("할 수 있는 일", "What it allows")}>{SCOPE_TEXT[scope.name] ? L(...SCOPE_TEXT[scope.name]) : scope.write ? L("쓰기·관리", "Write or admin") : scope.write === false ? L("읽기", "Read") : "—"}</td>
        </tr>)}</tbody>
      </table></div> : c.issued?.provider === "aws_iam" && !usageLookup(c) ? <InventoryPermissions c={c} /> : usageLookup(c) ? <LookupPermissions c={c} /> : <div className="card-body muted">{c.issued ? L("발급 목록에 권한 정보가 없습니다.", "The issuance inventory carries no permission info.")
        : L("발급 서비스에서 권한 정보를 받지 못했습니다. 이 유형은 발급 목록을 연결하지 않았습니다.", "The issuer provided no permission info. This type has no connected issuance inventory.")}</div>}
    </Card>

    <Card level={3} title={L("핵심 정보", "Key facts")}>
      <CardBody><Facts>
        <Fact label={L("소유 계정", "Owning account")} tip={c.issuer ? `${L("근거: ", "Basis: ")}${serviceName(c.issuer.basis, c.issuer.basis)}` : L("발급 서비스 목록을 연결하지 않았습니다.", "No issuance inventory is connected.")}>
          {c.issuer ? <>{c.issuer.name}{c.issuer.role ? <span className="subtle"> · {c.issuer.role === "IAM_USER" ? L("IAM 사용자", "IAM user") : c.issuer.role}</span> : null}</>
            : detail?.credential.principal ? detail.credential.principal : <span className="subtle">{L("미확인", "Unknown")}</span>}</Fact>
        {c.issued?.provider === "aws_iam" ? <Fact label={L("키 생성자", "Key creator")} tip={L("CloudTrail CreateAccessKey 이벤트 근거입니다. 키 소유자와 다를 수 있습니다.", "CloudTrail CreateAccessKey evidence; may differ from the key owner.")}><CreatorSummary c={c} /></Fact> : null}
        <Fact label={L("발급일", "Issued")} tip={L("발급 서비스가 보고한 생성 시각", "Creation time reported by the issuer")}>{c.created_at ? fmtDay(c.created_at, locale) : <span className="subtle">{L("미확인", "Unknown")}</span>}</Fact>
        <Fact label={L("만료", "Expires")} tip={L("발급 목록의 만료일 필드", "Expiry field in the issuance inventory")}><Expiry c={c} /></Fact>
        <Fact label={L("마지막 사용", "Last used")} tip={lastUsed ? (lastUsed.basis === "GITHUB_AUDIT" ? L("GitHub 감사 로그", "GitHub audit log") : usageBasis(c, L)) : `${usageGap(c, L)}${L(". 사용하지 않았다는 뜻이 아닙니다.", ". This does not mean it is unused.")}`}>
          {lastUsed ? rel(lastUsed.at, locale) : <span className="subtle">{lastUseGap(c, L) ?? L("미수집", "Not collected")}</span>}</Fact>
        <RecentSources c={c} />
        <Fact label={L("Vault 보관", "Vault")} tip={c.vault.state === "stored" ? vaultWhere(c) : L("연결한 Vault와 값의 지문으로 대조", "Fingerprint matching against the connected vaults")}>
          {c.vault.state === "stored" ? <span className="tone-ok">{L("보관 확인", "Stored")}</span> : c.vault.state === "none" ? <span className="tone-warn">{L("연결 Vault에 없음", "Not in connected Vaults")}</span>
            : <span className="subtle">{L("대조 안 함", "Not matched")}</span>}</Fact>
        <Fact label={L("활성 여부", "Activity")} tip={verifyBasis(c, L)}><VerifyTag state={c.verification.state} basis={c.verification.basis} /></Fact>
      </Facts></CardBody>
    </Card>

    <UsageCard c={c} canLookup={canLookup} principal={detail ? detail.credential.principal ?? null : undefined} />

    {c.finding_id && managed.data && (managed.data.items.length || activity) ? <Card level={3} headClass="wrap" title={L("발급 목록 연결", "Issuance inventory links")}
      meta={managed.data.evidence === "LINKED" ? L(`값 일치 ${managed.data.value_match_count ?? 0}건 · 식별자 연결 ${managed.data.identifier_match_count ?? 0}건`, `${managed.data.value_match_count ?? 0} value match · ${managed.data.identifier_match_count ?? 0} identifier link`)
        : L(`후보 ${managed.data.total}건`, `${managed.data.total} candidates`)}>
      {activity ? <CardBody><Facts>
        <Fact label={L("GitHub 감사 로그 사용 기록", "GitHub audit log activity")}>{L(`${activity.events}건`, String(activity.events))}</Fact>
        <Fact label={L("기간", "Period")}>{fmtDay(activity.first_seen_at, locale)} – {fmtDay(activity.last_seen_at, locale)}</Fact>
        {activity.repositories.length ? <Fact label={L("저장소", "Repositories")}><span className="cell-wrap">{activity.repositories.join(", ")}</span></Fact> : null}
        {activity.actions.length ? <Fact label={L("동작", "Actions")}><span className="cell-wrap">{activity.actions.join(", ")}</span></Fact> : null}
      </Facts></CardBody> : null}
      {managed.data.items.length ? <div className="sub-scroll"><table className="sub-tbl">
        <thead><tr><th>{L("발급 항목", "Issued item")}</th><th>{L("연결 근거", "Link basis")}</th><th>{L("수집 위치", "Collected from")}</th><th>{L("관측", "Observed")}</th></tr></thead>
        <tbody>{managed.data.items.slice(0, 20).map(item => <tr key={item.entity_id}>
          <td data-label={L("발급 항목", "Issued item")}><button type="button" className="link-btn" onClick={() => openIssued(item.entity_id)}><code className="mono cell-wrap">{item.object_id}</code></button></td>
          <td data-label={L("연결 근거", "Link basis")}>{item.evidence === "VALUE" ? L("값 일치", "Value match") : item.evidence === "IDENTIFIER" ? L("식별자 일치", "Identifier match")
            : item.evidence === "OWNER" ? L("같은 소유자", "Same owner") : L("후보", "Candidate")}</td>
          <td data-label={L("수집 위치", "Collected from")}><span className="cell-wrap">{item.origin}</span></td>
          <td className="nowrap num" data-label={L("관측", "Observed")}>{fmtDT(item.observed_at, locale)}{item.usage_events ? <div className="subtle small">{L(`사용 기록 ${item.usage_events}건`, `${item.usage_events} use records`)}</div> : null}</td>
        </tr>)}</tbody>
      </table></div> : null}
    </Card> : null}
  </>;
}

const STAGES: Record<string, [string, string]> = { EXPOSED: ["노출 관측", "Exposed"], REACHABLE: ["도달 범위", "Reachable"], USABLE: ["유효성", "Usable"],
  PRIVILEGED: ["권한", "Privilege"], USED: ["사용 관측", "Used"], REMOVED: ["제거", "Removed"] };
const STAGE_STATES: Record<string, [string, string]> = { OBSERVED: ["관측됨", "Observed"], NOT_OBSERVED: ["확인함 · 없음", "Checked · none"], NOT_COLLECTED: ["수집 안 함", "Not collected"], UNDETERMINED: ["판정 불가", "Undetermined"] };
const USABLE: Record<string, [string, string]> = { VALID: ["발급 서비스가 인증을 확인", "The issuer accepted it"], RESTRICTED: ["인증되나 정책으로 제한", "Accepted but restricted"],
  REJECTED: ["발급 서비스가 거부", "The issuer rejected it"], EXPIRED: ["만료됨", "Expired"], INDETERMINATE: ["응답을 판정하지 못함", "Inconclusive answer"],
  NOT_SUPPORTED: ["이 유형은 검증하지 않음", "Not verified for this type"], VERIFICATION_OFF: ["검증이 꺼져 있음", "Verification is off"], NOT_ATTEMPTED: ["검증한 적 없음", "Never checked"] };

function stageText(stage: NonNullable<Detail["exposure_path"]>["stages"][number], L: (ko: string, en: string) => string) {
  const n = (value?: number) => value ?? 0;
  switch (stage.stage) {
    case "EXPOSED": return L(`기록된 위치 ${n(stage.locations)}곳`, `${n(stage.locations)} recorded locations`);
    case "REACHABLE": return stage.level === "PUBLIC" ? L(`공개 접근 가능 ${n(stage.public_locations)}곳`, `${n(stage.public_locations)} publicly reachable`)
      : stage.level === "INTERNAL" ? L("내부 위치만", "Internal locations only") : L(`${n(stage.undetermined_locations)}곳의 공개 범위를 읽지 못함`, `Visibility unread at ${n(stage.undetermined_locations)} locations`);
    case "USABLE": return L(...(USABLE[stage.outcome ?? ""] ?? USABLE.NOT_ATTEMPTED));
    case "PRIVILEGED":
      if (stage.quarantine_policies?.length) return L("AWS 격리 정책 연결 관측 · 키 노출 근거 아님", "AWS quarantine policy attached · not evidence of key exposure");
      if (stage.denies_every_action) return L("모든 작업이 명시적으로 거부됨", "Every action is explicitly denied");
      if (stage.allows_every_action) return L("모든 작업을 허용하는 정책 관측", "An allow-all policy was observed");
      if (stage.source === "PROVIDER_SCOPES") return L(`발급 서비스가 보고한 권한 ${n(stage.scopes)}개`, `${n(stage.scopes)} scopes reported`);
      if (stage.source === "IAM_IDENTITY_POLICIES") return L("IAM 정책을 읽음", "IAM policies read");
      if (stage.source === "IAM_SIMULATE_PRINCIPAL_POLICY") return L(`정책 시뮬레이션 · 잠재 허용 ${n(stage.allowed_actions)}개`, `Policy simulation · ${n(stage.allowed_actions)} potentially allowed`);
      return L("수집한 권한 근거 없음", "No permission evidence collected");
    case "USED":
      if (stage.state === "OBSERVED") return L(`귀속된 호출 ${n(stage.events)}건${stage.denied_events ? ` · 거부 ${stage.denied_events}건` : ""}`, `${n(stage.events)} attributed calls${stage.denied_events ? ` · ${stage.denied_events} denied` : ""}`);
      return stage.state === "NOT_OBSERVED" ? L("조회 기간 안에 호출 없음", "No calls in the lookup window") : L("사용 조회를 실행한 적 없음", "No usage lookup has run");
    case "REMOVED":
      if (stage.outcome === "ALL_LOCATIONS_REMOVED") return L("기록된 모든 위치에서 제거됨", "Removed from every recorded location");
      if (stage.outcome === "SOME_LOCATIONS_REMOVED") return L(`${n(stage.locations)}곳 중 ${n(stage.removed_locations)}곳 제거됨`, `${n(stage.removed_locations)} of ${n(stage.locations)} removed`);
      return stage.outcome === "STILL_PRESENT" ? L("발견된 위치에 그대로 있음", "Still present where it was found") : L("확인되지 않음", "Not established");
    default: return "";
  }
}

export function RiskTab({ c, rules, detail, onRule }: { c: CredentialRecord; rules: Rule[]; detail?: Detail; onRule: (rule: Rule) => void }) {
  const L = useL();
  const iam = awsPermissionEvidence(c);
  const [banner, setBanner] = useState(true);
  const exposure = c.exposed ? axisLevel(rules, "exposure", L) : { cls: "l-low", text: L("노출 관측 없음", "Not observed") };
  const likelihood = axisLevel(rules, "likelihood", L);
  const unknown = rules.filter(rule => rule.axis === "unknown");
  const primary = detail?.exposures.find(e => e.id === detail.primary_exposure_id) ?? detail?.exposures[0];
  const details = primary?.detection_details;
  const axis = (title: string, level: { cls: string; text: string }, key: "exposure" | "likelihood", tip: string) => {
    const list = rules.filter(rule => rule.axis === key);
    return <section className="card">
      <div className="axis-head"><h3>{title}</h3><InfoTip text={tip} /><span className={`level ${level.cls}`}>{level.text}</span></div>
      <div className="card-body pad-top"><div className="rules-label">{L("규칙", "Rules")}</div>
        <div className="rules">{list.length ? list.map(rule => <RuleChip key={rule.id} rule={rule} onRule={onRule} />) : <span className="muted">{L("해당 규칙 없음", "No matching rules")}</span>}</div></div>
    </section>;
  };
  return <>
    {banner ? <Banner onClose={() => setBanner(false)}><span>{L("위험도는 ", "Risk combines two axes of evidence: ")}<b>{L("노출 정도", "exposure")}</b>{L("와 ", " and ")}<b>{L("악용 가능성", "likelihood of misuse")}</b>
      {L(" 두 축의 근거로 정합니다. 빨간 규칙은 위험을 높이고 초록 규칙은 낮춥니다. 점선 회색은 아직 근거가 없는 항목이라 판단에서 빼지 않고 따로 보여 줍니다.", ". Red rules raise the risk and green rules lower it. Dashed gray rules have no evidence yet, so they are shown separately instead of being dropped.")}</span></Banner> : null}
    {axis(L("노출 정도", "Exposure"), exposure, "exposure", L("값이 얼마나 넓게, 오래 보였는지", "How widely and how long the value was visible"))}
    {axis(L("악용 가능성", "Likelihood of misuse"), likelihood, "likelihood", L("이 값으로 지금 무엇을 할 수 있는지", "What this value can do right now"))}
    {unknown.length ? <section className="card">
      <div className="axis-head"><h3>{L("판단 근거 없음", "No evidence yet")}</h3><InfoTip text={L("수집하지 않았거나 확인할 수 없는 항목입니다. 없음이나 안전으로 해석하지 않습니다.", "Not collected or not confirmable. Never read these as 'none' or 'safe'.")} />
        <span className="level l-none">{L(`${unknown.length}개`, String(unknown.length))}</span></div>
      <div className="card-body pad-top"><div className="rules">{unknown.map(rule => <RuleChip key={rule.id} rule={rule} onRule={onRule} />)}</div></div>
    </section> : null}
    {detail?.exposure_path?.stages.length ? <Card level={3} title={L("노출 단계", "Exposure stages")} info={L("노출부터 제거까지 여섯 단계에서 모은 관측입니다.", "Observations gathered at six stages, from exposure to removal.")}>
      <CardBody><Facts>{detail.exposure_path.stages.map(stage => stage.stage === "PRIVILEGED" && (iam.policyObserved || iam.simulationObserved || c.scopes?.length) ?
        <Fact key={stage.stage} label={L("권한", "Privilege")}>
          <span className="tone-warn">{iam.historical ? L("과거 관측", "Historical observation") : iam.partial ? L("부분 수집", "Partial collection") : L("관측됨", "Observed")}</span>
          <div className="subtle small">{iam.policyObserved ? L(`IAM 정책 ${iam.policies.length}개`, `${iam.policies.length} IAM policies`)
            : iam.simulationObserved ? L(`시뮬레이션 · 잠재 허용 ${iam.actions.length}개`, `Simulation · ${iam.actions.length} potentially allowed`)
              : L(`발급 서비스가 보고한 권한 ${c.scopes!.length}개`, `${c.scopes!.length} scopes reported`)}</div>
        </Fact> : <Fact key={stage.stage} label={L(...(STAGES[stage.stage] ?? [stage.stage, stage.stage]))}>
        <span className={cls(stage.state === "OBSERVED" && (stage.stage === "EXPOSED" || stage.stage === "USED") ? "tone-bad" : stage.state === "OBSERVED" ? "tone-warn" : "subtle")}>{L(...(STAGE_STATES[stage.state] ?? [stage.state, stage.state]))}</span>
        <div className="subtle small">{stageText(stage, L)}</div></Fact>)}</Facts></CardBody>
    </Card> : null}
    {details?.risk_score !== undefined ? <Card level={3} title={L("위험 점수 근거", "Risk score evidence")} meta={`${details.risk_score} / 100`}>
      <CardBody>
        {details.risk_evidence?.length ? <ul className="md-gaps">{details.risk_evidence.map(line => {
          const scored = scoreLine(line, L, type => typeLabel(type, L));
          return <li key={line}><b>{scored.dimension}</b> <span className="num">{scored.points}</span> · {scored.text}</li>;
        })}</ul> : null}
        {details.risk_missing_evidence?.length ? <><div className="rules-label" style={{ marginTop: 12 }}>{L("점수에 반영하지 못한 근거", "Evidence the score could not use")}</div>
          <div className="rules">{details.risk_missing_evidence.map(code => <span key={code} className="rule unknown small-rule">{missingEvidence(code, L)}</span>)}</div></> : null}
      </CardBody>
    </Card> : null}
  </>;
}

function RuleChip({ rule, onRule }: { rule: Rule; onRule: (rule: Rule) => void }) {
  return <button type="button" className={`rule ${rule.tone}`} data-tip={rule.desc} onClick={() => onRule(rule)}>{rule.label}</button>;
}

export const REVIEW_STATUS: Record<string, [string, string]> = { OPEN: ["조사 대기", "Awaiting review"], IN_PROGRESS: ["조사 중", "Investigating"], WAITING_OWNER: ["담당자 응답 대기", "Awaiting response"], CLOSED: ["조사 완료", "Review completed"] };
export const REVIEW_REASONS: Record<string, [string, string]> = { RESPONSIBLE_TEAM_CONFIRMED: ["대응 담당 팀 확인", "Responsible team confirmed"], CREDENTIAL_RETIRED: ["Credential 폐기 확인", "Credential retired"], NOT_ACTIONABLE: ["추가 조사 대상 아님", "No further review needed"] };

export function reviewStatusText(status: string, L: (ko: string, en: string) => string) {
  return L(...(REVIEW_STATUS[status] ?? [status, status]));
}

export function OwnerTab({ c, review, context, targets, owner: person, canEdit, onAssign, onContact, onNotify, onRecheck }: {
  c: CredentialRecord; review?: OwnershipReviewResponse; context?: FindingContext; targets: Target[]; owner?: Person; canEdit: boolean;
  onAssign: () => void; onContact: (people: Target[]) => void; onNotify: () => void; onRecheck?: () => void;
}) {
  const L = useL();
  const locale = useLocale();
  const [editing, setEditing] = useState(false);
  const sent = c.contact;
  const resp = (match?: (contact: NonNullable<CredentialRecord["contact"]>) => boolean) => sent && (!match || match(sent))
    ? <span className="resp sent"><span className="ring" /><span className="clip">{L(`${sent.channel === "slack" ? "Slack" : "메일"}로 연락함 · ${fmtDay(`${sent.due_at}T12:00:00Z`, locale)}까지 회신 요청`, `Contacted by ${sent.channel === "slack" ? "Slack" : "email"} · reply by ${fmtDay(`${sent.due_at}T12:00:00Z`, locale)}`)}</span></span>
    : <span className="resp"><span className="ring" />{L("응답 없음", "No response")}</span>;
  const owner = c.owner;
  // Where the owner works: the ownership review's team, else the IdP's department.
  const ownerTeam = owner?.team ?? person?.department ?? null;
  const candidates = review?.context.candidates ?? [];
  // The owner's own row reads by the directory's name when the IdP knows them.
  const others = targets.filter(target => target.name !== (person?.name ?? owner?.name ?? owner?.team));
  return <>
    {owner?.name || owner?.team ? <section className="card person-card">
      <div className="pc-top"><span className="pc-ic"><Ic name="users" size={22} /></span>
        <div className="pc-main"><div className="pc-title">{L("대응 담당자", "Response owner")}</div>
          <div className="pc-people"><Pill>{person?.name ?? owner.name ?? owner.team}{owner.name && ownerTeam ? <span className="subtle"> · {ownerTeam}</span> : null}</Pill>
            {person?.state === "DEPARTED" ? <span className="tag tone-bad" data-tip={L("IdP에서 퇴사로 확인된 사람입니다. 다른 담당자를 지정하세요.", "The IdP shows this person has left. Assign someone else.")}>{L("퇴사", "Left")}</span> : null}
            {canEdit ? <button type="button" className="icon-btn small-btn" onClick={onAssign} aria-label={L("담당자 바꾸기", "Change owner")} data-tip={L("담당자 바꾸기", "Change owner")}><Ic name="pencil" size={15} /></button> : null}</div>
          <div className="meta">{L("근거: ", "Basis: ")}{ownerBasis(c, L)}</div></div>
        {canEdit && c.finding_id ? <button type="button" className="link-btn" onClick={() => onContact(targets.slice(0, 1))}><Ic name="send" size={15} />{L("연락하기", "Contact")}</button> : null}
      </div>
      <div className="pc-foot">
        <div><div className="meta">{L("담당 확인", "Owner acknowledgement")}</div>{resp()}</div>
        <div><div className="meta">{L("사용 목적 소명", "Business justification")}</div>{resp(contact => contact.template === "purpose")}</div>
      </div>
    </section> : <section className="card person-card">
      <div className="pc-top"><span className="pc-ic"><Ic name="userQ" size={22} /></span>
        <div className="pc-main"><div className="pc-title">{L("대응 담당자 미확인", "Response owner unknown")}</div>
          <div className="meta">{L("CODEOWNERS·태그·관리자 지정에서 담당자를 찾지 못했습니다. 아래 사람에게 먼저 물어보거나 직접 지정하세요.", "No owner was found in CODEOWNERS, tags or admin assignments. Ask the people below first, or assign one directly.")}</div></div>
        {canEdit && c.finding_id ? <button type="button" className="ghost-btn" onClick={onAssign}><Ic name="userPlus" size={15} />{L("담당자 지정", "Assign owner")}</button> : null}
      </div>
    </section>}
    {others.length ? <Card level={3} title={L("함께 연락할 수 있는 사람", "Others you can contact")}>
      <div className="card-body other-list">{others.map(target => <div className="other-row" key={`${target.name}:${target.role}`}>
        <Pill>{target.name}{target.team ? <span className="subtle"> · {target.team}</span> : null}</Pill><span className="meta other-basis">{target.role} · {target.basis}</span>
        {canEdit && c.finding_id ? <button type="button" className="link-btn" onClick={() => onContact([target])}><Ic name="send" size={15} />{L("연락하기", "Contact")}</button> : null}
      </div>)}</div>
    </Card> : null}
    {c.finding_id && review ? <Card level={3} title={L("소유자 조사", "Ownership review")} right={canEdit && !editing ? <button type="button" className="link-btn" onClick={() => setEditing(true)}><Ic name="pencil" size={14} />{L("조사 정보 수정", "Edit review")}</button> : undefined}>
      <CardBody>
        {editing ? <ReviewEditor findingId={c.finding_id} review={review} candidates={candidates} onDone={() => setEditing(false)} /> : <Facts>
          <Fact label={L("조사 상태", "Review status")}>{reviewStatusText(review.review.status, L)}{review.review.due_at && review.review.status !== "CLOSED" && (time(review.review.due_at) ?? Infinity) < Date.now() ? <span className="tone-bad"> · {L("기한 지남", "overdue")}</span> : null}</Fact>
          <Fact label={L("담당 팀", "Responsible team")}>{review.review.assigned_team || <span className="subtle">{L("미배정", "Unassigned")}</span>}</Fact>
          <Fact label={L("조사 기한", "Due")}>{review.review.due_at ? fmtDT(review.review.due_at, locale) : <span className="subtle">—</span>}</Fact>
          {review.review.closed_reason ? <Fact label={L("완료 사유", "Completion reason")}>{L(...(REVIEW_REASONS[review.review.closed_reason] ?? [review.review.closed_reason, review.review.closed_reason]))}</Fact> : null}
          <Fact label={L("CODEOWNERS 후보", "CODEOWNERS candidates")} tip={review.context.codeowners_path ? `${review.context.repository ?? ""} · ${review.context.codeowners_path}` : undefined}>
            {candidates.length ? <span className="pill-wrap">{candidates.map(candidate => <Pill key={`${candidate.owner}:${candidate.line}`}>{candidate.owner}</Pill>)}</span>
              : <span className="subtle">{({ NO_CODEOWNERS: L("CODEOWNERS 파일 없음", "No CODEOWNERS file"), NOT_COLLECTED: L("수집 안 함", "Not collected"), UNSUPPORTED: L("이 위치는 지원하지 않음", "Not supported for this location"),
                UNAVAILABLE: L("읽지 못함", "Could not be read"), NOT_FOUND_OR_NOT_VISIBLE: L("저장소를 찾지 못함", "Repository not found"), TRUNCATED: L("파일이 너무 큼", "File too large"),
                FORBIDDEN: L("읽을 권한 없음", "No permission to read"), OBSERVED: L("일치하는 항목 없음", "No matching entry") } as Record<string, string>)[review.context.status] ?? "—"}</span>}</Fact>
        </Facts>}
      </CardBody>
    </Card> : null}
    <section className="card person-card">
      <div className="pc-top"><span className="pc-ic"><Ic name="key" size={22} /></span>
        <div className="pc-main"><div className="pc-title">{L("소유 계정", "Owning account")}</div>
          {c.issuer ? <><div className="pc-people"><Pill>{c.issuer.name}{c.issuer.role ? <span className="subtle"> · {c.issuer.role === "IAM_USER" ? L("IAM 사용자", "IAM user") : c.issuer.role}</span> : null}</Pill></div>
            <div className="meta">{L("근거: ", "Basis: ")}{c.issuer.basis === "VERIFIED_PRINCIPAL" ? L("검증 때 발급 서비스가 알려 준 소유 계정", "The owning account the issuer returned at verification") : `${serviceName(c.issuer.basis, c.issuer.basis)} ${L("발급 목록", "inventory")}`}</div></>
            : <div className="meta">{L("발급 서비스 목록을 연결하지 않아 소유 계정을 알 수 없습니다.", "No issuance inventory is connected, so the owning account is unknown.")}</div>}
        </div>
      </div>
    </section>
    <AccessCard c={c} context={context} canEdit={canEdit} onNotify={onNotify} onRecheck={onRecheck} />
    <section className="card"><div className="card-body pad-top"><Facts>
      <Fact label={L("발급 시각", "Issued at")}>{c.created_at ? fmtDT(c.created_at, locale) : <span className="subtle">{L("미확인", "Unknown")}</span>}</Fact>
      {c.issued?.provider === "aws_iam" ? <Fact label={L("키 생성자", "Key creator")} tip={L("CloudTrail CreateAccessKey 이벤트 근거입니다. 키 소유자와 다를 수 있습니다.", "CloudTrail CreateAccessKey evidence; may differ from the key owner.")}><CreatorSummary c={c} /></Fact> : null}
      <Fact label={L("마지막 사용", "Last used")} tip={c.last_used ? usageBasis(c, L) : usageGap(c, L)}>{c.last_used ? fmtDT(c.last_used.at, locale) : <span className="subtle">{lastUseGap(c, L) ?? L("미수집", "Not collected")}</span>}</Fact>
      <RecentSources c={c} />
    </Facts></div></section>
  </>;
}

/** Provider account observations retain each repository's evidence. */
export function accessTargets(context: FindingContext | undefined, L: (ko: string, en: string) => string): Target[] {
  return accessPeople(context).filter(person => !person.principal_kind || person.principal_kind === "USER").map(person => ({ name: person.name ?? person.login, role: L("관측된 공급자 계정", "Observed provider account"),
    basis: [person.repository, person.source_connection_id, accessBasis(person.basis, L), person.role].filter(Boolean).join(" · ") }));
}

function ReviewEditor({ findingId, review, candidates, onDone }: { findingId: string; review: OwnershipReviewResponse; candidates: { owner: string; kind: string }[]; onDone: () => void }) {
  const L = useL();
  const toast = useToast();
  const saved = useSaved();
  const [revision] = useState(review.review.revision);
  const [status, setStatus] = useState(review.review.status);
  const [team, setTeam] = useState(review.review.assigned_team ?? "");
  const due0 = review.review.due_at ? new Date(review.review.due_at) : null;
  const [due, setDue] = useState(due0 ? new Date(due0.getTime() - due0.getTimezoneOffset() * 60000).toISOString().slice(0, 16) : "");
  const [reason, setReason] = useState<string>(review.review.closed_reason ?? "");
  const [busy, setBusy] = useState(false);
  const problem = status !== "OPEN" && !team.trim() ? L("조사 대기 외에는 담당 팀이 필요합니다.", "A responsible team is required beyond Awaiting review.")
    : status === "WAITING_OWNER" && !due ? L("담당자 응답 대기에는 기한이 필요합니다.", "Awaiting response needs a due date.")
      : status === "CLOSED" && !reason ? L("완료 사유를 고르세요.", "Choose a completion reason.") : "";
  const save = async () => {
    setBusy(true);
    try {
      await send("ownership-reviews/bulk", "POST", { items: [{ finding_id: findingId, revision }], status, assigned_team: team.trim(),
        due_at: due ? new Date(due).toISOString() : null, closed_reason: status === "CLOSED" ? reason : "" });
      toast(L("소유자 조사를 저장했습니다.", "Saved the ownership review."));
      saved(); onDone();
    } catch (error) { toast(reasonText(error, L), "bad"); } finally { setBusy(false); }
  };
  return <>
    {revision !== review.review.revision ? <p className="meta tone-warn">{L("조사 정보가 변경됐습니다. 입력은 유지했습니다. 취소 후 다시 열어 최신 내용을 확인하세요.", "The review changed. Your input is kept. Cancel and reopen to review the latest version.")}</p> : null}
    <div className="row2">
      <SelectField label={L("조사 상태", "Review status")} value={status} onChange={value => setStatus(value)}
        options={Object.keys(REVIEW_STATUS).map(key => ({ id: key as typeof status, label: L(...REVIEW_STATUS[key]) }))} />
      <div className="field"><label htmlFor="rv-due">{L("조사 기한", "Due")}</label><input id="rv-due" type="datetime-local" value={due} onChange={event => setDue(event.target.value)} /></div>
    </div>
    <TextField label={L("담당 팀 (팀 이름만)", "Responsible team (team name only)")} value={team} onChange={setTeam} maxLength={128} />
    {candidates.some(candidate => candidate.kind === "TEAM") ? <div className="pill-wrap" style={{ marginTop: 8 }}>
      {candidates.filter(candidate => candidate.kind === "TEAM").map(candidate => <button type="button" key={candidate.owner} className="tag" onClick={() => setTeam(candidate.owner)}>{candidate.owner}</button>)}</div> : null}
    {status === "CLOSED" ? <SelectField label={L("완료 사유", "Completion reason")} value={reason} onChange={setReason}
      options={[{ id: "", label: L("사유 선택", "Choose a reason") }, ...Object.keys(REVIEW_REASONS).map(key => ({ id: key, label: L(...REVIEW_REASONS[key]) }))]} /> : null}
    {problem ? <p className="meta tone-warn">{problem}</p> : null}
    <div className="modal-foot">
      <button type="button" className="ghost-btn" onClick={onDone}>{L("취소", "Cancel")}</button>
      <button type="button" className="primary-btn" disabled={busy || Boolean(problem)} onClick={save}>{L("저장", "Save")}</button>
    </div>
  </>;
}

const STEP_LABEL: Record<StepState, [string, string]> = { open: ["열림", "Open"], progress: ["진행 중", "In progress"], done: ["완료", "Done"], na: ["해당 없음", "Not applicable"] };

export function RemedTab({ c, items, name, canEdit, onComment, extra }: {
  c: CredentialRecord; items: RemedItem[]; name: string; canEdit: boolean; onComment: (step: StepId, current: string) => void; extra?: ReactNode;
}) {
  const L = useL();
  const locale = useLocale();
  const toast = useToast();
  const saved = useSaved();
  const [banner, setBanner] = useState(true);
  const [closed, setClosed] = useState<Record<string, boolean>>({});
  const menu = useMenu();
  const [menuStep, setMenuStep] = useState<StepId | null>(null);
  const stateOf = (id: StepId) => {
    const stored = c.steps[id];
    if (c.status === "done" && (!stored || stored.status !== "na")) return { status: "done" as StepState, comment: stored?.comment ?? "", updated: stored?.updated_at ?? c.resolved_at };
    return { status: stored?.status ?? "open", comment: stored?.comment ?? "", updated: stored?.updated_at ?? c.first_seen_at ?? c.created_at };
  };
  const setStep = async (step: StepId, status: StepState) => {
    if (!c.finding_id) return;
    try {
      const current = await api<{ revision: number }>(`findings/${c.finding_id}/annotations`);
      await send(`findings/${c.finding_id}/remediation/${step}`, "PUT", { revision: current.revision, status });
      toast(L(`조치 상태를 '${L(...STEP_LABEL[status])}'(으)로 바꿨습니다.`, `Remediation status set to '${L(...STEP_LABEL[status])}'.`));
      saved();
    } catch (error) { toast(reasonText(error, L), "bad"); }
  };
  const copyGuide = async (item: RemedItem) => {
    const text = `${item.title}\n${plainSteps(item.steps, name, c.issuer?.name ?? name, c.hint ?? "")}`;
    try { await navigator.clipboard.writeText(text); toast(L("가이드를 복사했습니다.", "Guide copied.")); } catch { toast(L("복사하지 못했습니다.", "Could not copy."), "bad"); }
  };
  return <>
    {banner ? <Banner onClose={() => setBanner(false)}>{L("위험 근거에서 나온 권장 조치입니다. CreMore는 Credential을 직접 폐기하지 않고, 담당자가 수행한 결과를 기록합니다. 조직 상황에 맞는 단계를 고르세요.", "Recommended steps derived from the risk evidence. CreMore never revokes credentials itself; it records what the owner did. Pick the steps that fit your organization.")}</Banner> : null}
    {!items.length ? <section className="card"><div className="card-body pad-top muted">{L("남은 조치가 없습니다.", "No remaining actions.")}</div></section> : null}
    {items.map(item => {
      const state = stateOf(item.id), open = closed[item.id] !== true;
      return <section className="card remed-card" id={`guide-${item.id}`} key={item.id}>
        <div className="rc-head"><h3>{item.title}</h3>
          <button type="button" className={`rc-state s-${state.status}`} disabled={!canEdit || !c.finding_id} onClick={event => { setMenuStep(item.id); menu.open(event.currentTarget); }}>
            <span className="ring" /><span className="clip">{L(...STEP_LABEL[state.status])}</span><Ic name="down" size={13} /></button>
          <button type="button" className="icon-btn" aria-label={open ? L("접기", "Collapse") : L("펼치기", "Expand section")} onClick={() => setClosed(value => ({ ...value, [item.id]: open }))}><Ic name={open ? "up" : "down"} size={17} /></button>
        </div>
        {open ? <>
          <dl className="rc-grid">
            <div><dt>{L("관련 근거", "Related evidence")}</dt><dd><span className="rel-chip">{item.rule}</span></dd></div>
            <div><dt>{L("코멘트", "Comment")}</dt><dd>{state.comment ? <div className="comment-text">{state.comment}</div> : null}
              {canEdit && c.finding_id ? <button type="button" className="comment-btn" onClick={() => onComment(item.id, state.comment)}>{state.comment ? L("코멘트 수정", "Edit comment") : L("코멘트 추가", "Add comment")} <Ic name="pencil" size={14} /></button> : null}</dd></div>
            <div><dt>{L("관련 인원", "People involved")}</dt><dd className="pill-wrap">{item.people.length ? item.people.map(person => <Pill key={person}>{person}</Pill>) : <Pill unknown>{L("미확인", "Unknown")}</Pill>}</dd></div>
            <div><dt>{L("마지막 상태 변경", "Last status change")}</dt><dd className="num">{fmtDT(state.updated, locale)}</dd></div>
          </dl>
          <div className="guide"><div className="guide-head"><Ic name="wand" size={17} />{L("가이드", "Guide")}
            <button type="button" className="icon-btn" aria-label={L("가이드 복사", "Copy guide")} data-tip={L("가이드 복사", "Copy guide")} onClick={() => copyGuide(item)}><Ic name="copy" size={16} /></button></div>
            <ol>{item.steps.map((step, index) => <li key={index} dangerouslySetInnerHTML={{ __html: fillSteps(step, name, c.issuer?.name ?? name, c.hint ?? "") }} />)}</ol>
            {item.link ? <div className="guide-note"><a href={item.link[1]} target="_blank" rel="noopener noreferrer">{item.link[0]}{L(" 열기 ", " ")}<Ic name="ext" size={13} /></a></div> : null}
          </div>
        </> : null}
      </section>;
    })}
    {menu.anchor && menuStep ? <Menu anchor={menu.anchor} onClose={menu.close} restore={menu.opener} label={L("조치 상태", "Remediation status")}>
      {(Object.keys(STEP_LABEL) as StepState[]).map(status => <MenuItem key={status} onSelect={() => { menu.close(); void setStep(menuStep, status); }}
        end={stateOf(menuStep).status === status ? L("현재", "Current") : undefined}>{L(...STEP_LABEL[status])}</MenuItem>)}
    </Menu> : null}
    {extra}
  </>;
}

const EVENT_TEXT: Record<string, [string, string]> = {
  ACKNOWLEDGED: ["검토 시작", "Review started"], RESOLVED: ["조치 완료로 표시", "Marked remediated"], REOPENED: ["다시 열림", "Reopened"],
  FALSE_POSITIVE: ["오탐으로 표시", "Marked false positive"], IGNORED: ["예외로 처리", "Accepted as an exception"], ASSIGNED: ["대응 담당자 지정", "Response owner assigned"],
  TAGS_CHANGED: ["태그 변경", "Tags changed"], STAGE_CHANGED: ["처리 단계 변경", "Stage changed"], REMEDIATION_STEP: ["조치 상태 변경", "Remediation status changed"],
  COMMENT: ["코멘트", "Comment"], OWNER_CONTACTED: ["담당자에게 연락", "Owner contacted"], RESCAN_REQUESTED: ["다시 검사 요청", "Rescan requested"],
  OWNER_CONTACT_SENT: ["담당자에게 보냄", "Sent to the owner"], OWNER_CONTACT_FAILED: ["담당자 연락 발송 실패", "Owner contact not sent"],
  ROLLUP_UPDATED: ["노출 집계 갱신", "Exposure summary updated"], RISK_REEVALUATED: ["위험도 다시 계산", "Risk recalculated"],
  FORWARDED_TO_SIEM: ["SIEM·웹훅으로 보냄", "Sent to the SIEM and webhooks"], MANAGEMENT_ACTION_REQUESTED: ["관리 조치 요청", "Management action requested"],
  MANAGEMENT_ACTION_CONFIRMED: ["관리 조치 확인", "Management action confirmed"], MANAGEMENT_ACTION_REFUSED: ["관리 조치 확인 거절", "Management action confirmation refused"],
  TICKET_CREATED: ["티켓 생성", "Ticket opened"],
  TICKET_UPDATED: ["티켓 변경", "Ticket updated"], TICKET_APPROVED: ["티켓 검토 승인", "Ticket review approved"],
  AUTO_FALSE_POSITIVE: ["학습한 오탐 규칙으로 자동 처리", "Auto-triaged by a learned false-positive profile"],
  AUTO_FALSE_POSITIVE_REOPENED: ["자동 오탐 처리를 되돌림", "Auto-triage reversed"],
  OWNERSHIP_REVIEW_UPDATED: ["소유자 조사 변경", "Ownership review changed"],
  RESPONSE_REQUESTED: ["노출 제거 대응 요청", "Exposure cleanup requested"], RESPONSE_TICKET_OPENED: ["외부 대응 티켓 생성", "External response ticket opened"],
  RESPONSE_ASSIGNED: ["대응 담당자 지정", "Responder assigned"], RESPONSE_UNASSIGNED: ["대응 담당자 지정 해제", "Responder unassigned"],
  RESPONSE_RESPONSIBILITY_CHANGED: ["책임 규칙 변경", "Responsibility rule changed"],
  RESPONSE_LATE_TICKET_OPENED: ["지연된 티켓 생성 확인", "Delayed ticket creation confirmed"],
  RESPONSE_SEND_UNKNOWN: ["대응 요청 발송 결과 불확실", "Response delivery result uncertain"], RESPONSE_TICKET_CHECKED: ["대응 티켓 회신 확인", "Response ticket reply checked"],
  RESPONSE_LINK_SENT: ["대응 링크 발송", "Response link sent"], RESPONSE_NOT_SENT: ["대응 요청 발송 실패", "Response request not sent"],
  RESPONSE_ANSWER_REFUSED: ["지정한 담당자의 회신으로 인정하지 않음", "Reply not accepted as the designated responder's"],
  RESPONSE_CLEANUP_DECLARED: ["담당자가 제거 완료 회신 · 재검사 대기", "Responder reported cleanup; awaiting rescan"], RESPONSE_DECLINED: ["담당자가 대응 요청 거절", "Responder declined the request"],
  RESPONSE_SEND_RELEASED: ["관리자가 진행 중인 중복 요청이 없다고 확인한 기록", "Admin recorded their confirmation that no duplicate request is pending"],
  RESPONSE_REMOVAL_VERIFIED: ["재검사로 모든 노출 제거 확인", "Rescan confirmed removal from all locations"], RESPONSE_REAPPEARED: ["제거 후 노출 재발견", "Exposure found again after removal"],
  RESPONSE_STILL_EXPOSED: ["재검사에서 노출 잔존 확인", "Rescan found remaining exposure"],
  RESPONSE_REVIEW_STARTED: ["검토 시작", "Review started"], RESPONSE_REPORT_RECORDED: ["담당자 조치 보고 기록", "Responder action report recorded"],
  RESPONSE_EVIDENCE_UPDATED: ["조치 검증 근거 갱신", "Remediation evidence updated"], RESPONSE_COMPLETED: ["근거 확인 후 조치 완료", "Remediation completed with evidence"],
};
// Events whose notes only name internal records (an event, action or ticket ID): the label says it all.
const QUIET_NOTES = new Set(["FORWARDED_TO_SIEM", "MANAGEMENT_ACTION_REQUESTED", "MANAGEMENT_ACTION_CONFIRMED", "MANAGEMENT_ACTION_REFUSED", "TICKET_CREATED", "TICKET_UPDATED", "TICKET_APPROVED"]);
// Notes that are internal codes, not words someone wrote.
const CODE_NOTE = /^[A-Z0-9_:.-]+$/;

/** The team an ownership review's audit note names (``team="…" due=… reason=…``), quoted as JSON. */
export function reviewTeam(note: string | null | undefined) {
  const quoted = /^team=("(?:[^"\\]|\\.)*")/.exec(note ?? "");
  try { return quoted ? String(JSON.parse(quoted[1]!)) : ""; } catch { return ""; }
}

export function HistoryTab({ c, detail, typeName }: { c: CredentialRecord; detail?: Detail; typeName: string }) {
  const L = useL();
  const locale = useLocale();
  type Entry = { at: string; what: string; who?: string; dot?: "bad" | "ok" | "pri" | "" };
  const events: Entry[] = [];
  if (c.created_at) events.push({ at: c.created_at, what: L("발급됨", "Issued"), who: c.issuer ? `${serviceName(c.issued?.provider ?? c.provider, c.issued?.provider)} ${L("발급 목록", "inventory")}` : "", dot: "" });
  for (const e of c.exposures) if (e.first_seen_at) events.push({ at: e.first_seen_at, what: L(`노출 발견 · ${serviceName(exposureService(e.source_type))} ${e.resource_name}`, `Exposure found · ${serviceName(exposureService(e.source_type))} ${e.resource_name}`), who: L("검사", "Scan"), dot: "bad" });
  if (c.verification.at && c.verification.state !== "unknown") events.push({ at: c.verification.at, what: ({ active: L("활성 상태 확인", "Confirmed active"), revoked: L("폐기 확인", "Revocation confirmed"),
    inactive: L("비활성 상태 확인", "Confirmed inactive"), failed: L("인증 실패 확인", "Authentication failed"), expired: L("만료 확인", "Confirmed expired") } as Record<string, string>)[c.verification.state] ?? L("상태 확인", "Status checked"),
    who: verifyBasis(c, L), dot: c.verification.state === "active" ? "bad" : "ok" });
  for (const event of detail?.events ?? []) {
    const base = L(...(EVENT_TEXT[event.event_type] ?? [event.event_type, event.event_type]));
    const note = event.event_type === "COMMENT" ? `${base} · ${event.note ?? ""}`
      : event.event_type === "OWNERSHIP_REVIEW_UPDATED" ? [base, event.to_status ? reviewStatusText(event.to_status, L) : "", reviewTeam(event.note)].filter(Boolean).join(" · ")
      // channel · template · count · reply-by (a send's digests after these are for investigators, not this list)
      : (event.event_type === "OWNER_CONTACTED" || event.event_type === "OWNER_CONTACT_SENT") && event.note
      ? `${base} · ${event.note.split(" · ").slice(0, 4).map((part, index) => index === 0 ? (part === "slack" ? "Slack" : L("메일", "email")) : index === 1 ? templateLabel(part as never, L) : index === 2 ? L(`${part}명`, `${part} people`) : fmtDay(`${part}T12:00:00Z`, locale)).join(" · ")}`
      // channel · template · the code of what went wrong
      : event.event_type === "OWNER_CONTACT_FAILED" && event.note
      ? `${base} · ${event.note.split(" · ").map((part, index) => index === 0 ? (part === "slack" ? "Slack" : L("메일", "email")) : index === 1 ? templateLabel(part as never, L) : reasonText(new DashboardAPIError(part, 502), L)).join(" · ")}`
      : event.note && !CODE_NOTE.test(event.note) && event.event_type !== "ACKNOWLEDGED" && !QUIET_NOTES.has(event.event_type) ? `${base} · ${event.note}` : base;
    events.push({ at: event.created_at, what: note, who: actorLabel(event.actor, L), dot: event.event_type === "RESOLVED" ? "ok" : "pri" });
  }
  events.sort((a, b) => (time(b.at) ?? 0) - (time(a.at) ?? 0));
  return <Card level={3} title={L("이력", "History")} meta={L("최근 순", "Newest first")}>
    <ol className="timeline">{events.map((entry, index) => <li key={index}><span className={cls("dot", entry.dot)} />
      <div className="when num">{fmtDT(entry.at, locale)}</div><div className="what">{entry.what}</div>{entry.who ? <div className="who">{entry.who}</div> : null}</li>)}
      {!events.length ? <li><span className="dot" /><div className="what">{typeName}</div></li> : null}</ol>
  </Card>;
}
