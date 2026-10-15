/* What waits for someone's approval: AWS access key action plans (disable, delete, prepare and publish a
 * rotation), plans on another provider's credential (disable, revoke; cremore/remediation/provider_actions.py),
 * key rotation jobs, management actions and tickets whose playbook needs an independent Admin.
 * Types, words and who may act follow the server's own rules (cremore/remediation/action_plans.py,
 * cremore/api/routes/governance.py, cremore/governance/tickets.py); the server checks them again. */

import type { PlatformRole } from "@/lib/dashboard-session";
import type { Say } from "@/console/text";

export type ActionType = "DISABLE_ACCESS_KEY" | "DELETE_ACCESS_KEY" | "PREPARE_ACCESS_KEY_ROTATION" | "PUBLISH_ACCESS_KEY_ROTATION"
  | "DISABLE_PROVIDER_CREDENTIAL" | "REVOKE_PROVIDER_CREDENTIAL";
/** Actions on another provider's credential: queued, and run by the worker, which alone opens the credential that acts. */
export const PROVIDER_ACTIONS: ActionType[] = ["DISABLE_PROVIDER_CREDENTIAL", "REVOKE_PROVIDER_CREDENTIAL"];
/** Cannot be undone: a planned change with its acknowledgement, and the installation's deletion switch. */
export const isIrreversible = (action: string) => action === "DELETE_ACCESS_KEY" || action === "REVOKE_PROVIDER_CREDENTIAL";
export type PlanStatus = "PENDING_APPROVAL" | "APPROVED" | "QUEUED" | "EXECUTING" | "VERIFIED" | "FAILED" | "OUTCOME_UNKNOWN" | "CANCELLED" | "EXPIRED" | "BLOCKED";
export type Reason = "EXPOSURE_CONTAINMENT" | "SECURITY_INCIDENT" | "OWNER_REQUEST" | "OWNER_DEPARTED";
export type Consumer = {
  consumer_id: string; owner_id: string; evidence_id: string; environment: string; transition: string; authentication_basis: string;
  workload_succeeded: boolean; scheduled_cycle_checked: boolean; confirmed_at: string; valid_until: string;
};
export type Review = {
  deletion_acknowledged?: boolean; mode: "PLANNED" | "EMERGENCY"; scope_evidence_id: string; recovery_evidence_id: string; incident_id?: string;
  scope_complete: boolean; unknown_consumers: boolean; business_impact: string; impact_accepted: boolean; stop_criteria_reviewed: boolean;
  replacement_reviewed: boolean; window_start: string; window_end: string; consumers: Consumer[];
};
export type Readiness = { status: string; reasons: string[]; confirmed_consumers: number; declared_consumers: number; execution_gate_passed: boolean };
export type Rotation = { secret_arn: string; expected_current_version: string; preparation_plan_id?: string };
export type Plan = {
  id: string; credential_id: string; account_id: string; user_name: string; principal_arn: string; identifier_hint: string;
  action_type: ActionType; status: PlanStatus; reason_code: Reason; plan_hash: string; adapter_version?: string;
  requested_by: string; requested_at: string; approved_by?: string; approved_at?: string; self_approved?: boolean; expires_at: string;
  executed_at?: string; provider_write_started_at?: string; verified_at?: string; safe_error_code?: string; recheck_only?: boolean;
  operational_review?: Review; readiness?: Readiness; rotation?: Rotation; rotation_progress?: { stage: string; recorded_at: string }[];
  result_kind?: string; next_step?: string;
  /** What the plan is for: a discovered key or a departed owner's key (the queue says), or another provider's
   * credential by the identifiers its own list gives (every provider plan says, with the connection that acts). */
  target?: { kind: "credential" | "departed_owner" | "provider_credential"; credential_type?: string; provider?: string;
    entity_id?: string; object_id?: string; origin?: string; tenant?: string; hint?: string; connection_id?: string;
    connection_name?: string; auth_method?: string; subject?: string; reference?: Record<string, unknown>;
    /** What a revoke takes away when it is not the credential itself (an organization's grant to it). */
    revokes?: string };
  owner_approval?: OwnerApproval;
  /** An Admin's emergency containment without the owner's approval, and whether the owner was told after. */
  owner_emergency?: OwnerEmergency | null;
  /** Whether an Admin may contain this key at once (publicly exposed, owner approval still missing). */
  emergency_eligible?: boolean;
};
export type OwnerEmergency = {
  by: string; at: string; reason: string; noticed_at: string | null; noticed_by: string | null;
  notice_channel: "mail" | "slack" | "record" | null; notice_to: string | null; notice_evidence: string | null;
  /** Whether the declaration is what let the provider write start; only then is the owner told. */
  applied: boolean; notice_pending: boolean;
};
/** Actions whose users notice them wait for the owner's approval while the installation asks for it. */
export const OWNER_ACTIONS: ActionType[] = ["DISABLE_ACCESS_KEY", "DELETE_ACCESS_KEY", "PUBLISH_ACCESS_KEY_ROTATION", ...PROVIDER_ACTIONS];
export type OwnerApprovalState = "PENDING" | "APPROVED" | "DECLINED" | "EXPIRED" | "NOT_SENT" | "ANSWERED_BY_OTHER" | "NOT_INDEPENDENT";
/** "mail" | "slack": a link CreMore sent; "record": the local operator's record; otherwise the ticket system's id. */
type OwnerDecision = { state: OwnerApprovalState; channel: string; recipient: string; decided_at: string | null; note: string | null; evidence?: string | null };
/** The approval asked in the company's ticket system: its ticket, where it opens, and what the last read said. */
export type OwnerTicket = {
  system: string; ticket: string | null; approval: string | null; url: string | null; check_code: string | null;
  answered_by: string | null; answered_at: string | null;
};
/** The owner's decision (cremore/remediation/owner_approval.py): through the link CreMore sent, signed in with the
 * company account, in the company's ticket system, or recorded by the local operator with its evidence. A new
 * request keeps the last decline. */
export type OwnerApproval = OwnerDecision & {
  requested_by: string; requested_at: string; expires_at: string; previous?: OwnerDecision | null;
  /** Who decided through a link or a ticket (the local operator for a record). */
  decided_by?: string | null;
  ticket?: OwnerTicket | null;
};
export type Policy = {
  independent_authorization_required?: boolean;
  execution_enabled: boolean; single_operator?: boolean; auth_mode: string; supported_action?: string; supported_actions?: string[];
  rotation_execution_enabled?: boolean; rotation_secret_arns?: string[]; deletion_execution_enabled?: boolean;
  owner_approval_required?: boolean;
  /** The ticket system an owner's approval can be asked in (its name), or null. */
  owner_ticket_system?: string | null;
};
export type CredentialPolicy = Policy & { can_plan: boolean; can_delete?: boolean; block_reason?: string; deletion_block_reason?: string;
  /** Another provider's credential: the one integration set up to act on it, when there is one, and the scans or
   * collections that hold its very credential (warned, never refused). */
  remediation_connection?: { id: string; name: string; provider?: string; auth_method?: string;
    shared_with?: { id: string; name: string }[] } | null;
  /** What a revoke of it takes away when that is not the credential itself. */
  revokes?: string };
export type PlanList = { plans: Plan[]; policy: CredentialPolicy };
export type Queue = { items: Plan[]; policy: Policy };

export type RotationJob = {
  id: string; credential_id: string; status: "REQUESTED" | "PREPARED" | "PUBLISHED" | "FAILED" | string; phase: string;
  requested_by: string; approved_by: string | null; error: string | null; secret_arn: string; user_name: string; account_id: string;
  old_key_id: string; new_key_id: string; created_at: string; updated_at: string;
  /** Legacy jobs are history only, including responses from older servers. */
  read_only?: boolean; migration_required?: boolean; migration_code?: string; action_plan_path?: string;
  reconciliation_required?: boolean;
};
export type RotationProfile = { id: string; execution_enabled: boolean };
export type ManagementAction = {
  id: string; finding_id: string; action_type: string; status: string; requested_by: string | null; confirmed_by: string | null;
  note: string | null; created_at: string; updated_at: string;
};
export type Ticket = {
  id: string; credential_id: string | null; finding_id: string | null; orphan_ref: string | null; provider: string; credential_type: string;
  template_id: string; status: string; version: number; priority: string; service_impact: string; responsible_team: string;
  owner_id?: string; review_due_at: string; evidence: { kind: string; id: string }[]; steps: { code: string; status: string }[];
  created_by: string; created_at: string; updated_by: string; updated_at: string;
  playbook?: { config: { approval_rule: string } }; internal_approval?: { approved_by: string; approved_at: string }; review_digest?: string;
  /** Recorded through the API or the earlier panel; an update sends it back as it is. */
  security_review?: Record<string, string>;
};
export type TicketPage = { data: { items: Ticket[]; next_offset: number | null } };

export const PLANS_PATH = "action-plans";
export const ROTATIONS_PATH = "rotation-automation/jobs";
export const ROTATION_PROFILES_PATH = "rotation-automation/profiles";
export const MANAGEMENT_PATH = "management-actions";
export const TICKETS_PATH = "tickets";

export const KEY_TYPES = ["AWS_ACCESS_KEY", "AWS_ACCESS_KEY_ID"];
export const isRotation = (action: string) => action === "PREPARE_ACCESS_KEY_ROTATION" || action === "PUBLISH_ACCESS_KEY_ROTATION";
const CANCELLABLE: PlanStatus[] = ["PENDING_APPROVAL", "APPROVED", "QUEUED"];
const UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const VERSION = /^[A-Za-z0-9-]{32,64}$/;
export const isUuid = (value: string) => UUID.test(value);

/** A plan whose approval window passed reads as expired, as the server treats it. */
export function planStatus(plan: Plan, now = Date.now()): PlanStatus {
  if ((plan.status === "PENDING_APPROVAL" || plan.status === "APPROVED") && Date.parse(plan.expires_at) <= now) return "EXPIRED";
  return plan.status;
}

export function validRotation(action: string, binding?: Rotation) {
  if (!isRotation(action)) return binding === undefined;
  if (!binding || !binding.secret_arn.startsWith("arn:") || !VERSION.test(binding.expected_current_version)) return false;
  return action === "PREPARE_ACCESS_KEY_ROTATION" ? !binding.preparation_plan_id : Boolean(binding.preparation_plan_id && UUID.test(binding.preparation_plan_id));
}

/** ``ref``: the UUID reference tickets keep for this person (their created_by, updated_by and owner_id). */
export type Actor = { id: string; role: PlatformRole; ref?: string };
const remediates = (role: PlatformRole) => role === "Remediator" || role === "Admin";

/** Which of approve, execute, recheck and cancel this person may do now, and the first reason when they may not. */
export function planPermissions(plan: Plan, policy: Policy, actor: Actor, L: Say, now = Date.now()) {
  const status = planStatus(plan, now);
  const auth = policy.auth_mode.toLowerCase();
  const single = policy.single_operator === true && auth === "local";
  const identity = single || auth === "oidc";
  const rotation = isRotation(plan.action_type), deleting = isIrreversible(plan.action_type);
  // Another provider's credential names itself; the installation's AWS list does not cover it.
  const provider = plan.target?.kind === "provider_credential";
  const supported = provider ? PROVIDER_ACTIONS.includes(plan.action_type)
    : deleting ? Boolean(policy.supported_actions?.includes(plan.action_type)) && !plan.rotation
      : rotation ? Boolean(policy.supported_actions?.includes(plan.action_type) && plan.rotation && policy.rotation_secret_arns?.includes(plan.rotation.secret_arn))
        : plan.action_type === "DISABLE_ACCESS_KEY";
  const ready = plan.readiness?.execution_gate_passed === true;
  const approvedBy = Boolean(plan.approved_by) && (single || plan.approved_by !== plan.requested_by);
  const enabled = policy.execution_enabled && (!rotation || policy.rotation_execution_enabled === true) && (!deleting || policy.deletion_execution_enabled === true);
  const recheckEnabled = policy.execution_enabled && (!rotation || policy.rotation_execution_enabled === true);
  const written = Boolean(plan.provider_write_started_at);
  // Whoever decided as the key's owner through a link does not also approve for the security team.
  const ownerDecider = plan.owner_approval?.channel !== "record" ? plan.owner_approval?.decided_by ?? null : null;
  const approve = status === "PENDING_APPROVAL" && supported && ready && identity && !written && actor.role === "Admin" && (single || actor.id !== plan.requested_by)
    && actor.id !== ownerDecider;
  const ownerWaits = policy.owner_approval_required === true && OWNER_ACTIONS.includes(plan.action_type) && plan.owner_approval?.state !== "APPROVED";
  const runnable = status === "APPROVED" && supported && ready && identity && !written && enabled && approvedBy;
  // The server refuses a plan whose owner also requested or approved it, whatever order those landed in.
  const ownerAlsoActed = Boolean(ownerDecider) && (ownerDecider === plan.approved_by || ownerDecider === plan.requested_by);
  const execute = runnable && !ownerWaits && !ownerAlsoActed && remediates(actor.role);
  // An Admin contains a publicly exposed key at once; the owner is told afterwards.
  const emergency = runnable && ownerWaits && plan.emergency_eligible === true && actor.role === "Admin";
  const notice = Boolean(plan.owner_emergency?.notice_pending) && remediates(actor.role);
  const recheck = status === "OUTCOME_UNKNOWN" && supported && identity && recheckEnabled && remediates(actor.role) && approvedBy;
  const cancel = CANCELLABLE.includes(status) && !written && !plan.recheck_only && remediates(actor.role);
  const why = status === "PENDING_APPROVAL"
    ? !identity ? L("이 로그인 방식에서는 계획을 승인할 수 없습니다.", "This sign-in method cannot approve plans.")
      : actor.role !== "Admin" ? L("관리자가 승인합니다.", "An Admin approves plans.")
        : !single && actor.id === plan.requested_by ? L("요청한 사람과 다른 관리자가 승인합니다.", "A different Admin than the requester approves.")
          : actor.id === ownerDecider ? L("키 소유자로 결정한 사람은 계획을 승인하지 않습니다.", "Whoever decided as the key's owner does not approve the plan.")
          : !ready ? L("운영 검토에 채울 항목이 남았습니다.", "The operational review has items left to complete.") : ""
    : status === "APPROVED" ? !enabled ? L("설치 설정에서 이 조치의 실행이 꺼져 있습니다.", "This installation has execution of this action turned off.")
      : !remediates(actor.role) ? L("조치 담당자 또는 관리자가 실행합니다.", "A Remediator or Admin executes plans.")
        : ownerWaits ? L("키 소유자의 승인을 받아야 실행할 수 있습니다.", "The key's owner approves before it runs.")
          : ownerAlsoActed ? L("키 소유자로 결정한 사람이 이 계획을 요청하거나 승인해 실행할 수 없습니다.", "Whoever decided as the key's owner also requested or approved this plan, so it cannot run.") : ""
      : "";
  const askOwner = (status === "PENDING_APPROVAL" || status === "APPROVED") && remediates(actor.role) && plan.owner_approval?.state !== "APPROVED";
  return { approve, execute, recheck, cancel, askOwner, emergency, notice, why };
}

/* ---------- words ---------- */

export const ACTION_WORDS: Record<ActionType, [string, string]> = {
  DISABLE_ACCESS_KEY: ["액세스 키 비활성화", "Disable the access key"],
  DELETE_ACCESS_KEY: ["비활성 키 영구 삭제", "Delete the inactive key"],
  PREPARE_ACCESS_KEY_ROTATION: ["교체할 새 키 준비", "Prepare a replacement key"],
  PUBLISH_ACCESS_KEY_ROTATION: ["새 키를 Secret에 게시", "Publish the new key to the Secret"],
  DISABLE_PROVIDER_CREDENTIAL: ["자격증명 비활성화", "Disable the credential"],
  REVOKE_PROVIDER_CREDENTIAL: ["자격증명 영구 폐기", "Revoke the credential for good"],
};
/** A revoke that ends one organization's grant, not the credential (cremore/remediation/provider_actions.py). */
const REVOKES_WORDS: Record<string, [string, string]> = { ORGANIZATION_ACCESS: ["조직 접근 회수", "Revoke its organization access"] };
/** The action in words; a revoke says what it takes away when that is not the credential itself. */
export function actionWords(action: ActionType, revokes?: string): [string, string] {
  return action === "REVOKE_PROVIDER_CREDENTIAL" && revokes && REVOKES_WORDS[revokes] ? REVOKES_WORDS[revokes] : ACTION_WORDS[action];
}
/** What a provider plan's result code means (cremore/remediation/action_plans.py run_queued); others show as codes. */
export const RESULT_CODE_WORDS: Record<string, [string, string]> = {
  CREDENTIAL_NOT_DISABLED: ["먼저 비활성화한 키만 영구 삭제합니다 · 비활성화 계획부터 실행하세요", "Only a disabled key is deleted · run a disable plan first"],
  CREDENTIAL_ALREADY_DISABLED: ["이미 비활성화돼 있어 바꾸지 않았습니다", "Already disabled, so nothing was changed"],
  CREDENTIAL_ALREADY_REVOKED: ["이미 폐기돼 있어 바꾸지 않았습니다", "Already revoked, so nothing was changed"],
  CREDENTIAL_EXPIRED: ["이미 만료돼 쓸 수 없어 바꾸지 않았습니다", "Already expired and unusable, so nothing was changed"],
  CREDENTIAL_ABSENT: ["공급자에 더 이상 없어 바꾸지 않았습니다", "The provider no longer has it, so nothing was changed"],
  REMEDIATION_CONNECTION_UNAVAILABLE: ["승인 때 정한 조치용 연동을 쓸 수 없어 실행하지 않았습니다", "The integration approved to act is no longer usable, so it did not run"],
  EXECUTION_INTERRUPTED: ["작업자가 쓰기 뒤 확인 전에 멈췄습니다 · 상태를 다시 확인하세요", "The worker stopped between the write and its read-back · recheck the state"],
  PLAN_EXPIRED: ["실행을 기다리는 동안 계획 기한이 지났습니다", "The plan expired while it waited to run"],
  EXECUTION_DISABLED: ["실행을 기다리는 동안 이 설치의 실행이 꺼졌습니다", "Execution was turned off while it waited"],
  DELETION_DISABLED: ["실행을 기다리는 동안 이 설치의 영구 삭제가 꺼졌습니다", "Deletion was turned off while it waited"],
  READINESS_GATE_FAILED: ["실행 때 운영 검토 조건이 맞지 않았습니다(변경 시간창 등)", "The operational review did not hold when it ran (the change window, for one)"],
  CREDENTIAL_UNAVAILABLE: ["조치용 연동의 저장된 자격증명을 열지 못했습니다", "The acting integration's stored credential could not be opened"],
  GCP_PERMISSION_DENIED: ["Google Cloud가 권한 부족으로 거절했습니다", "Google Cloud refused it for missing permissions"],
  GITLAB_PERMISSION_DENIED: ["GitLab이 권한 부족으로 거절했습니다", "GitLab refused it for missing permissions"],
  REMEDIATION_CONNECTION_CHANGED: ["승인 뒤 조치용 연동의 로그인 방식이나 계정이 바뀌어 실행하지 않았습니다", "The acting integration's sign-in or account changed after approval, so it did not run"],
  GITLAB_TARGET_NOT_VISIBLE: ["조치용 토큰이 이 토큰의 그룹·프로젝트를 볼 수 없어 없어졌는지 판단하지 않았습니다", "The acting token cannot see this token's group or project, so its absence is not concluded"],
  WORKER_ERROR: ["작업자가 실행 전에 멈춰 아무것도 쓰지 않았습니다", "The worker stopped before running it; nothing was written"],
  GCP_ACCOUNT_NOT_IN_PROJECT: ["서비스 계정이 계획의 프로젝트 소속이 아니어서 건드리지 않았습니다", "The service account is not the plan's project's own, so it was not touched"],
  STATE_ACTIVE: ["쓰기 뒤 다시 읽었을 때 아직 활성이었습니다 · 상태를 다시 확인하세요", "It still read as active after the write · recheck the state"],
  NOTION_PERMISSION_DENIED: ["Notion이 권한 부족으로 거절했습니다(조직 봇의 읽기·폐기 범위)", "Notion refused it for missing scopes (the org bot's read and revoke scopes)"],
  GITHUB_PERMISSION_DENIED: ["GitHub이 권한 부족으로 거절했습니다(App의 개인 액세스 토큰 쓰기 권한)", "GitHub refused it for missing permissions (the App's Personal access tokens: write)"],
  AZURE_DEVOPS_PERMISSION_DENIED: ["Azure DevOps가 권한 부족으로 거절했습니다(토큰 관리 범위, 프로젝트 컬렉션 관리자)", "Azure DevOps refused it for missing permissions (token administration, Project Collection Administrator)"],
  NOTION_WORKSPACE_NOT_VISIBLE: ["조치용 봇이 이 워크스페이스를 볼 수 없어 없어졌는지 판단하지 않았습니다", "The acting bot cannot see this workspace, so its absence is not concluded"],
  GITHUB_ORGANIZATION_NOT_VISIBLE: ["조치용 App이 이 조직을 볼 수 없어 없어졌는지 판단하지 않았습니다", "The acting App cannot see this organization, so its absence is not concluded"],
  AZURE_DEVOPS_OWNER_NOT_VISIBLE: ["토큰 소유자가 조직 사용자 목록에 없어 토큰을 다시 읽지 못했습니다", "The token's owner is no longer an organization user, so the token could not be read back"],
};

/** The words for a plan's result code, when there are some; an organization's grant is named as such. */
export function resultCodeWords(plan: Plan): [string, string] | undefined {
  const code = plan.safe_error_code ?? "";
  if (code === "CREDENTIAL_ABSENT" && plan.target?.revokes === "ORGANIZATION_ACCESS")
    return ["계획이 가리킨 조직 접근 승인이 이미 없어 바꾸지 않았습니다", "The grant this plan names no longer exists, so nothing was changed"];
  return RESULT_CODE_WORDS[code];
}

/** What the provider's own list names the credential by, as the plan binds it (identifiers only). */
export function referenceText(plan: Plan): string {
  const shown = (value: unknown): string => value && typeof value === "object"
    ? Object.values(value as Record<string, unknown>).map(shown).join(" ") : String(value);
  return Object.entries(plan.target?.reference ?? {}).filter(([name]) => !["hint", "key", "listed_in"].includes(name))
    .map(([name, value]) => `${name} ${shown(value)}`).join(" · ");
}
export const STATUS_WORDS: Record<PlanStatus, [string, string]> = {
  PENDING_APPROVAL: ["승인 대기", "Awaiting approval"], APPROVED: ["승인됨 · 실행 대기", "Approved · awaiting execution"],
  QUEUED: ["실행 접수", "Execution queued"], EXECUTING: ["실행 중", "Executing"], VERIFIED: ["완료 확인", "Verified"],
  FAILED: ["실패", "Failed"], OUTCOME_UNKNOWN: ["결과 재확인 필요", "Result needs a recheck"], CANCELLED: ["취소됨", "Cancelled"],
  EXPIRED: ["기한 지남", "Expired"], BLOCKED: ["정책에 막힘", "Blocked by policy"],
};
export const STATUS_TONE: Record<PlanStatus, "ok" | "warn" | "partial" | "running" | undefined> = {
  PENDING_APPROVAL: "warn", APPROVED: "running", QUEUED: "running", EXECUTING: "running", VERIFIED: "ok", FAILED: "partial",
  OUTCOME_UNKNOWN: "partial", CANCELLED: undefined, EXPIRED: undefined, BLOCKED: "partial",
};
export const OWNER_WORDS: Record<OwnerApprovalState, [string, string]> = {
  PENDING: ["결정 대기", "Waiting"], APPROVED: ["승인함", "Approved"], DECLINED: ["거절함", "Declined"],
  EXPIRED: ["기한 지남", "Expired"], NOT_SENT: ["보내지 못함", "Not sent"],
  ANSWERED_BY_OTHER: ["다른 사람이 응답함", "Answered by someone else"],
  NOT_INDEPENDENT: ["보안 측과 구별 안 됨", "Not independent"],
};
export const OWNER_TONE: Record<OwnerApprovalState, "ok" | "warn" | "partial" | "running" | undefined> = {
  PENDING: "running", APPROVED: "ok", DECLINED: "partial", EXPIRED: undefined, NOT_SENT: "partial", ANSWERED_BY_OTHER: "warn",
  NOT_INDEPENDENT: "warn",
};
export const REASON_WORDS: Record<Reason, [string, string]> = {
  EXPOSURE_CONTAINMENT: ["노출 차단", "Contain the exposure"], SECURITY_INCIDENT: ["보안 사고 대응", "Security incident"],
  OWNER_REQUEST: ["담당자 요청", "The owner asked"], OWNER_DEPARTED: ["소유자 퇴사", "The owner left"],
};
export const READINESS_WORDS: Record<string, [string, string]> = {
  CHANGE_REVIEW_REQUIRED: ["운영 검토가 없습니다", "No operational review"],
  CHANGE_REVIEW_INVALID: ["운영 검토 형식이 맞지 않습니다", "The operational review is malformed"],
  CHANGE_WINDOW_NOT_CURRENT: ["지금은 변경 시간창 밖입니다", "Outside the change window"],
  IMPACT_AND_RECOVERY_REVIEW_REQUIRED: ["업무 영향·복구·중단 기준 검토가 필요합니다", "Review impact, recovery and stop criteria"],
  CONSUMER_SCOPE_INCOMPLETE: ["사용처 조사가 끝나지 않았습니다", "The consumer survey is not complete"],
  REPLACEMENT_REVIEW_REQUIRED: ["대체 인증 방식을 검토하지 않았습니다", "The replacement authentication is not reviewed"],
  EMPTY_CONSUMER_SCOPE: ["사용처를 한 곳 이상 적어야 합니다", "List at least one consumer"],
  CONSUMER_TRANSITION_NOT_CONFIRMED: ["새 자격증명으로 전환·업무 성공을 확인하지 않은 사용처가 있습니다", "A consumer has not confirmed its switch and workload success"],
  CONSUMER_EVIDENCE_NOT_CURRENT: ["근거 기간이 지난 사용처가 있습니다", "A consumer's evidence is out of date"],
  EMERGENCY_INCIDENT_REQUIRED: ["긴급 조치에는 사고 ID가 필요합니다", "An emergency action needs an incident ID"],
  DELETE_PLANNED_ACKNOWLEDGEMENT_REQUIRED: ["영구 삭제는 계획 변경과 삭제 확인이 필요합니다", "Deletion needs a planned change and an acknowledgement"],
  ROTATION_PLANNED_REVIEW_REQUIRED: ["키 교체는 계획 변경으로만 진행합니다", "Rotation runs only as a planned change"],
};
export const RESULT_WORDS: Record<string, [string, string]> = {
  SUCCESSOR_PREPARED_OLD_KEY_ACTIVE: ["새 키 준비 완료 · 기존 키는 그대로", "Replacement prepared · old key unchanged"],
  SUCCESSOR_PUBLISHED_OLD_KEY_ACTIVE: ["Secret 게시 완료 · 기존 키는 그대로", "Published to the Secret · old key unchanged"],
  PROVIDER_OUTCOME_UNKNOWN_OLD_KEY_NOT_DISABLED: ["결과 재확인 필요 · 기존 키는 그대로", "Result needs a recheck · old key unchanged"],
  ROTATION_NOT_COMPLETED: ["교체 단계를 마치지 못함", "Rotation phase not finished"],
};
export const NEXT_WORDS: Record<string, [string, string]> = {
  INDEPENDENTLY_APPROVE_PUBLISH: ["게시 계획을 따로 요청해 승인받습니다", "Request a publish plan and get it approved"],
  VERIFY_CONSUMER_TRANSITION_BEFORE_DISABLE: ["사용처가 새 키로 바뀐 것을 확인한 뒤 비활성화 계획을 요청합니다", "Confirm the consumers switched, then request a disable plan"],
  READ_ONLY_RECHECK_NO_WRITE_RETRY: ["상태만 다시 확인합니다", "Recheck the state only"],
  REVIEW_ACTION_STATE: ["이 단계의 상태를 확인합니다", "Review this phase's state"],
};
export const STAGE_WORDS: Record<string, [string, string]> = {
  CREATED: ["새 키 생성", "Replacement created"], VALIDATED: ["새 키 신원 확인", "Replacement identity checked"],
  PENDING_WRITE_STARTED: ["AWSPENDING 기록 시작", "AWSPENDING write started"], PENDING_CONFIRMED: ["AWSPENDING 확인", "AWSPENDING confirmed"],
  PROMOTE_STARTED: ["AWSCURRENT 승격 시작", "AWSCURRENT promotion started"], PROMOTE_CONFIRMED: ["AWSCURRENT 확인", "AWSCURRENT confirmed"],
};
export const ROTATION_WORDS: Record<string, [string, string]> = {
  REQUESTED: ["승인 대기", "Awaiting approval"], PREPARED: ["준비 완료 · 게시 대기", "Prepared · awaiting publish"],
  PUBLISHED: ["게시 완료", "Published"], FAILED: ["실패", "Failed"],
};
export const MANAGEMENT_WORDS: Record<string, [string, string]> = {
  ACKNOWLEDGE_OWNER: ["담당자 확인", "Owner acknowledgement"], ROTATE: ["키 교체", "Rotate the key"],
  PENDING: ["확인 대기", "Awaiting confirmation"], CONFIRMED: ["확인됨", "Confirmed"], EXECUTED: ["실행됨", "Executed"], REJECTED: ["거절됨", "Rejected"],
};
export const TICKET_WORDS: Record<string, [string, string]> = {
  PUBLIC_EXPOSURE: ["공개 노출 대응", "Public exposure"], EXCESSIVE_SHARING: ["내부 과다 공유", "Excessive internal sharing"],
  PERSONAL_PAT_SERVICE_USE: ["서비스의 개인 PAT 사용", "Personal PAT used by a service"], DEFERRED_REPLACEMENT: ["교체 보류", "Deferred replacement"],
  DEPARTED_OWNER: ["퇴사자 Credential", "Departed owner"], CUSTOM: ["직접 정한 검토", "Custom review"],
  OPEN: ["접수", "Open"], IN_PROGRESS: ["진행 중", "In progress"], WAITING_OWNER: ["담당자 확인 대기", "Waiting for the owner"],
  WAITING_APPROVAL: ["조치 승인 대기", "Waiting for action approval"], NEEDS_ATTENTION: ["확인 필요", "Needs attention"], RESOLVED: ["검토 완료", "Resolved"],
};

export const STEP_WORDS: Record<string, [string, string]> = {
  CONFIRM_OWNER_AND_TARGET: ["담당자와 관리 대상 확인", "Confirm the owner and the target"], REVIEW_CONTAINMENT: ["제한 조치와 서비스 영향 검토", "Review containment and service impact"],
  REVIEW_PROVIDER_ACTION: ["공급자 조치 근거 검토", "Review the provider action evidence"], REVIEW_SOURCE_AND_HISTORY_CLEANUP: ["원본과 이력 정리 검토", "Review source and history cleanup"],
  INVESTIGATE_IMPACT: ["관측된 영향 조사", "Investigate observed impact"], REVIEW_REVALIDATION: ["후속 검증 근거 검토", "Review new verification evidence"],
  REVIEW_SHARING_SCOPE: ["실제 공유 범위 검토", "Review the sharing scope"], ASSIGN_RESPONSIBILITY: ["책임 담당자 지정", "Assign responsibility"],
  REVIEW_SERVICE_AUTH_MIGRATION: ["서비스·앱 인증으로 이전 검토", "Review moving to service or app authentication"], REVIEW_CONSUMER_ADOPTION: ["새 인증 채택 근거 검토", "Review adoption evidence"],
  REVIEW_SUPPORTED_RESTRICTIONS: ["공급자가 지원하는 제한 검토", "Review the provider's restrictions"], SET_FOLLOW_UP: ["후속 검토 기한 설정", "Set a follow-up date"],
  REVIEW_APPROVAL: ["공급자 조치 승인 검토", "Review the provider action approval"],
  TODO: ["검토 전", "To review"], REVIEWED: ["검토함", "Reviewed"], NOT_APPLICABLE: ["해당 없음", "Not applicable"],
};

export const say = (words: Record<string, [string, string]>, key: string, L: Say) => words[key] ? L(...words[key]) : key;

/** A ticket an independent Admin still has to approve before it can be resolved. */
export const ticketNeedsApproval = (ticket: Ticket) =>
  ticket.playbook?.config.approval_rule === "INDEPENDENT_ADMIN" && !ticket.internal_approval && ticket.status !== "RESOLVED";

/* ---------- a new plan's review ---------- */

/** A datetime-local value for this device, from an ISO time. */
export function localInput(iso: string) {
  const date = new Date(iso);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
}

export function blankConsumer(now = Date.now()): Consumer {
  return { consumer_id: "", owner_id: "", evidence_id: "", environment: "PRODUCTION", transition: "UNKNOWN", authentication_basis: "UNKNOWN",
    workload_succeeded: false, scheduled_cycle_checked: false, confirmed_at: localInput(new Date(now).toISOString()),
    valid_until: localInput(new Date(now + 7 * 86_400_000).toISOString()) };
}

export function blankReview(now = Date.now()): Review {
  return { mode: "PLANNED", scope_evidence_id: "", recovery_evidence_id: "", scope_complete: false, unknown_consumers: false, business_impact: "UNKNOWN",
    impact_accepted: false, stop_criteria_reviewed: false, replacement_reviewed: false, window_start: localInput(new Date(now).toISOString()),
    window_end: localInput(new Date(now + 4 * 3_600_000).toISOString()), consumers: [blankConsumer(now)] };
}

/** The review as the API takes it (times in ISO), or the first thing that keeps it from being sent. */
export function reviewBody(review: Review, action: ActionType, L: Say): { body?: Review; problem?: string } {
  const rotation = isRotation(action), deleting = isIrreversible(action);
  const iso = (value: string) => { const at = Date.parse(value); return Number.isFinite(at) ? new Date(at).toISOString() : ""; };
  if (!isUuid(review.scope_evidence_id) || !isUuid(review.recovery_evidence_id)) return { problem: L("조사 범위·복구 계획 근거 ID는 UUID로 적습니다.", "Scope and recovery evidence IDs are UUIDs.") };
  if (review.mode === "EMERGENCY" && review.incident_id && !isUuid(review.incident_id)) return { problem: L("사고 ID는 UUID로 적습니다.", "The incident ID is a UUID.") };
  const start = iso(review.window_start), end = iso(review.window_end);
  if (!start || !end || Date.parse(end) <= Date.parse(start)) return { problem: L("변경 종료는 시작보다 뒤여야 합니다.", "The change window must end after it starts.") };
  if (deleting && !review.deletion_acknowledged) return { problem: action === "REVOKE_PROVIDER_CREDENTIAL"
    ? L("되돌릴 수 없음 확인에 체크해야 합니다.", "Acknowledge that it cannot be undone.")
    : L("영구 삭제 확인에 체크해야 합니다.", "Acknowledge the permanent deletion.") };
  const seen = new Set<string>();
  const consumers: Consumer[] = [];
  for (const consumer of review.consumers) {
    if (!isUuid(consumer.consumer_id) || !isUuid(consumer.owner_id) || (consumer.evidence_id && !isUuid(consumer.evidence_id)))
      return { problem: L("사용처·확인 담당자·근거 ID는 UUID로 적습니다.", "Consumer, owner and evidence IDs are UUIDs.") };
    const key = `${consumer.consumer_id}/${consumer.environment}`;
    if (seen.has(key)) return { problem: L("같은 사용처·환경을 두 번 적었습니다.", "A consumer and environment appear twice.") };
    seen.add(key);
    const confirmed = rotation ? "0001-01-01T00:00:00Z" : iso(consumer.confirmed_at), valid = rotation ? "0001-01-01T00:00:00Z" : iso(consumer.valid_until);
    if (!rotation && (!confirmed || !valid || Date.parse(valid) <= Date.parse(confirmed))) return { problem: L("사용처 근거의 유효 종료는 확인 시각보다 뒤여야 합니다.", "A consumer's evidence must stay valid after it was confirmed.") };
    consumers.push({ ...consumer, transition: rotation ? "PENDING" : consumer.transition, authentication_basis: rotation ? "UNKNOWN" : consumer.authentication_basis,
      workload_succeeded: !rotation && consumer.workload_succeeded, scheduled_cycle_checked: !rotation && consumer.scheduled_cycle_checked, confirmed_at: confirmed, valid_until: valid });
  }
  const { incident_id, deletion_acknowledged, ...rest } = review;
  return { body: { ...rest, ...(review.mode === "EMERGENCY" ? { incident_id: incident_id ?? "" } : {}), ...(deleting ? { deletion_acknowledged: Boolean(deletion_acknowledged) } : {}),
    window_start: start, window_end: end, consumers } };
}
