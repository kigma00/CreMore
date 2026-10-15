"use client";

/* The permissions card's rows where the service gives no scopes of its own but a usage lookup read them: an AWS access
 * key's identity policies (its user's or role's, as IAM holds them; investigation/identity_policies.py) and, where the
 * installation allows it, the high-impact actions IAM's policy simulator allows (potential access: what the policies
 * permit, not what was done; investigation/potential_access.py). */

import type { CredentialPotentialAccess, CredentialPotentialAction, IdentityPolicyStatement } from "@/lib/dashboard-types";
import { useLocale } from "@/components/locale";
import { DetailPopover } from "@/console/layer";
import { awsPermissionEvidence, type CredentialRecord, iamPolicyLabel } from "@/console/records";
import { fmtDT, type Say, useL } from "@/console/text";
import { Banner } from "@/console/ui";

type Usage = NonNullable<CredentialRecord["aws_permissions"]> & { collection_status?: string };

type Row = { key: string; service: string; permission: string; source: string; allows: string; tag: string | null };
type Note = { tone: "bad" | "ok" | "warn" | undefined; text: string };

/** The KMS keys an identity policy allows `action` on whose key policy does not let IAM policies grant it
 * (investigation/potential_access.py: NamedResource.key_policy_blocks). */
export const blockedKeys = (potential: CredentialPotentialAccess | undefined, action: string) =>
  (potential?.named_resources ?? []).filter(named => named.key_policy_blocks?.includes(action)).map(named => named.resource);

/** The KMS keys `action` was simulated on whose key policy could not be read: judged by the identity policies alone. */
export const unreadKeys = (potential: CredentialPotentialAccess | undefined, action: string) =>
  (potential?.named_resources ?? []).filter(named => named.resource.split(":")[2] === "kms" && named.resource_policy === "NOT_READ"
    && named.actions.includes(action)).map(named => named.resource);

/** The named resources where `action` got no answer because a condition needs request context the simulation lacked. */
export const conditionalOn = (potential: CredentialPotentialAccess | undefined, action: string) =>
  (potential?.named_resources ?? []).filter(named => named.conditional?.includes(action));

export function simulationDecision(action: CredentialPotentialAction, L: Say, blocked = 0) {
  const named = action.resource_scope === "NAMED" ? action.resources?.length ?? 0 : 0;
  const decision = action.decision === "ALLOWED" ? (named ? L(`지정 리소스 ${named}개에서 허용 (잠재 권한)`, `Allowed on ${named} named resource${named === 1 ? "" : "s"} (potential)`)
    : L("허용 (잠재 권한)", "Allowed (potential)"))
    : action.decision === "EXPLICIT_DENY" ? L("명시적 거부 (시뮬레이션)", "Explicit deny (simulation)")
      : blocked ? L(`IAM 정책은 허용, KMS 키 ${blocked}개의 키 정책에 막힘 (시뮬레이션)`, blocked === 1
        ? "The IAM policy allows it; the key policy of 1 KMS key blocks it (simulation)"
        : `The IAM policy allows it; the key policies of ${blocked} KMS keys block it (simulation)`)
        : L("허용 근거 없음 (시뮬레이션)", "No allow found (simulation)");
  return action.missing_context_values?.length
    ? `${L("조건 입력 부족 · ", "Missing context · ")}${action.missing_context_values.join(", ")} · ${decision}` : decision;
}

export function IAMPolicySummary({ c }: { c: CredentialRecord }) {
  const L = useL();
  const names = c.issued?.iam_policies?.policy_names;
  if (!names?.length) return <span>{iamPolicyLabel(c, L)}</span>;
  return <DetailPopover label={iamPolicyLabel(c, L)}>
    <ul>{names.map(name => <li key={name}>{name}</li>)}</ul>
  </DetailPopover>;
}

/** Issuance inventory has no discovered credential or usage lookup record. */
export function InventoryPermissions({ c }: { c: CredentialRecord }) {
  const L = useL();
  const p = c.issued?.iam_policies;
  return <div className="card-body perm-notes">
    <IAMPolicySummary c={c} />
    {c.issued?.current === false ? <p className="tone-warn small">{L("이전 수집에서 확인한 정책입니다. 현재 범위의 수집을 완료해야 최신 상태를 확인할 수 있습니다.",
      "Policies from an earlier collection. Finish collection in the current scope to confirm the latest state.")}</p> : null}
    {p && ["COMPLETE", "PARTIAL"].includes(p.status) ? <>
      {p.allow_actions.length ? <DetailPopover label={L(`Allow 문장에 적힌 작업 · ${p.allow_actions.length}개`, `Actions named in Allow statements · ${p.allow_actions.length}`)}>
        <ul>{p.allow_actions.map(action => <li key={action}><code>{action}</code></li>)}</ul>
      </DetailPopover> : null}
      <p>{L(`거부 문장 ${p.deny_statements}개 · 조건부 문장 ${p.conditional_statements}개 · 권한 경계 ${p.permissions_boundary ? "있음" : "관측 없음"}`,
        `${p.deny_statements} deny statements · ${p.conditional_statements} conditional statements · Permissions boundary ${p.permissions_boundary ? "present" : "not observed"}`)}</p>
    </> : null}
    <p className="subtle small">{L("IAM 사용자·그룹 정책의 조회 결과입니다. 리소스 정책·SCP·세션 정책, 조건·거부·권한 경계를 합산한 실제 접근 권한이 아닙니다.",
      "IAM user and group policy metadata, not effective access after resource policies, SCPs, session policies, conditions, denies and permissions boundaries.")}</p>
  </div>;
}

const SOURCES: Record<string, [string, string]> = {
  INLINE_USER: ["사용자 인라인 정책", "User inline policy"], MANAGED_USER: ["사용자 관리형 정책", "User managed policy"],
  INLINE_GROUP: ["그룹 인라인 정책", "Group inline policy"], MANAGED_GROUP: ["그룹 관리형 정책", "Group managed policy"],
  INLINE_ROLE: ["역할 인라인 정책", "Role inline policy"], MANAGED_ROLE: ["역할 관리형 정책", "Role managed policy"],
  PERMISSIONS_BOUNDARY: ["권한 경계", "Permissions boundary"],
};
// What a simulated action risks, as the simulator's action catalog names it; a read is not tagged.
const RISKS: Record<string, [string, string]> = {
  PRIVILEGE_ESCALATION: ["권한 상승", "privilege escalation"], DESTRUCTIVE: ["삭제", "destructive"], SECRET_ACCESS: ["비밀 읽기", "secret access"],
  CODE_MODIFICATION: ["코드 변경", "code change"], EXECUTION: ["실행", "execution"], RESOURCE_CREATION: ["리소스 생성", "resource creation"],
  WRITE: ["쓰기", "write"],
};
// IAM action names are case-insensitive.
const READ = /^(Get|List|Describe|Head|Lookup|Search|Select|Scan|Query|BatchGet|View)/i;

/** Unconditional `*` on `*`: the backend's own test for a statement that covers everything (identity_policies._everything). */
export const everything = (s: IdentityPolicyStatement) =>
  s.actions.includes("*") && s.resources.includes("*") && !(s.condition_keys.length || s.not_actions.length || s.not_resources.length);

/** What one policy's statements allow, shortly: every action, the named ones, every action or resource but some. */
export function allowsText(statements: IdentityPolicyStatement[], L: Say) {
  const allow = statements.filter(s => s.effect === "Allow");
  const deny = statements.filter(s => s.effect === "Deny");
  const list = (items: string[]) => items.slice(0, 4).join(", ") + (items.length > 4 ? L(` 외 ${items.length - 4}개`, ` and ${items.length - 4} more`) : "");
  const count = (n: number, ko: string, en: string) => L(`${ko} ${n}개`, `${n} ${en}${n === 1 ? "" : "s"}`);
  const parts: string[] = [];
  if (allow.some(everything)) parts.push(L("모든 작업", "Every action"));
  else {
    const named = (s: IdentityPolicyStatement) => s.resources.length > 0 && !s.resources.includes("*") && !s.not_resources.length;
    // `*` reads as every action only where a statement grants it without a condition, and says where if only on named resources.
    const star = allow.filter(s => s.actions.includes("*")), plain = star.filter(s => !s.condition_keys.length);
    if (star.length) parts.push(!plain.length ? L("조건이 맞을 때 모든 작업", "Every action when a condition matches")
      : plain.every(named) ? L("지정한 리소스에서 모든 작업", "Every action on named resources") : L("모든 작업", "Every action"));
    const actions = [...new Set(allow.flatMap(s => s.actions))].filter(action => action !== "*");
    if (actions.length) parts.push(list(actions));
    const exceptActions = [...new Set(allow.flatMap(s => s.not_actions))];
    if (exceptActions.length) parts.push(L(`${list(exceptActions)} 제외 모든 작업`, `Every action except ${list(exceptActions)}`));
    // NotResource grants everything but the named resources: never "named resources only".
    const exceptResources = [...new Set(allow.flatMap(s => s.not_resources))];
    if (exceptResources.length) parts.push(L(`${list(exceptResources)} 제외 모든 리소스`, `Every resource except ${list(exceptResources)}`));
    else if (allow.length && allow.every(named) && !(plain.length && plain.every(named))) parts.push(L("지정한 리소스에만", "On named resources only"));
  }
  const conditional = allow.filter(s => s.condition_keys.length).length;
  if (conditional) parts.push(count(conditional, "조건부 문장", "conditional statement"));
  if (deny.length) parts.push(count(deny.length, "거부 문장", "deny statement"));
  return parts.join(" · ") || "—";
}

/** The rows the lookup read: one per identity policy, then each simulated decision. A permissions boundary
 * grants nothing; it reads as the most the other policies can allow. */
export function permissionRows(u: Usage | undefined, L: Say): Row[] {
  const rows: Row[] = [];
  const policies = u?.identity_policies;
  if (policies && ["COMPLETE", "PARTIAL"].includes(policies.collection_status)) {
    policies.policies.forEach((policy, index) => {
      const boundary = policy.source === "PERMISSIONS_BOUNDARY";
      const writes = !boundary && policy.statements.some(s => s.effect === "Allow"
        && (s.not_actions.length > 0 || s.actions.some(action => action === "*" || !READ.test(action.split(":")[1] ?? action))));
      const source = SOURCES[policy.source] ? L(...SOURCES[policy.source]) : policy.source;
      // The service as AWS names it in actions (iam, s3), as the simulated rows and the usage card name it. The same
      // managed policy can come through two groups: each is its own row.
      // A policy whose statements all fell past the stored 300 has none to show (the truncation note says why).
      const cut = policies.statements_truncated && !policy.statements.length;
      rows.push({ key: `policy:${index}`, service: "iam", permission: policy.name, source: policy.group ? `${source} · ${policy.group}` : source,
        allows: cut ? L("앞의 300개 문장 밖이라 보여 주지 않습니다", "Past the first 300 statements; not shown")
          : `${boundary ? L("최대 범위: ", "At most: ") : ""}${allowsText(policy.statements, L)}`, tag: writes ? L("쓰기", "write") : null });
    });
  }
  const potential = u?.potential_access;
  // A simulation that stopped short keeps the actions it decided (the note says it stopped short).
  if (potential?.collection_status === "COMPLETE" || potential?.collection_status === "PARTIAL") {
    for (const action of potential.actions) {
      rows.push({ key: `potential:${action.action}`, service: action.service, permission: action.action, source: L("정책 시뮬레이션", "Policy simulation"),
        allows: simulationDecision(action, L, blockedKeys(potential, action.action).length),
        tag: action.decision === "ALLOWED" && !action.missing_context_values?.length && RISKS[action.risk] ? L(...RISKS[action.risk]) : null });
    }
  }
  return rows;
}

/** What the reading carries beside the rows, the gravest first: a root key, an attached quarantine policy, an
 * allow-everything or deny-everything policy; then what bounds the reading (an unconfirmed owning account, a reading
 * that stopped short or was cut, a session key's role, a simulation that did not run); then what there was to read. */
export function permissionNotes(u: Usage | undefined, L: Say): Note[] {
  const policies = u?.identity_policies, potential = u?.potential_access;
  const notes: Note[] = [];
  const root = policies?.principal_type === "ROOT";
  if (root) notes.push({ tone: "bad", text: L("루트 사용자의 키입니다. IAM 정책으로 제한되지 않습니다.", "This is the root user's key; IAM policies do not limit it.") });
  const summary = policies?.summary;
  if (summary?.quarantine_policies?.length) notes.push({ tone: "warn", text: L(`주체에 AWS 격리 정책이 연결되어 있습니다: ${summary.quarantine_policies.join(", ")}. 연결한 주체와 이 키의 노출 여부는 확인되지 않았습니다.`,
    `An AWS quarantine policy is attached to the principal: ${summary.quarantine_policies.join(", ")}. The attaching actor and exposure of this key are not established.`) });
  if (summary?.allow_all_policies.length) notes.push({ tone: summary.boundary_limits_allow_all ? "warn" : "bad", text: summary.boundary_limits_allow_all
    ? L(`모든 작업을 허용하는 정책(${summary.allow_all_policies.join(", ")})이 있지만 권한 경계가 좁힙니다.`, `A policy allows every action (${summary.allow_all_policies.join(", ")}), narrowed by a permissions boundary.`)
    : L(`모든 작업을 허용하는 정책이 있습니다: ${summary.allow_all_policies.join(", ")}`, `A policy allows every action: ${summary.allow_all_policies.join(", ")}`) });
  if (summary?.deny_all_policies.length) notes.push({ tone: "warn", text: L(`모든 작업을 거부하는 정책 문장이 관측되었습니다: ${summary.deny_all_policies.join(", ")}`, `A policy statement denying every action was observed: ${summary.deny_all_policies.join(", ")}`) });
  if (potential?.actions.some(action => action.missing_context_values?.length)) notes.push({ tone: "warn", text: L(
    "시뮬레이션에 필요한 조건 입력이 없습니다. 거부 결과로 실제 접근 불가나 낮은 권한을 확정하지 않습니다.",
    "Required condition context is missing. Denial results do not establish actual denial or low privilege.") });
  if (potential && ["COMPLETE", "PARTIAL"].includes(potential.collection_status) && (potential.assessment_version ?? 0) < 2) notes.push({ tone: "warn", text: L(
    "이전 시뮬레이션은 누락된 조건 정보를 보존하지 않았습니다. 현재 평가를 위해 다시 수집해야 합니다.",
    "This older simulation did not preserve missing condition context. Recollect for a current assessment.") });
  if (u?.collection_status === "ACCOUNT_UNVERIFIED" && (policies || potential?.collection_status === "COMPLETE" || potential?.collection_status === "PARTIAL")) {
    notes.push({ tone: "warn", text: L("소유 계정을 확인하기 전에 읽은 정책입니다.", "Read before the owning account was confirmed.") });
  }
  if (policies && ["PARTIAL", "FAILED"].includes(policies.collection_status)) {
    const codes = [...new Set(policies.errors.map(item => item.error_code).filter(Boolean))].join(", ");
    notes.push({ tone: "warn", text: policies.collection_status === "FAILED"
      ? L(`이 키 주체의 정책을 읽지 못했습니다${codes ? ` (${codes})` : ""}.`, `The key principal's policies could not be read${codes ? ` (${codes})` : ""}.`)
      : L(`정책 일부를 읽지 못했습니다${codes ? ` (${codes})` : ""}.`, `Some policies could not be read${codes ? ` (${codes})` : ""}.`) });
  }
  // Every statement is read and judged; only the first 300 are kept (identity_policies.MAX_STATEMENTS).
  if (policies?.statements_truncated) notes.push({ tone: "warn", text: L("정책 문장이 많아 앞의 300개만 보여 줍니다. 모든 작업의 허용·거부는 전체 문장으로 판단했습니다.",
    "Only the first 300 statements are shown; allowing or denying every action is judged from all of them.") });
  if ((potential?.collection_status === "COMPLETE" || potential?.collection_status === "PARTIAL") && potential.evaluated_role_arn) notes.push({ tone: undefined,
    text: L(`세션 키라서 맡은 역할(${potential.evaluated_role_arn})의 잠재 권한입니다. 세션 정책이 더 좁힐 수 있습니다.`,
      `A session key: this is the potential of the role it assumed (${potential.evaluated_role_arn}); a session policy can narrow it.`) });
  if (potential?.collection_status === "FAILED") notes.push({ tone: "warn", text: L(`권한 시뮬레이션을 마치지 못했습니다${potential.error_code ? ` (${potential.error_code})` : ""}.`,
    `The permission simulation did not finish${potential.error_code ? ` (${potential.error_code})` : ""}.`) });
  if (potential?.collection_status === "PARTIAL") notes.push({ tone: "warn", text: L(`권한 시뮬레이션이 일부 작업만 판단했습니다${potential.error_code ? ` (${potential.error_code})` : ""}.`,
    `The permission simulation decided only some actions${potential.error_code ? ` (${potential.error_code})` : ""}.`) });
  if (potential?.collection_status === "UNSUPPORTED" && !root) notes.push({ tone: undefined, text: L("이 주체는 권한 시뮬레이션을 하지 않습니다.", "This principal is not simulated.") });
  if (policies?.collection_status === "UNSUPPORTED") notes.push({ tone: undefined, text: L("이 주체 유형은 IAM 정책을 읽지 않습니다.", "IAM policies are not read for this kind of principal.") });
  if (policies?.collection_status === "COMPLETE" && !policies.policies.length) notes.push({ tone: undefined,
    text: L("이 키 주체에 붙은 IAM 정책이 없습니다.", "No IAM policy is attached to this key's principal.") });
  return notes;
}

/** The permissions card's body from one usage record: the notes, then the rows; nothing read yet says how it is read. */
export function PermissionsView({ u }: { u: Usage }) {
  const L = useL();
  const locale = useLocale();
  const rows = permissionRows(u, L);
  const policies = rows.filter(row => row.key.startsWith("policy:"));
  const simulated = rows.filter(row => row.key.startsWith("potential:"));
  const hasSimulation = ["COMPLETE", "PARTIAL"].includes(u.potential_access?.collection_status ?? "");
  const notes = permissionNotes(u, L);
  if (!rows.length && !notes.length && !hasSimulation) return <div className="card-body muted">{L("사용 기록을 조회하면 이 키 주체의 IAM 정책을 읽습니다.", "A usage lookup reads the IAM policies of this key's principal.")}</div>;
  return <>
    {notes.length ? <div className="card-body perm-notes">{notes.map(note => <Banner key={note.text} tone={note.tone}
      icon={note.tone === "ok" ? "checkCircle" : note.tone ? "alert" : "info"}>{note.text}</Banner>)}</div> : null}
    {policies.length ? <div className="sub-scroll"><table className="sub-tbl">
      <thead><tr><th>{L("서비스", "Service")}</th><th>{L("정책", "Policy")}</th><th>{L("정책 문장의 범위", "Policy statement scope")}</th></tr></thead>
      <tbody>{policies.map(row => <tr key={row.key}>
        <td className="nowrap" data-label={L("서비스", "Service")}>{row.service}</td>
        <td data-label={L("정책", "Policy")}><code className="mono cell-wrap">{row.permission}</code>{row.tag ? <> <span className="vis vis-org small">{row.tag}</span></> : null}
          <div className="subtle small">{row.source}</div></td>
        <td className="cell-wrap" data-label={L("정책 문장의 범위", "Policy statement scope")}>{row.allows}</td>
      </tr>)}</tbody>
    </table></div> : null}
    {hasSimulation ? <div className="card-body"><DetailPopover label={L(`정책 시뮬레이션 · 평가 ${simulated.length}개`, `Policy simulation · ${simulated.length} evaluated`)}>
      {u.potential_access?.evaluated_at ? <p className="subtle small">{fmtDT(u.potential_access.evaluated_at, locale)}</p> : null}
      {u.potential_access?.named_resources ? <>
        <p className="small">{L(`선별한 작업 · 리소스 *와 주체 정책에 적힌 리소스 ${u.potential_access.named_resources.length}개 · 요청 조건 미입력. 실제 접근 권한은 평가하지 않았습니다.`,
          `Selected actions · resource * and ${u.potential_access.named_resources.length} resource${u.potential_access.named_resources.length === 1 ? "" : "s"} the principal's policies name · no request context. Effective access was not evaluated.`)}</p>
        {u.potential_access.named_resources_complete === false ? <p className="tone-warn small">{L("정책에 적힌 리소스가 많아 앞의 25개만 시뮬레이션했습니다.", "The policies name more resources than the 25 simulated.")}</p> : null}
        <p className="small">{L("IAM 사용자는 주체 정책에 ARN 하나로 적힌 같은 계정 S3 버킷·Secrets Manager 시크릿·KMS 키의 정책도 함께 시뮬레이션하고, KMS 키는 키 정책이 IAM 정책에 사용 허용을 위임하거나 사용자에게 직접 허용하는지도 확인합니다. 미평가 항목: 리소스 *나 ARN 패턴으로 허용된 작업의 리소스 정책, 읽지 못한 리소스 정책, 그 밖의 리소스 정책과 RCP, 다른 계정이 리소스 정책으로 준 권한, 역할의 리소스 정책, 실제 세션 정책·태그, KMS grant·암호화 조건과 종속 권한. 조직/SCP·권한 경계 결과는 시뮬레이션 입력에만 적용되며, SCP의 누락된 조건 키는 AWS가 반환하지 않습니다.",
          "For an IAM user the same-account S3 bucket, Secrets Manager secret and KMS key policies of resources its policies name by a single ARN are simulated too, and for a KMS key whether its key policy delegates use to IAM policies or grants the user directly. Not evaluated: resource policies for actions allowed on * or an ARN pattern, resource policies that could not be read, other resource policies and RCPs, access other accounts grant in resource policies, a role's resource policies, actual session policies/tags, KMS grants/encryption context and dependent permissions. Organizations/SCP and boundary results apply only to simulated input; AWS does not return missing SCP context keys.")}</p>
      </> : <>
        <p className="small">{L("선별한 작업 · 리소스 * · 요청 조건 미입력. 실제 접근 권한은 평가하지 않았습니다. 지정 리소스에만 허용된 권한은 놓칠 수 있습니다.",
          "Selected actions · resource * · no request context. Effective access was not evaluated. Grants limited to named resources can be missed.")}</p>
        <p className="small">{L("미평가 항목: 리소스 정책의 허용·거부와 RCP, 실제 세션 정책·태그, KMS 키 정책·grant·암호화 조건과 종속 권한. 조직/SCP·권한 경계 결과는 시뮬레이션 입력에만 적용되며, SCP의 누락된 조건 키는 AWS가 반환하지 않습니다.",
          "Not evaluated: resource policy allows/denies and RCPs, actual session policies/tags, KMS key policies/grants/encryption context and dependent permissions. Organizations/SCP and boundary results apply only to simulated input; AWS does not return missing SCP context keys.")}</p>
      </>}
      {u.potential_access?.collection_status === "PARTIAL" ? <p className="tone-warn small">{L("일부 작업만 평가했습니다.", "Only some actions were evaluated.")}</p> : null}
      <ul className="simulation-actions">{simulated.map((row, index) => {
        const action = u.potential_access!.actions[index];
        const blocked = blockedKeys(u.potential_access, action.action);
        const unread = unreadKeys(u.potential_access, action.action);
        const conditional = conditionalOn(u.potential_access, action.action);
        const layer = (value: boolean | undefined) => value === true ? L("허용", "allows") : value === false ? L("허용 안 됨", "does not allow") : L("미확인", "unknown");
        return <li key={row.key}><code>{row.permission}</code>
          <span className="small">{row.allows}{row.tag ? ` · ${row.tag}` : ""}</span>
          {action.resource_scope === "NAMED" && action.resources?.length ? <span className="small subtle mono cell-wrap">{action.resources.join(", ")}</span> : null}
          {blocked.length ? <span className="small subtle mono cell-wrap">{L("키 정책에 막힌 키: ", "Keys whose key policy blocks it: ")}{blocked.join(", ")}</span> : null}
          {unread.length ? <span className="small subtle mono cell-wrap">{L("키 정책을 읽지 못한 키(주체 정책만으로 판단): ", "Keys whose key policy could not be read (judged by the identity policies alone): ")}{unread.join(", ")}</span> : null}
          {conditional.length ? <span className="small subtle mono cell-wrap">{L("요청 조건에 따라 다름: ", "Depends on request conditions: ")}{conditional.map(named => `${named.resource} (${named.missing_context_values.join(", ")})`).join(", ")}</span> : null}
          <span className="small subtle">{L("조직: ", "Organizations: ")}{layer(action.organizations_allowed)} · {L("권한 경계: ", "Boundary: ")}{layer(action.permissions_boundary_allowed)}</span></li>;
      })}</ul>
      {!simulated.length ? <p>{L("수집한 작업별 판단이 없습니다. 권한이 없다는 뜻은 아닙니다.", "No action decisions were collected. This does not mean there are no permissions.")}</p> : null}
    </DetailPopover></div> : null}
  </>;
}

/** The permissions card's body for a discovered AWS key, from the same usage record the usage card reads. */
export function LookupPermissions({ c }: { c: CredentialRecord }) {
  const evidence = awsPermissionEvidence(c);
  const u = c.aws_permissions ?? {};
  const failedPolicies = u.identity_policies?.collection_status === "FAILED" ? u.identity_policies : undefined;
  const display = evidence.fromInventory ? { potential_access: u.potential_access, identity_policies: failedPolicies } : u;
  return <>
    {evidence.fromInventory ? <InventoryPermissions c={c} /> : null}
    {(!evidence.fromInventory || display.potential_access || failedPolicies) ? <PermissionsView u={display} /> : null}
  </>;
}
