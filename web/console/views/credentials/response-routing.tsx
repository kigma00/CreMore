"use client";

import { PersonPicker } from "@/console/people-picker";
import { type DirectoryPerson, type ResponderRouting, selectablePerson } from "@/console/people";
import { type Say, useL } from "@/console/text";
import { SelectField, TextField } from "@/console/ui";
import type { ResponseChannelOption } from "@/console/views/integrations/response-channels";

const BASIS: Record<string, [string, string]> = {
  ADMIN_CONFIRMED: ["관리자가 확인한 계정 연결", "Account link confirmed by an administrator"],
  MANUAL: ["명시적 담당자 지정", "Explicit responder assignment"], MANUAL_ASSIGNMENT: ["명시적 담당자 지정", "Explicit responder assignment"],
  RESPONSIBILITY_RULE: ["관리자가 설정한 책임 규칙", "Admin responsibility rule"], EXPLICIT_RULE: ["관리자가 설정한 책임 규칙", "Admin responsibility rule"],
  VERIFIED_EMAIL: ["검증된 이메일 일치", "Verified email match"], SCIM_EXTERNAL_ID: ["SCIM 외부 ID 일치", "SCIM external ID match"],
  SAML_NAME_ID: ["SAML 신원 일치", "SAML identity match"], EXTERNAL_UID: ["외부 신원 ID 일치", "External identity match"],
  IDP_OBJECT_ID: ["IdP 개체 ID 일치", "IdP object ID match"],
};
export const routingBasis = (basis: string, L: Say) => L(...(BASIS[basis] ?? [basis, basis]));
export const routingTargetKey = (target: ResponderRouting["targets"][number]) => `${target.kind}:${target.key}`;

export function ResponderFields({ routing, person, onChange, team, onTeam, ruleTarget, onRuleTarget, channels = [], ruleChannel = "", onRuleChannel, disabled = false, admin = false }: {
  routing: ResponderRouting; person: DirectoryPerson | null; onChange: (person: DirectoryPerson | null) => void;
  team: string; onTeam: (team: string) => void; ruleTarget?: string; onRuleTarget?: (target: string) => void;
  /** The approved team channels a rule may name, the one chosen and its change (phase 2). */
  channels?: ResponseChannelOption[]; ruleChannel?: string; onRuleChannel?: (channelId: string) => void; disabled?: boolean; admin?: boolean;
}) {
  const L = useL();
  return <>
    {routing.recommendations.length ? <div className="safety">
      <strong>{L("근거가 있는 담당자 추천", "Responders with supporting evidence")}</strong>
      {routing.recommendations.map((entry, index) => <button type="button" className="ghost-btn cell-wrap" key={`${entry.person.person_ref}:${entry.basis}:${index}`}
        disabled={disabled || !selectablePerson(entry.person)} onClick={() => { onChange(entry.person); onTeam(entry.team ?? ""); }} style={{ textAlign: "left", height: "auto", whiteSpace: "normal" }}>
        <span>{entry.person.name} · {entry.person.email}<span className="meta" style={{ display: "block" }}>{[entry.person.department, routingBasis(entry.basis, L)].filter(Boolean).join(" · ")}</span></span>
      </button>)}
    </div> : <p className="meta">{L("확정할 수 있는 추천이 없습니다. 로그인 IdP에서 담당자를 직접 선택하세요.", "No responder can be recommended with confidence. Choose someone from the sign-in IdP.")}</p>}
    {routing.status === "AMBIGUOUS" ? <p className="meta tone-warn">{L("후보가 여러 명입니다. 대응할 한 명을 직접 선택해야 합니다.", "There are multiple candidates. Explicitly choose the person who will respond.")}</p> : null}
    <PersonPicker label={L("대응 담당자", "Responder")} value={person} onChange={onChange} disabled={disabled} admin={admin} />
    <TextField label={L("명시적 책임 팀 (선택)", "Explicit responsible team (optional)")} value={team} onChange={onTeam} maxLength={100} disabled={disabled}
      hint={L("팀 이름은 책임 표시입니다. IdP 그룹으로 추정하거나 팀 전체에 발송하지 않습니다.", "This team label records responsibility. It is not treated as an IdP group or used to notify every member.")} />
    {onRuleTarget ? <SelectField label={L("같은 위치·발급 계정의 다음 발견에도 적용", "Reuse for future findings at this location or issuing account")} value={ruleTarget ?? ""}
      onChange={onRuleTarget} disabled={disabled} options={[{ id: "", label: L("이번 Credential에만 적용", "Only this credential") }, ...(routing.targets ?? []).map(target => ({
        id: routingTargetKey(target), label: `${target.kind === "account" ? L("발급 계정", "Issuing account") : L("발견 위치", "Location")} · ${target.label}`,
      }))]} hint={L("선택한 대상에 명시적 책임 규칙을 저장합니다. 추천은 자동 발송이나 조치 승인이 아닙니다.", "Saves an explicit responsibility rule for the selected target. Recommendations do not send tickets or approve remediation automatically.")} /> : null}
    {onRuleTarget && ruleTarget && onRuleChannel && channels.length ? <SelectField label={L("규칙의 팀 Slack 채널", "The rule's team Slack channel")} value={ruleChannel}
      onChange={onRuleChannel} disabled={disabled} options={[{ id: "", label: L("채널 없음", "No channel") }, ...channels.map(item => ({ id: item.channel_id,
        label: `#${item.name} · ${item.is_private ? L("비공개", "Private") : L("공개", "Public")}` }))]}
      hint={L("다음 발견에서 이 채널을 함께 추천합니다. 대응 알림 채널로 승인한 채널만 고를 수 있습니다.", "Recommended together with the person for future findings. Only approved response channels can be chosen.")} /> : null}
  </>;
}
