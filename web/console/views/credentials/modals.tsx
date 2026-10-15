"use client";

/* The credential panel's windows: contact an owner, assign one, add a tag or comment, read a risk
 * rule, open the access map full size and rescan an exposed location. */

import { useEffect, useMemo, useState } from "react";

import { useLocale } from "@/components/locale";
import { api, DashboardAPIError } from "@/lib/dashboard-api";
import { reasonText, send, useApi } from "@/console/data";
import { Ic } from "@/console/icons";
import { Modal, useToast } from "@/console/layer";
import { Logo, serviceName } from "@/console/logos";
import { addressesOf, type DirectoryPerson, type Person, personOf, type ResponderRouting, selectablePerson } from "@/console/people";
import { type Contact, type CredentialRecord, exposureService } from "@/console/records";
import { fmtDay, fmtDT, useL } from "@/console/text";
import { cls, Field, SelectField, type Status, statusLabel, TextField } from "@/console/ui";
import { AccessGraph, nextZoom, ZoomControl } from "@/console/views/credentials/graph";
import { plainSteps, remediationFor, type Rule, rulesFor } from "@/console/views/credentials/risk";
import { visLabel } from "@/console/labels";
import { ResponderFields } from "@/console/views/credentials/response-routing";
import { type ContactChannels, listOf } from "@/console/views/integrations/contact-delivery";

export type Target = { name: string; role: string; basis: string; email?: string; team?: string; departed?: boolean };

const TEMPLATES: Record<Contact["template"], { label: [string, string]; subject: [string, string] }> = {
  info: { label: ["정보 요청", "Information request"], subject: ["[보안 확인 요청] {name} 사용 여부를 알려 주세요", "[Security check] Is {name} still in use?"] },
  revoke: { label: ["폐기·교체 요청", "Revoke and replace"], subject: ["[보안 조치 요청] 노출된 {name}을 폐기하고 새로 발급해 주세요", "[Action needed] Please revoke and reissue the exposed {name}"] },
  purpose: { label: ["사용 목적 확인", "Business justification"], subject: ["[보안 확인 요청] {name}의 사용 목적과 필요한 권한을 알려 주세요", "[Security check] What is {name} used for, and what access does it need?"] },
  scope: { label: ["권한·만료 조정 요청", "Reduce access and set expiry"], subject: ["[보안 개선 요청] {name}의 권한을 줄이고 만료일을 정해 주세요", "[Improvement] Please reduce {name}'s access and set an expiry"] },
};

export function templateLabel(template: Contact["template"], L: (ko: string, en: string) => string) {
  return L(...TEMPLATES[template].label);
}

function dueDate(days: number) {
  const date = new Date(Date.now() + days * 86_400_000);
  return date.toISOString().slice(0, 10);
}

export function ContactModal({ c, name, typeName, targets, people, directory, canChangeStatus, notify, onClose, onDone }: {
  c: CredentialRecord; name: string; typeName: string; targets: Target[]; people: Target[]; directory?: Person[]; canChangeStatus: boolean;
  /** Everyone who can read the exposed repository, rather than an owner. */
  notify?: boolean; onClose: () => void; onDone: (status: Status | null) => Promise<void>;
}) {
  const L = useL();
  const locale = useLocale();
  const toast = useToast();
  const multi = people.length > 1;
  const [channel, setChannel] = useState<"mail" | "slack">("mail");
  const [template, setTemplate] = useState<Contact["template"]>(c.status === "pending" || !c.status ? "info" : "revoke");
  const [days, setDays] = useState(3);
  const [status, setStatus] = useState<Status>(c.status && c.status !== "pending" && c.status !== "done" && c.status !== "fp" && c.status !== "ignored" ? c.status : "review");
  const [guide, setGuide] = useState(true);
  // Each recipient's address: what the IdP says, or the name itself when it is an address.
  const [address, setAddress] = useState(Array.from(new Set(people.map(p => p.email ?? addressesOf(directory, [p.name])[0] ?? "")
    .filter(Boolean))).join(", "));
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [secret, setSecret] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  const due = dueDate(days);
  // A channel an admin set up is sent by CreMore itself; otherwise the mail app or the clipboard carries it.
  const delivery = useApi<ContactChannels>("contact-delivery");
  const direct = delivery.data?.[channel] === true;
  const domains = delivery.data?.allowed_domains ?? [];
  const channels = delivery.data?.allowed_channels ?? [];

  const rules = useMemo(() => rulesFor(c, L, locale).filter(r => r.tone === "bad" || r.tone === "warn").slice(0, 3).map(r => r.label).join(", "), [c, L, locale]);
  useEffect(() => {
    // A person the IdP names is greeted by name; an address by its local part: "kim.demo@example.com" -> "kim.demo".
    const person = multi ? L("여러분", "everyone") : (personOf(directory, people[0]?.name)?.name ?? people[0]?.name ?? L("담당자", "owner")).split("@")[0];
    const dueText = fmtDay(`${due}T12:00:00Z`, locale);
    const first = remediationFor(c, L)[0];
    const steps = first ? plainSteps(first.steps.slice(0, 3), name, c.issuer?.name ?? name, c.hint ?? "") : "";
    const where = c.exposures.filter(e => e.current).map(e => `${serviceName(exposureService(e.source_type))} ${e.resource_name} / ${e.location}${e.line ? `:${e.line}` : ""} (${visLabel(e.visibility, L)})`).join("\n  ")
      || L("노출 위치 없음", "No exposure location");
    const facts = `- Credential: ${name} (${typeName}${c.hint ? `, ${c.hint}` : ""})\n${L("- 발급 서비스: ", "- Issuer: ")}${serviceName(c.provider)}\n${L("- 노출 위치: ", "- Found in: ")}${where}${rules ? `\n${L("- 위험 근거: ", "- Risk evidence: ")}${rules}` : ""}`;
    const ask = {
      info: L(`이 Credential을 지금도 쓰고 있는지, 어디에서 쓰는지 ${dueText}까지 알려 주세요. 쓰지 않는다면 그렇다고만 답해 주셔도 됩니다.`, `Please tell us by ${dueText} whether this credential is still in use and where. If it isn't, a one-line reply is enough.`),
      revoke: L(`노출된 값은 이미 복사됐을 수 있어 폐기하고 새로 발급해야 합니다. 아래 순서로 진행한 뒤 ${dueText}까지 회신해 주세요.\n`, `The exposed value may already have been copied, so it needs to be revoked and reissued. Please follow these steps and reply by ${dueText}.\n`) + steps,
      purpose: L(`이 Credential이 어떤 업무에 필요한지, 꼭 필요한 권한이 무엇인지 ${dueText}까지 알려 주세요.`, `Please tell us by ${dueText} which work this credential supports and which permissions it really needs.`),
      scope: L(`쓰기 권한과 만료일 없는 설정은 노출 시 피해가 커집니다. 필요한 권한만 남기고 만료일을 정한 뒤 ${dueText}까지 알려 주세요.`, `Write access with no expiry makes an exposure more damaging. Please keep only the access you need, set an expiry, and let us know by ${dueText}.`),
    }[template];
    const footer = `\n\n${L("※ 이 메시지에는 비밀값을 넣지 않았습니다. 가린 식별자만 적었습니다.", "Note: this message contains no secret values, only a masked identifier.")}${guide ? `\n${L("조치 가이드: CreMore > Credential > ", "Remediation guide: CreMore > Credentials > ")}${name}${L(" > 조치", " > Remediation")}` : ""}`;
    const text = channel === "slack"
      ? `${L(`${person}님, 보안팀입니다. ${name}${c.hint ? `(${c.hint})` : ""}이 노출돼 확인 부탁드립니다.`, `Hi ${person}, this is the security team. ${name}${c.hint ? ` (${c.hint})` : ""} was found exposed. Please take a look.`)}\n${facts}\n\n${ask}${footer}`
      : `${L(`${person}님, 안녕하세요. 보안팀입니다.\n\n정기 점검에서 아래 Credential이 노출된 것을 확인했습니다.`, `Hi ${person},\n\nThis is the security team. Our scheduled scan found the credential below exposed.`)}\n${facts}\n\n${ask}${footer}`;
    setBody(text);
    setSubject(L(...TEMPLATES[template].subject).replace("{name}", name));
  }, [template, channel, guide, due, name, typeName, c, L, locale, multi, people, rules, directory]);

  useEffect(() => {
    const text = `${subject}\n${body}`;
    setSecret(null);
    const timer = window.setTimeout(() => {
      api<{ contains_credential: boolean }>("text-check", { method: "POST", body: JSON.stringify({ text: text.slice(0, 2000) }) })
        .then(result => setSecret(result.contains_credential)).catch(() => setSecret(null));
    }, 350);
    return () => window.clearTimeout(timer);
  }, [subject, body]);

  // ``byCreMore``: the set-up channel sends it; otherwise the reader's own mail app or clipboard carries it (also
  // for recipients a set-up channel does not reach, such as more than twenty or another domain).
  const submit = async (byCreMore: boolean) => {
    if (!c.finding_id || secret) return;
    setBusy(true);
    try {
      const current = await api<{ revision: number }>(`findings/${c.finding_id}/annotations`);
      if (byCreMore) {
        const sent = await send<{ delivered: string[]; failed: { to: string; code: string }[] }>(`findings/${c.finding_id}/contacts/send`, "POST",
          { revision: current.revision, channel, template, due_at: due, to: listOf(address), subject: channel === "mail" ? subject : "", body });
        const missed = sent.failed.map(item => `${item.to} (${reasonText(new DashboardAPIError(item.code, 502), L)})`).join(", ");
        toast(missed ? L(`${sent.delivered.length}곳에 보냈고 연락 기록을 남겼습니다. 보내지 못한 곳: ${missed}`, `Sent to ${sent.delivered.length} and recorded the contact. Not sent: ${missed}`)
          : L(`${sent.delivered.length}곳에 보냈고 연락 기록을 남겼습니다.`, `Sent to ${sent.delivered.length} and recorded the contact.`), missed ? "bad" : undefined);
        await onDone(canChangeStatus && status !== c.status ? status : null);
        onClose();
        return;
      }
      await send(`findings/${c.finding_id}/contacts`, "POST", { revision: current.revision, channel, template, recipients: Math.max(1, people.length), due_at: due });
      if (channel === "mail") {
        const href = `mailto:${encodeURIComponent(address.trim()).replaceAll("%2C", ",").replaceAll("%40", "@")}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
        window.location.href = href;
        toast(L("메일 앱에서 새 메일을 열고 연락 기록을 남겼습니다.", "Opened a new mail in your mail app and recorded the contact."));
      } else {
        await navigator.clipboard?.writeText(body).catch(() => undefined);
        toast(L("Slack 메시지를 복사하고 연락 기록을 남겼습니다.", "Copied the Slack message and recorded the contact."));
      }
      await onDone(canChangeStatus && status !== c.status ? status : null);
      onClose();
    } catch (error) {
      toast(reasonText(error, L), "bad");
    } finally {
      setBusy(false);
    }
  };

  return <Modal onClose={onClose} labelledBy="contact-title">
    <h2 id="contact-title">{notify ? L("접근 가능 인원에게 알림", "Notify people with access") : multi ? L("여러 사람에게 연락", "Contact several people") : L("담당자에게 연락", "Contact owner")}
      <small><Logo id={c.provider} size={20} /><span className="clip">{name}</span></small></h2>
    <div className="mtabs" role="tablist">
      <button type="button" role="tab" aria-selected={channel === "slack"} onClick={() => setChannel("slack")}>Slack</button>
      <button type="button" role="tab" aria-selected={channel === "mail"} onClick={() => setChannel("mail")}>{L("메일", "Email")}</button>
    </div>
    <div className="field"><span className="lbl">{L("받는 사람 · 근거", "Recipients · basis")}</span>
      <div className="to-chips">{(people.length ? people : targets.slice(0, 1)).map(person => {
        const about = (multi ? [person.team] : [person.team, person.role, person.basis]).filter(Boolean).join(" · ");
        return <span className="to-chip" key={`${person.name}:${person.role}`}><Ic name="user" size={15} />
          <span className="clip">{person.name}{about ? <span className="subtle"> · {about}</span> : null}</span>
          {person.departed ? <span className="tag tone-bad">{L("퇴사", "Left")}</span> : null}</span>;
      })}</div>
    </div>
    <div className="row2">
      {canChangeStatus ? <SelectField label={L("처리 상태 변경", "Change status")} value={status} onChange={setStatus}
        options={(["pending", "review", "action"] as Status[]).map(s => ({ id: s, label: statusLabel(s, L) }))} /> : <div />}
      <SelectField label={L("회신 기한", "Reply by")} value={String(days)} onChange={value => setDays(Number(value))}
        options={[1, 3, 7, 14].map(d => ({ id: String(d), label: L(`${d}일 뒤 (${fmtDay(`${dueDate(d)}T12:00:00Z`, locale)})`, `In ${d} day${d === 1 ? "" : "s"} (${fmtDay(`${dueDate(d)}T12:00:00Z`, locale)})`) }))} />
    </div>
    {channel === "mail"
      ? <TextField label={L("받는 주소", "Email address")} value={address} onChange={setAddress} placeholder="name@example.com"
        hint={direct && domains.length ? L(`${domains.join(", ")} 주소로만 보냅니다.`, `Only addresses in ${domains.join(", ")} receive it.`) : undefined} />
      : <TextField label={L("보낼 곳", "Send to")} value={address} onChange={setAddress} placeholder={direct ? L("이메일 또는 #채널", "Address or #channel") : L("@사용자 또는 #채널", "@user or #channel")}
        hint={direct ? L(`사람은 ${domains.join(", ") || "허용한 도메인의"} 주소로 찾아 DM으로 보냅니다. 채널은 ${channels.join(", ") || "관리자가 허용한 채널"}로만 보냅니다.`,
          `People are found by their ${domains.join(", ") || "allowed-domain"} address and messaged directly; channels: ${channels.join(", ") || "only those an admin allowed"}.`) : undefined} />}
    <SelectField label={L("템플릿", "Template")} value={template} onChange={setTemplate}
      options={(Object.keys(TEMPLATES) as Contact["template"][]).map(key => ({ id: key, label: L(...TEMPLATES[key].label) }))} />
    {channel === "mail" ? <Field label={L("제목", "Subject")} htmlFor="c-subject"><textarea id="c-subject" className="subject" rows={2} value={subject} onChange={event => setSubject(event.target.value)} /></Field> : null}
    <Field label={L("내용", "Message")} htmlFor="c-body"><textarea id="c-body" value={body} onChange={event => setBody(event.target.value)} /></Field>
    <div className="safety" id="c-safety">
      {secret ? <div className="bad"><Ic name="alert" size={16} /><span>{L("메시지에 비밀값으로 보이는 문자열이 있습니다. 지우기 전에는 보낼 수 없습니다.", "The message contains what looks like a secret value. Remove it before sending.")}</span></div>
        : <div className="ok"><Ic name="checkCircle" size={16} /><span>{secret === null ? L("비밀값 확인 중", "Checking for secret values") : L("비밀값 없음 · 가린 식별자만 들어 있습니다", "No secret values · masked identifiers only")}</span></div>}
      <div className="ok"><Ic name="checkCircle" size={16} /><span>{L("노출 위치와 위험 근거를 함께 보냅니다", "Includes the exposed location and risk evidence")}</span></div>
      <label className="check-line"><input type="checkbox" checked={guide} onChange={event => setGuide(event.target.checked)} /> {L("조치 가이드 위치를 함께 적기", "Mention where the remediation guide is")}</label>
    </div>
    <div className="modal-foot">
      <span className="note">{direct ? L(`보내기를 누르면 CreMore가 ${channel === "mail" ? "메일로" : "Slack으로"} 보내고 연락 기록이 남습니다.`,
        `Send makes CreMore send it by ${channel === "mail" ? "mail" : "Slack"} and records the contact.`)
        : channel === "mail" ? L("보내기를 누르면 메일 앱에 새 메일이 열리고 연락 기록이 남습니다.", "Send opens a new mail in your mail app and records the contact.")
          : L("보내기를 누르면 메시지가 복사되고 연락 기록이 남습니다.", "Send copies the message and records the contact.")}</span>
      <button type="button" className="ghost-btn" onClick={onClose}>{L("취소", "Cancel")}</button>
      {direct ? <button type="button" className="ghost-btn" onClick={() => void submit(false)} disabled={busy || secret !== false || !c.finding_id || (channel === "mail" && !address.trim())}>
        {channel === "mail" ? L("메일 앱으로", "In my mail app") : L("복사해서 보내기", "Copy instead")}</button> : null}
      <button type="button" className="primary-btn" id="c-send" onClick={() => void submit(direct)} disabled={busy || secret !== false || !c.finding_id || ((channel === "mail" || direct) && !address.trim())}>
        <Ic name="send" size={16} />{L("보내기", "Send")}</button>
    </div>
  </Modal>;
}

export function AssignModal({ c, name, onClose, onAssign, admin = false }: { c: CredentialRecord; name: string; onClose: () => void; admin?: boolean;
  onAssign: (person: DirectoryPerson | null, team: string, version: number, basis: string) => Promise<void> }) {
  const L = useL(), toast = useToast();
  const routing = useApi<ResponderRouting>(`findings/${c.finding_id}/response/routing`);
  const [base, setBase] = useState<ResponderRouting | null>(null);
  useEffect(() => { if (!base && routing.data) setBase(routing.data); }, [base, routing.data]);
  const [person, setPerson] = useState<DirectoryPerson | null>(null);
  const [team, setTeam] = useState(c.owner?.team ?? "");
  const [basis, setBasis] = useState(L("관리자 지정", "Assigned by admin"));
  const [busy, setBusy] = useState(false);
  const changed = !!base && routing.data?.version !== base.version;
  const assign = async (selected: DirectoryPerson | null) => {
    if (!base || changed) return;
    setBusy(true);
    try { await onAssign(selected, selected ? team.trim() : "", base.version, selected ? basis.trim() : ""); onClose(); }
    catch (error) { toast(reasonText(error, L), "bad"); if (error instanceof DashboardAPIError && error.status === 409) routing.reload(); }
    finally { setBusy(false); }
  };
  return <Modal onClose={onClose} labelledBy="assign-title" size="narrow" dismissable={!busy}>
    <h2 id="assign-title">{L("담당자 지정", "Assign owner")} <small><span className="clip">{name}</span></small></h2>
    {routing.error ? <p className="meta tone-warn">{reasonText(routing.error, L)}<button type="button" className="link-btn" onClick={routing.reload}>{L("다시 확인", "Retry")}</button></p>
      : !base ? <p className="meta">{L("담당자 근거를 확인하고 있습니다.", "Checking responder evidence.")}</p>
        : <ResponderFields routing={base} person={person} onChange={setPerson} team={team} onTeam={setTeam} disabled={busy} admin={admin} />}
    {changed ? <p className="meta tone-warn">{L("담당자 지정이 변경됐습니다. 닫고 다시 열어 최신 내용을 확인하세요.", "The assignment changed. Close and reopen to review the latest version.")}</p> : null}
    <TextField label={L("지정 근거", "Basis")} value={basis} onChange={setBasis} maxLength={200} />
    <div className="modal-foot">
      {c.owner?.basis === "ASSIGNED" || base?.assignment ? <button type="button" className="ghost-btn" style={{ marginRight: "auto" }} disabled={busy || !base || changed}
        onClick={() => void assign(null)}>{L("지정 해제", "Unassign")}</button> : null}
      <button type="button" className="ghost-btn" disabled={busy} onClick={onClose}>{L("취소", "Cancel")}</button>
      <button type="button" className="primary-btn" disabled={busy || !base || changed || !selectablePerson(person)}
        onClick={() => { if (selectablePerson(person)) void assign(person); }}>{L("지정", "Assign")}</button>
    </div>
  </Modal>;
}

export function TextModal({ title, label, initial, ok, multi, subject, onClose, onSave, maxLength = 2000 }: {
  title: string; label: string; initial: string; ok: string; multi?: boolean; subject?: string; onClose: () => void; onSave: (value: string) => Promise<void>; maxLength?: number;
}) {
  const L = useL();
  const [value, setValue] = useState(initial);
  const [busy, setBusy] = useState(false);
  return <Modal onClose={onClose} labelledBy="text-title" size="narrow">
    <h2 id="text-title">{title}{subject ? <small><span className="clip">{subject}</span></small> : null}</h2>
    <Field label={label} htmlFor="t-input">
      {multi ? <textarea id="t-input" className="short" value={value} onChange={event => setValue(event.target.value)} maxLength={maxLength} data-autofocus />
        : <input id="t-input" value={value} onChange={event => setValue(event.target.value)} maxLength={maxLength} data-autofocus />}
    </Field>
    <div className="modal-foot">
      <button type="button" className="ghost-btn" onClick={onClose}>{L("취소", "Cancel")}</button>
      <button type="button" className="primary-btn" disabled={busy || !value.trim()}
        onClick={async () => { setBusy(true); try { await onSave(value.trim()); } finally { setBusy(false); } }}>{ok}</button>
    </div>
  </Modal>;
}

export function RuleModal({ c, rule, name, onClose, onGuide }: { c: CredentialRecord; rule: Rule; name: string; onClose: () => void; onGuide: (id: string) => void }) {
  const L = useL();
  const axisName = { exposure: L("노출 정도", "Exposure"), likelihood: L("악용 가능성", "Likelihood of misuse"), unknown: L("판단 근거 없음", "No evidence yet") }[rule.axis];
  const toneText = { bad: L("위험을 높임", "Raises risk"), warn: L("위험을 높임", "Raises risk"), good: L("위험을 낮춤", "Lowers risk"), unknown: L("판단 보류", "On hold") }[rule.tone];
  const fix = rule.remedy ? remediationFor(c, L).find(item => item.id === rule.remedy) : undefined;
  const places = c.exposures.filter(e => e.current);
  return <Modal onClose={onClose} labelledBy="rule-title" size="narrow">
    <h2 id="rule-title">{rule.label} <small><Logo id={c.provider} size={18} /><span className="clip">{name}</span></small></h2>
    <dl className="kv">
      <dt>{L("관련 노출 위치", "Related locations")}</dt>
      <dd className="pill-wrap">{places.length && rule.axis === "exposure" ? places.map((e, index) => <span key={index} className={cls("rule", e.visibility === "public" ? "bad" : "warn", "small-rule")}>
        <Ic name="alert" size={14} /><span className="clip">{e.resource_name}</span></span>) : <span className="subtle">—</span>}</dd>
      <dt>{L("규칙 분류", "Rule category")}</dt><dd className="pill-wrap"><span className="tag">{axisName}</span> <span className="tag">{rule.cat}</span></dd>
      <dt>{L("판단", "Assessment")}</dt><dd>{toneText}</dd>
      <dt>{L("설명", "Description")}</dt><dd>{rule.desc}</dd>
      <dt>{L("근거", "Evidence")}</dt><dd>{rule.evidence}</dd>
      <dt>{L("권장 조치", "Recommended action")}</dt>
      <dd>{fix ? <>{fix.title}<div className="kv-action"><button type="button" className="ghost-btn" onClick={() => onGuide(fix.id)}><Ic name="wand" size={15} />{L("조치 가이드 보기", "View remediation guide")}</button></div></>
        : <span className="subtle">{L("따로 필요한 조치 없음", "No separate action needed")}</span>}</dd>
    </dl>
    <div className="modal-foot"><button type="button" className="ghost-btn" onClick={onClose}>{L("닫기", "Close")}</button></div>
  </Modal>;
}

export function GraphModal({ c, name, view, setView, onClose }: { c: CredentialRecord; name: string; view: "exposure" | "access"; setView: (view: "exposure" | "access") => void; onClose: () => void }) {
  const L = useL();
  const [zoom, setZoom] = useState(1);
  return <Modal onClose={onClose} labelledBy="graph-title" size="wide">
    <h2 id="graph-title" className="graph-title">{L("접근 관계", "Access relationships")} <small><Logo id={c.provider} size={18} /><span className="clip">{name}</span></small>
      <span className="graph-title-right"><GraphToggle view={view} setView={next => { setView(next); setZoom(1); }} /></span></h2>
    <div className="graph-box big"><ZoomControl onZoom={direction => setZoom(current => nextZoom(current, direction))} /><AccessGraph c={c} view={view} big zoom={zoom} name={name} /></div>
    <div className="modal-foot"><span className="note">{L("빨간 표시는 위험 근거, 초록 표시는 완화 근거, 점선은 확정되지 않은 연결입니다.", "Red marks risk evidence, green marks mitigating evidence, and dashed lines are unconfirmed links.")}</span>
      <button type="button" className="ghost-btn" onClick={onClose}>{L("닫기", "Close")}</button></div>
  </Modal>;
}

export function GraphToggle({ view, setView }: { view: "exposure" | "access"; setView: (view: "exposure" | "access") => void }) {
  const L = useL();
  return <div className="seg" role="group" aria-label={L("그림 보기", "Map view")}>
    <button type="button" aria-pressed={view === "exposure"} onClick={() => setView("exposure")}>{L("노출 경로", "Exposure path")}</button>
    <button type="button" aria-pressed={view === "access"} onClick={() => setView("access")}>{L("권한 범위", "Access scope")}</button>
  </div>;
}

type RescanExposure = { id: string; source_type: string; resource_name: string; location: string; status: string; source_connection_ids?: string[] };
type Profile = { id: string; name: string; version: number; state?: string };

export function RescanModal({ findingId, exposures, onClose, onStarted }: { findingId: string; exposures: RescanExposure[]; onClose: () => void; onStarted: () => void }) {
  const L = useL();
  const locale = useLocale();
  const toast = useToast();
  const candidates = exposures.filter(e => e.status !== "REMOVED" && (e.source_connection_ids?.length ?? 0) > 0);
  const [exposure, setExposure] = useState(candidates[0]?.id ?? "");
  const [profiles, setProfiles] = useState<Profile[] | null>(null);
  const [profile, setProfile] = useState("");
  const [plan, setPlan] = useState<{ plan_id: string; profile_version: number; expires_at: string } | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!exposure) return;
    setProfiles(null); setProfile(""); setPlan(null); setError(null);
    api<{ profiles: Profile[] }>(`findings/${findingId}/rescan-profiles?exposure_id=${encodeURIComponent(exposure)}`)
      .then(result => { setProfiles(result.profiles); setProfile(result.profiles[0]?.id ?? ""); }).catch(setError);
  }, [findingId, exposure]);
  const prepare = async () => {
    setBusy(true); setError(null);
    try { setPlan(await send(`findings/${findingId}/rescan-preview`, "POST", { exposure_id: exposure, profile_id: profile, verify: false })); }
    catch (reason) { setError(reason); } finally { setBusy(false); }
  };
  const run = async () => {
    if (!plan) return;
    setBusy(true); setError(null);
    try {
      await send(`findings/${findingId}/rescan`, "POST", { plan_id: plan.plan_id, profile_version: plan.profile_version, confirm: true });
      toast(L("다시 검사를 시작했습니다. 수집·탐지 현황에서 진행을 볼 수 있습니다.", "Rescan started. Follow it under Collection & detection status."));
      onStarted(); onClose();
    } catch (reason) { setError(reason); } finally { setBusy(false); }
  };
  return <Modal onClose={onClose} labelledBy="rescan-title" size="narrow">
    <h2 id="rescan-title">{L("노출 위치 다시 검사", "Rescan the exposed location")}</h2>
    {!candidates.length ? <p className="re-cap">{L("등록된 연동으로 찾은 위치가 없어 다시 검사할 수 없습니다.", "No location was found through a registered integration, so there is nothing to rescan.")}</p> : <>
      <p className="re-cap">{L("선택한 위치 한 곳만 승인된 검사 범위 안에서 다시 읽습니다. 값이 사라졌으면 노출이 제거됨으로 바뀝니다.", "Reads only the chosen location, inside an approved scan scope. If the value is gone, the exposure becomes removed.")}</p>
      <SelectField label={L("다시 검사할 위치", "Location to rescan")} value={exposure} onChange={setExposure}
        options={candidates.map(e => ({ id: e.id, label: `${serviceName(exposureService(e.source_type))} · ${e.resource_name} · ${e.location}` }))} />
      {profiles === null && !error ? <p className="meta">{L("검사 범위를 불러오는 중", "Loading scan scopes")}</p> : null}
      {profiles && !profiles.length ? <p className="re-cap">{L("이 연동에 승인된 검사 범위가 없습니다. 연동 서비스에서 검사 범위를 먼저 승인하세요.", "This integration has no approved scan scope. Approve one under Integrations first.")}</p> : null}
      {profiles?.length ? <SelectField label={L("검사 범위", "Scan scope")} value={profile} onChange={value => { setProfile(value); setPlan(null); }}
        options={profiles.map(p => ({ id: p.id, label: `${p.name} · v${p.version}` }))} /> : null}
      {plan ? <div className="safety"><div className="ok"><Ic name="checkCircle" size={16} /><span>{L(`실행 계획을 준비했습니다 · ${fmtDT(plan.expires_at, locale)}까지 유효`, `Plan ready · valid until ${fmtDT(plan.expires_at, locale)}`)}</span></div></div> : null}
    </>}
    {error ? <div className="err-line" role="alert"><Ic name="alert" size={16} /><span>{reasonText(error, L)}</span></div> : null}
    <div className="modal-foot">
      <button type="button" className="ghost-btn" onClick={onClose}>{L("닫기", "Close")}</button>
      {plan ? <button type="button" className="primary-btn" onClick={run} disabled={busy}><Ic name="scan" size={16} />{L("다시 검사 실행", "Run rescan")}</button>
        : <button type="button" className="primary-btn" onClick={prepare} disabled={busy || !profile}>{L("실행 계획 준비", "Prepare plan")}</button>}
    </div>
  </Modal>;
}
