"use client";

/* One credential in the side panel: what it is, where it was found, why it is risky, who owns it,
 * what to do and what happened. Triage writes go through the finding's own routes. */

import { useEffect, useMemo, useRef, useState } from "react";

import { useLocale } from "@/components/locale";
import { api } from "@/lib/dashboard-api";
import { hasRole, type Session } from "@/lib/dashboard-session";
import type { OwnershipReviewResponse } from "@/lib/dashboard-types";
import { reasonText, send, useApi, useSaved } from "@/console/data";
import { Ic } from "@/console/icons";
import { kindLabel } from "@/console/labels";
import { Drawer, Menu, MenuItem, MenuLabel, MenuSep, Modal, useMenu, useToast } from "@/console/layer";
import { Logo, serviceName } from "@/console/logos";
import type { ViewId } from "@/console/nav";
import { accessRows, type FindingContext, assignedPerson, usePeople } from "@/console/people";
import { type CredentialRecord, isRemoved, lastUseGap, type ResponseSummary, type StepId } from "@/console/records";
import { downloadCsv, rel, useL } from "@/console/text";
import { DTabs, RiskTag, type Status, statusLabel, StatusTag, VerifyTag } from "@/console/ui";
import { AssignModal, ContactModal, RescanModal, RuleModal, type Target, TextModal } from "@/console/views/credentials/modals";
import { locKind, ownerBasis, remediationFor, type Rule, rulesFor, usageBasis, usageGap, verifyBasis } from "@/console/views/credentials/risk";
import { accessTargets, type Detail, HistoryTab, OverviewTab, OwnerTab, RemedTab, RiskTab } from "@/console/views/credentials/tabs";
import { KEY_TYPES } from "@/console/views/approvals/model";
import { KeyPlans } from "@/console/views/approvals/plans";
import { Governance } from "@/console/views/credentials/governance";
import { SecretBinding } from "@/console/views/credentials/binding";
import { IssuedItemModal } from "@/console/views/credentials/issued";
import { ResponseCard, ResponseTag } from "@/console/views/credentials/response";

export type DTab = "overview" | "risk" | "owner" | "remed" | "history";
type ModalState =
  | { kind: "contact"; people: Target[]; notify?: boolean } | { kind: "assign" } | { kind: "tag" } | { kind: "comment" }
  | { kind: "step"; step: StepId; current: string } | { kind: "rule"; rule: Rule } | { kind: "rescan" } | { kind: "forward" }
  | { kind: "issued"; entity: string } | null;

export function CredentialDrawer({ c, session, typeName, name, tab, setTab, onClose, go }: {
  c: CredentialRecord; session: Session; typeName: string; name: string; tab: string | null; setTab: (tab: DTab) => void; onClose: () => void;
  go: (view: ViewId, params?: Record<string, string | null | undefined>) => void; records: CredentialRecord[];
}) {
  const L = useL();
  const locale = useLocale();
  const toast = useToast();
  const saved = useSaved();
  const detail = useApi<Detail>(c.finding_id ? `findings/${c.finding_id}` : null, { every: 30_000 });
  const review = useApi<OwnershipReviewResponse>(c.finding_id ? `findings/${c.finding_id}/ownership-review` : null);
  const response = useApi<ResponseSummary>(c.finding_id ? `findings/${c.finding_id}/response` : null);
  const rules = useMemo(() => rulesFor(c, L, locale), [c, L, locale]);
  const items = useMemo(() => remediationFor(c, L), [c, L]);
  const canTriage = hasRole(session.role, "Analyst") && Boolean(c.finding_id);
  // Who a name stands for (department, email, whether they left), from the IdP integrations.
  const directory = usePeople(hasRole(session.role, "Analyst"));
  const people = directory.data?.items;
  // What the code hosts say about the exposed files: CODEOWNERS, last authors, who can read each repository.
  const [watching, setWatching] = useState(false);
  const context = useApi<FindingContext>(canTriage ? `findings/${c.finding_id}/context` : null, { every: watching ? 3_000 : undefined });
  const contextPending = context.data?.job_status === "QUEUED" || context.data?.job_status === "RUNNING";
  useEffect(() => {
    // A finished read changes the row too (owner, authors, the count with access).
    if (watching && !contextPending) saved();
    setWatching(contextPending);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [contextPending]);
  const withAccess = useMemo(() => accessTargets(context.data, L), [context.data, L]);
  const [modal, setModal] = useState<ModalState>(null);
  const [busy, setBusy] = useState(false);
  const actionsMenu = useMenu(), contactMenu = useMenu();
  const dtab: DTab = (["overview", "risk", "owner", "remed", "history"] as const).find(value => value === tab) ?? "overview";
  const top = useRef<HTMLDivElement>(null);
  useEffect(() => { top.current?.closest(".drawer")?.scrollTo({ top: 0 }); }, [dtab, c.id]);

  const targets = useMemo(() => {
    const out: Target[] = [];
    // One row per person, by the directory's name when it knows them.
    const push = (target: Target) => {
      const next = target;
      if (next.name && !out.some(t => t.name === next.name)) out.push(next);
    };
    if (c.owner?.name || c.owner?.team) push({ name: c.owner.name ?? c.owner.team!, role: L("대응 담당자", "Response owner"), basis: ownerBasis(c, L), email: c.owner?.email ?? undefined, team: c.owner?.department ?? undefined });
    if (c.issuer) push({ name: c.issuer.name, role: L("발급 계정", "Issuing account"), basis: `${serviceName(c.issued?.provider ?? c.provider, c.issued?.provider)} ${L("발급 목록", "inventory")}` });
    for (const candidate of review.data?.context.candidates ?? []) push({ name: candidate.owner, role: "CODEOWNERS", basis: [review.data?.context.repository, review.data?.context.codeowners_path].filter(Boolean).join(" · ") });
    // Whoever last changed each exposed file, with the address the commit carries (analysts read it).
    for (const e of c.exposures) {
      if (!e.current || !e.author) continue;
      const places = context.data?.locations.filter(place => place.source_type === e.source_type && place.repository === e.resource_name && place.path === e.location) ?? [];
      // The summary row lacks source identity. Only a unique matching location may supply its commit email.
      const commit = places.length === 1 && places[0].source_connection_id ? places[0].author : undefined;
      // A page reads by its name; a file by its repository and path.
      const where = locKind(e.source_type) === "doc" ? e.resource_name : `${e.resource_name} ${e.location}`;
      push({ name: e.author, role: L("노출 위치 작성자", "Author of the exposed location"), basis: L(`${where} 마지막 수정`, `Last edited ${where}`),
        email: commit?.email ?? undefined });
    }
    return out;
  }, [c, review.data, context.data, L]);
  const ownerPerson = assignedPerson(c);

  const act = async (work: () => Promise<unknown>, done?: string) => {
    setBusy(true);
    try { await work(); if (done) toast(done); saved(); detail.reload(); review.reload(); }
    catch (error) { toast(reasonText(error, L), "bad"); }
    finally { setBusy(false); }
  };
  const setStatus = (target: Status) => act(async () => {
    const id = c.finding_id!;
    const wf = c.workflow_status ?? "OPEN";
    const closed = ["RESOLVED", "FALSE_POSITIVE", "IGNORED"].includes(wf);
    const post = (path: string, body: unknown = {}) => send(`findings/${id}/${path}`, "POST", body);
    if (target === "pending") { if (wf !== "OPEN") await post("reopen", { resolution: "" }); return; }
    if (target === "review" || target === "action") {
      if (closed) await post("reopen", { resolution: "" });
      if (wf !== "ACKNOWLEDGED" || closed) await post("acknowledge");
      const current = await api<{ revision: number; stage: string | null }>(`findings/${id}/annotations`);
      if (target === "action" ? current.stage !== "action" : current.stage === "action") {
        await send(`findings/${id}/stage`, "PUT", { revision: current.revision, stage: target });
      }
      return;
    }
    if (wf !== "OPEN" && wf !== "ACKNOWLEDGED") await post("reopen", { resolution: "" });
    if (target === "done") await post("resolve", { resolution: "" });
    else if (target === "fp") await post("false-positive", { reason_code: "" });
    else if (target === "ignored") await post("ignore", { reason_code: "" });
  }, L(`처리 상태를 '${statusLabel(target, L)}'(으)로 바꿨습니다.`, `Status set to '${statusLabel(target, L)}'.`));
  const recheck = () => act(async () => { context.replace(await send<FindingContext>(`findings/${c.finding_id}/context`, "POST")); },
    L("코드 호스트에서 다시 확인합니다.", "Checking again with the code host."));
  // The finding as it stands, to every SIEM and webhook destination (finding.forwarded), audited by the API.
  const forward = async () => {
    setBusy(true);
    try {
      const sent = await send<{ destinations: number }>(`findings/${c.finding_id}/forward`, "POST");
      toast(L(`SIEM·웹훅 출력 ${sent.destinations}곳으로 보냈습니다.`, `Sent to ${sent.destinations} SIEM and webhook ${sent.destinations === 1 ? "destination" : "destinations"}.`));
      setModal(null);
      detail.reload();
    } catch (error) { toast(reasonText(error, L), "bad"); }
    finally { setBusy(false); }
  };
  const exportAccess = () => {
    if (!context.data) return;
    downloadCsv(`cremore-access-${c.finding_id}.csv`, accessRows(context.data));
    toast(L("위치별 접근 관측과 수집 상태를 CSV로 내려받았습니다.", "Downloaded location access observations and collection status as CSV."));
  };
  const saveTags = (tags: string[], done: string) => act(async () => {
    const current = await api<{ revision: number }>(`findings/${c.finding_id}/annotations`);
    await send(`findings/${c.finding_id}/tags`, "PUT", { revision: current.revision, tags });
  }, done);

  const usage = c.last_used ? <span className="use-chip" data-tip={usageBasis(c, L)}><Ic name="activity" size={14} />{L("마지막 사용 ", "Last used ")}{rel(c.last_used.at, locale)}</span>
    : <span className="use-chip" data-tip={usageGap(c, L)}><Ic name="activity" size={14} />{lastUseGap(c, L) ?? L("사용 기록 미수집", "Usage not collected")}</span>;
  const tabs = [{ id: "overview" as const, label: L("개요", "Overview") }, { id: "risk" as const, label: L("위험 분석", "Risk analysis"), count: rules.length },
    { id: "owner" as const, label: L("대응 담당자", "Response owner") }, { id: "remed" as const, label: L("조치", "Remediation"), count: items.length }, { id: "history" as const, label: L("이력", "History") }];
  const currentExposures = (detail.data?.exposures ?? []).filter(e => e.status !== "REMOVED" && (e.source_connection_ids?.length ?? 0) > 0);

  return <Drawer label={L(`${name} 상세`, `${name} details`)} onClose={onClose}>
    <div className="drawer-head" ref={top}>
      <div className="dh-top">
        <div className="dh-logo"><Logo id={c.provider} size={34} /></div>
        <div className="dh-main">
          <h2 className="dh-title">{name}</h2>
          <div className="dh-badges">
            <span className="tag">{kindLabel(c.kind, L, true)}</span>
            <span className="tag">{typeName}</span>
            {c.hint ? <span className="tag mono">{c.hint}<button type="button" aria-label={L("식별자 복사", "Copy identifier")} data-tip={L("가린 식별자 복사", "Copy masked identifier")}
              onClick={() => navigator.clipboard?.writeText(c.hint ?? "").then(() => toast(L("가린 식별자를 복사했습니다.", "Masked identifier copied.")), () => toast(L("복사하지 못했습니다.", "Could not copy."), "bad"))}><Ic name="copy" size={13} /></button></span> : null}
            {c.tags.map(tag => <span className="tag" key={tag}>#{tag}{canTriage ? <button type="button" aria-label={L(`#${tag} 태그 빼기`, `Remove tag #${tag}`)}
              onClick={() => void saveTags(c.tags.filter(t => t !== tag), L(`#${tag} 태그를 뺐습니다.`, `Removed tag #${tag}.`))}><Ic name="close" size={12} /></button> : null}</span>)}
          </div>
        </div>
        <div className="dh-actions">
          <ResponseTag c={response.data ? { ...c, response: response.data } : c} />
          <button type="button" className="icon-btn" aria-label={L("작업", "Actions")} data-tip={L("작업", "Actions")} onClick={event => actionsMenu.open(event.currentTarget)}><Ic name="dots" size={19} /></button>
          <button type="button" className="icon-btn" aria-label={L("상세 닫기", "Close details")} data-tip={L("상세 닫기", "Close details")} onClick={onClose}><Ic name="panelClose" size={19} /></button>
        </div>
      </div>
      <div className="dh-row2"><RiskTag level={c.risk} /><VerifyTag state={c.verification.state} basis={c.verification.basis} tip={verifyBasis(c, L)} />{usage}</div>
      <DTabs value={dtab} items={tabs} onChange={setTab} label={L("상세 탭", "Detail tabs")} />
    </div>
    <div className="drawer-body" id="drawer-body">
      {c.removal_pending_location_count ? <p className="meta tone-warn">{L(`다른 연결의 제거 확인 대기: ${c.removal_pending_location_count}곳. 같은 위치를 읽는 모든 연결이 확인될 때까지 현재 노출로 유지합니다.`, `Awaiting removal confirmation from other connections at ${c.removal_pending_location_count} locations. Exposure remains active until every connection reading the same location confirms removal.`)}</p> : null}
      {isRemoved(c) ? <p className="meta">{L("연결된 검사 범위의 모든 노출 위치에서 제거를 확인했습니다. 과거 기록과 대응 이력은 유지됩니다.", "Removal was confirmed at every exposed location in the connected scan scope. Historical evidence and response records remain available.")}</p> : null}
      {dtab === "owner" ? <ResponseCard c={c} response={response} canEdit={canTriage} admin={session.role === "Admin"}
        onRescan={currentExposures.length ? () => setModal({ kind: "rescan" }) : undefined} /> : null}
      {dtab === "overview" ? <OverviewTab c={c} detail={detail.data} name={name} canLookup={hasRole(session.role, "Analyst")}
        openIssued={entity => setModal({ kind: "issued", entity })} /> : null}
      {dtab === "risk" ? <RiskTab c={c} rules={rules} detail={detail.data} onRule={rule => setModal({ kind: "rule", rule })} /> : null}
      {dtab === "owner" ? <OwnerTab c={c} review={review.data} context={context.data} targets={targets} owner={ownerPerson} canEdit={canTriage} onAssign={() => setModal({ kind: "assign" })}
        onContact={chosen => setModal({ kind: "contact", people: chosen })} onNotify={() => setModal({ kind: "contact", people: withAccess, notify: true })}
        onRecheck={canTriage ? recheck : undefined} /> : null}
      {dtab === "remed" ? <RemedTab c={c} items={items} name={name} canEdit={canTriage} onComment={(step, current) => setModal({ kind: "step", step, current })}
        extra={<>
          {c.credential_id && KEY_TYPES.includes(c.credential_type) ? <>
            <SecretBinding credentialId={c.credential_id} admin={session.role === "Admin"} />
            <KeyPlans credentialId={c.credential_id} name={name} actor={{ id: session.id, role: session.role }} /></> : null}
          {/* A credential another provider's inventory lists: its own plans, where CreMore can act on it. */}
          {c.issued?.entity_id ? <KeyPlans key={c.issued.entity_id} provider path={`v2/coverage/inventory/${encodeURIComponent(c.issued.entity_id)}/action-plans`}
            name={name} actor={{ id: session.id, role: session.role }} /> : null}
          <Governance c={c} me={session.ref} people={people} canEdit={canTriage} go={go} actions={detail.data?.management_actions} onChanged={detail.reload} />
        </>} /> : null}
      {dtab === "history" ? <HistoryTab c={c} detail={detail.data} typeName={typeName} /> : null}
    </div>

    {actionsMenu.anchor ? <Menu anchor={actionsMenu.anchor} onClose={actionsMenu.close} restore={actionsMenu.opener} label={L("작업", "Actions")}>
      <MenuItem icon="webhook" disabled={!canTriage || !c.finding_id || busy} tip={c.finding_id ? undefined : L("노출된 Credential을 보냅니다.", "Exposed credentials are sent.")}
        onSelect={() => { actionsMenu.close(); setModal({ kind: "forward" }); }}>{L("웹훅 이벤트 보내기", "Send webhook event")}</MenuItem>
      <MenuItem icon="userPlus" disabled={!canTriage} onSelect={() => { actionsMenu.close(); setModal({ kind: "assign" }); }}>{L("담당자 지정", "Assign owner")}</MenuItem>
      <MenuItem icon="download" disabled={!context.data?.locations.length} tip={context.data?.locations.length ? undefined : L("내보낼 위치 관측이 없습니다.", "No location observations to export.")}
        onSelect={() => { actionsMenu.close(); exportAccess(); }}>{L("위치별 접근 관측 내보내기", "Export location access observations")}</MenuItem>
      {c.status ? <><MenuSep />
        <MenuItem icon="minusCircle" disabled={!canTriage || c.status === "fp"} onSelect={() => { actionsMenu.close(); void setStatus("fp"); }}>{L("오탐으로 표시", "Mark as false positive")}</MenuItem>
        <MenuItem icon="minusCircle" disabled={!canTriage || c.status === "ignored"} onSelect={() => { actionsMenu.close(); void setStatus("ignored"); }}>{L("예외로 분류", "Classify as an exception")}</MenuItem>
        {c.status === "fp" || c.status === "ignored" ? <MenuItem icon="refresh" disabled={!canTriage} onSelect={() => { actionsMenu.close(); void setStatus("pending"); }}>{L("오탐·예외 분류 해제", "Clear false-positive or exception classification")}</MenuItem> : null}</> : null}
      <MenuSep />
      <MenuItem icon="send" className="pri" disabled={!canTriage || !targets.length} end={<Ic name="right" size={15} />}
        tip={targets.length ? undefined : L("연락할 사람을 찾지 못했습니다", "No one to contact was found")}
        onSelect={() => { const anchor = actionsMenu.opener.current; actionsMenu.close(); if (anchor) contactMenu.open(anchor); }}>{L("담당자에게 연락", "Contact owner")}</MenuItem>
      <MenuItem icon="send" disabled={!canTriage || !withAccess.length} tip={withAccess.length ? undefined : L("접근 가능 인원을 확인하지 못했습니다.", "People with access could not be confirmed.")}
        onSelect={() => { actionsMenu.close(); setModal({ kind: "contact", people: withAccess, notify: true }); }}>{L("접근 가능 인원에게 알림", "Notify people with access")}</MenuItem>
      <MenuItem icon="tag" disabled={!canTriage} onSelect={() => { actionsMenu.close(); setModal({ kind: "tag" }); }}>{L("태그 추가", "Add tag")}</MenuItem>
      <MenuItem icon="comment" disabled={!canTriage} onSelect={() => { actionsMenu.close(); setModal({ kind: "comment" }); }}>{L("코멘트 남기기", "Add comment")}</MenuItem>
      {c.exposed ? <><MenuSep /><MenuItem icon="scan" disabled={!canTriage || !currentExposures.length}
        tip={currentExposures.length ? undefined : L("등록된 연동으로 찾은 위치가 없습니다", "No location was found through a registered integration")}
        onSelect={() => { actionsMenu.close(); setModal({ kind: "rescan" }); }}>{L("노출 위치 다시 검사", "Rescan the exposed location")}</MenuItem></> : null}
      {c.issued?.entity_id ? <MenuItem icon="columns" onSelect={() => { actionsMenu.close(); setModal({ kind: "issued", entity: c.issued!.entity_id! }); }}>{L("발급 항목 보기", "View the issued item")}</MenuItem> : null}
    </Menu> : null}

    {contactMenu.anchor ? <Menu anchor={contactMenu.anchor} onClose={contactMenu.close} restore={contactMenu.opener} label={L("연락할 사람", "Who to contact")}>
      <MenuLabel>{L("연락할 사람 · 근거", "Who to contact · basis")}</MenuLabel>
      {targets.map(target => <button type="button" role="menuitem" className="menu-item" key={`${target.name}:${target.role}`} onClick={() => { contactMenu.close(); setModal({ kind: "contact", people: [target] }); }}>
        <Ic name="user" size={17} /><span className="mi-text"><span>{target.name} · {target.role}</span><span className="person-sub">{target.basis}</span></span></button>)}
      {targets.length > 1 ? <MenuItem icon="users" onSelect={() => { contactMenu.close(); setModal({ kind: "contact", people: targets }); }}>{L("모두에게 연락", "Contact everyone")}</MenuItem> : null}
      <MenuSep /><MenuItem icon="userPlus" onSelect={() => { contactMenu.close(); setModal({ kind: "assign" }); }}>{L("담당자 먼저 지정하기", "Assign an owner first")}</MenuItem>
    </Menu> : null}

    {modal?.kind === "contact" ? <ContactModal c={c} name={name} typeName={typeName} targets={targets} people={modal.people} directory={people} canChangeStatus={false} notify={modal.notify}
      onClose={() => setModal(null)} onDone={async status => { if (status) await setStatus(status); else { saved(); detail.reload(); } }} /> : null}
    {modal?.kind === "assign" ? <AssignModal c={c} name={name} admin={session.role === "Admin"} onClose={() => setModal(null)} onAssign={async (person, team, version, basis) => {
      await send(`findings/${c.finding_id}/assign`, "POST", { person_ref: person?.person_ref ?? null, team, expected_version: version });
      if (person && basis) {
        try { await send(`findings/${c.finding_id}/comments`, "POST", { text: L(`담당자 지정 근거: ${basis}`, `Owner assignment basis: ${basis}`) }); }
        catch (error) { toast(L("담당자는 지정했지만 근거 코멘트를 저장하지 못했습니다. ", "The owner was assigned, but the basis comment was not saved. ") + reasonText(error, L), "bad"); }
      }
      toast(person ? L(`${person.name}님을 담당자로 지정했습니다.`, `Assigned ${person.name} as the owner.`) : L("담당자 지정을 해제했습니다.", "Unassigned the owner."));
      saved(); detail.reload(); review.reload();
    }} /> : null}
    {modal?.kind === "tag" ? <TextModal title={L("태그 추가", "Add tag")} label={L("태그 이름", "Tag name")} initial="" ok={L("추가", "Add")} subject={name} maxLength={41}
      onClose={() => setModal(null)} onSave={async value => {
        const tag = value.replace(/^#/, "").trim();
        await saveTags(Array.from(new Set([...c.tags, tag])), L(`#${tag} 태그를 추가했습니다.`, `Added tag #${tag}.`));
        setModal(null);
      }} /> : null}
    {modal?.kind === "comment" ? <TextModal title={L("코멘트 남기기", "Add comment")} label={L("코멘트", "Comment")} initial="" ok={L("남기기", "Post")} subject={name} multi
      onClose={() => setModal(null)} onSave={async value => {
        await act(() => send(`findings/${c.finding_id}/comments`, "POST", { text: value }), L("코멘트를 남겼습니다. 이력 탭에서 볼 수 있습니다.", "Comment posted. See it in the History tab."));
        setModal(null);
      }} /> : null}
    {modal?.kind === "step" ? <TextModal title={L("코멘트", "Comment")} label={L("조치 코멘트", "Remediation comment")} initial={modal.current} ok={L("저장", "Save")} subject={name} multi
      onClose={() => setModal(null)} onSave={async value => {
        const current = c.steps[modal.step];
        await act(async () => {
          const fresh = await api<{ revision: number }>(`findings/${c.finding_id}/annotations`);
          await send(`findings/${c.finding_id}/remediation/${modal.step}`, "PUT", { revision: fresh.revision, status: current?.status ?? "open", comment: value });
        }, L("조치 코멘트를 저장했습니다.", "Saved the remediation comment."));
        setModal(null);
      }} /> : null}
    {modal?.kind === "rule" ? <RuleModal c={c} rule={modal.rule} name={name} onClose={() => setModal(null)} onGuide={id => {
      setModal(null); setTab("remed");
      window.setTimeout(() => {
        const guide = document.getElementById(`guide-${id}`), panel = document.getElementById("drawer"), head = panel?.querySelector(".drawer-head") as HTMLElement | null;
        if (guide && panel) panel.scrollTo({ top: guide.offsetTop - (head?.offsetHeight ?? 0) - 12, behavior: "smooth" });
      }, 60);
    }} /> : null}
    {modal?.kind === "forward" ? <Modal onClose={() => setModal(null)} labelledBy="forward-title" size="narrow" dismissable={!busy}>
      <h2 id="forward-title">{L("웹훅 이벤트 보내기", "Send webhook event")} <small><span className="clip">{name}</span></small></h2>
      <p className="meta">{L("이 탐지를 지금 상태 그대로 연결된 모든 SIEM·웹훅 출력에 보냅니다. 1분 안에 다시 보내면 같은 이벤트입니다.",
        "Sends this finding as it stands to every connected SIEM and webhook destination. Sending it again within a minute is the same event.")}</p>
      <div className="pill-wrap"><RiskTag level={c.risk} />{c.status ? <StatusTag status={c.status} /> : null}</div>
      <div className="modal-foot">
        <button type="button" className="ghost-btn" onClick={() => setModal(null)} disabled={busy}>{L("취소", "Cancel")}</button>
        <button type="button" className="primary-btn" disabled={busy} onClick={() => void forward()}><Ic name="webhook" size={15} />{L("보내기", "Send")}</button>
      </div>
    </Modal> : null}
    {modal?.kind === "rescan" && c.finding_id ? <RescanModal findingId={c.finding_id} exposures={detail.data?.exposures ?? []} onClose={() => setModal(null)} onStarted={() => { saved(); }} /> : null}
    {modal?.kind === "issued" ? <IssuedItemModal entityId={modal.entity} onClose={() => setModal(null)} /> : null}
  </Drawer>;
}
