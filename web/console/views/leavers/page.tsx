"use client";

/* Departed owners' credentials: the people the IdPs show as gone, the provider accounts linked to them and each
 * credential they left, with a verdict (used after departure, active, revoked or expired, unknown). An AWS access
 * key a departed person left is disabled through an action plan; every other credential is reported with a ticket.
 * People are named from the IdP directory when their collection keeps profiles, else by their IdP user id. */

import { useMemo, useState } from "react";

import { useLocale } from "@/components/locale";
import { reasonText, send, useApi, useRead, useSaved } from "@/console/data";
import { Ic } from "@/console/icons";
import { typeLabel } from "@/console/labels";
import { Drawer, Menu, MenuItem, useMenu, useToast } from "@/console/layer";
import { Logo, serviceName } from "@/console/logos";
import { PEOPLE_PATH, type People, type Person } from "@/console/people";
import { DirectoryStatus } from "@/console/people-directory";
import type { ViewProps } from "@/console/shell";
import { fmtDT, rel, type Say, useL } from "@/console/text";
import { Banner, Card, CardBody, EmptyRow, ErrorLine, Fact, Facts, Loading, PageHead, Seg, StateChip, Tabs, Tile, Tiles } from "@/console/ui";
import { api } from "@/lib/dashboard-api";
import { type Actor } from "@/console/views/approvals/model";
import { KeyPlans } from "@/console/views/approvals/plans";

type Summary = {
  people: number; departed: number; departed_with_credentials: number; orphans: number; by_verdict: Record<string, number>; candidates: number;
  sources: { connection_id: string; name: string; provider: string; role: "idp" | "directory"; enabled: boolean; latest_run: { status: string; finished_at: string | null } | null }[];
  evaluated_at: string | null; retention_days: number;
  // PARTIAL: the latest check stopped at a listing it could not read whole (cremore/identity/leavers.py).
  status?: "COMPLETE" | "PARTIAL" | null; reasons?: string[];
};
type Orphan = {
  ref: string; verdict: string; provider: string; reasons: string[]; ticket_id: string | null; actionable: boolean; first_seen_at: string | null;
  person: { ref: string; provider: string; idp_user_id: string; idp_state: string; departed_at: string | null; departure_basis: string | null; idp_disagreement: boolean };
  account: { ref: string; provider: string; label: string; link_basis: string };
  credential: { type: string; name: string; state: string; last_used_at: string | null; expires_at: string | null; current: boolean; exposed: boolean | null; vault_state: string | null } | null;
};
type Orphans = { items: Orphan[]; total: number; facets: { verdict: string[]; provider: string[] } };
type LeaverPerson = {
  ref: string; provider: string; idp_user_id: string; idp_state: string; departed_at: string | null; departure_basis: string | null;
  accounts: { ref: string; provider: string; label: string }[]; verdicts: Record<string, number>;
};
type Candidate = { account_ref: string; person_ref: string; basis: string; account_label: string; account_provider: string; person: { provider: string; idp_user_id: string; departed_at: string | null } };

const VERDICTS: Record<string, [string, string]> = {
  USED_AFTER_DEPARTURE: ["퇴사 후 사용", "Used after departure"], ACTIVE: ["활성", "Active"],
  REVOKED_OR_EXPIRED: ["폐기·만료", "Revoked or expired"], UNKNOWN: ["상태 미확인", "State unknown"],
};
const VERDICT_TONE: Record<string, "ok" | "warn" | "partial" | undefined> = { USED_AFTER_DEPARTURE: "partial", ACTIVE: "warn", REVOKED_OR_EXPIRED: "ok", UNKNOWN: undefined };
const REASONS: Record<string, [string, string]> = {
  ISSUER_OBSERVATION_NOT_CURRENT: ["발급 목록의 마지막 수집에 이 자격증명이 없습니다", "The latest inventory collection did not list this credential"],
  PROVIDER_STATE_UNKNOWN: ["공급자가 상태를 알려 주지 않았습니다", "The provider reported no state"],
  PROVIDER_DOES_NOT_LIST_EVERY_CREDENTIAL: ["이 공급자는 한 사용자의 자격증명을 모두 나열하지 않습니다", "This provider does not list every credential of a user"],
  NO_LAST_USE_REPORTED: ["공급자가 마지막 사용 시각을 알려 주지 않았습니다", "The provider reported no last use"],
  IDP_STATES_DISAGREE: ["IdP마다 재직 상태가 다릅니다", "The IdPs disagree on this person's state"],
};
const DEPARTURE: Record<string, [string, string]> = {
  PROVIDER_REPORTED: ["IdP가 알린 시각", "Time the IdP reported"], ADMIN_EVENT: ["관리 이벤트 시각", "Admin event time"],
  FIRST_OBSERVED_DISABLED: ["비활성으로 처음 본 수집 시각", "First collection that saw them disabled"],
  FIRST_OBSERVED_MISSING: ["목록에서 처음 빠진 수집 시각", "First collection that no longer listed them"],
};
const LINK: Record<string, [string, string]> = {
  SAML_NAME_ID: ["SAML NameID", "SAML NameID"], SCIM_EXTERNAL_ID: ["SCIM 외부 ID", "SCIM external ID"], EXTERNAL_UID: ["외부 UID", "External UID"],
  IDP_OBJECT_ID: ["IdP 객체 ID", "IdP object ID"], VERIFIED_EMAIL: ["확인된 이메일", "Verified email"], PROVIDER_LOGIN: ["공급자 로그인", "Provider login"],
  OPERATOR_CONFIRMED: ["관리자 확정", "Confirmed by an Admin"],
};
const words = (table: Record<string, [string, string]>, key: string | null | undefined, L: Say) => key && table[key] ? L(...table[key]) : key ?? "—";
// A listing the check reads whole, by the code it stops with (leavers._every, _report_rows).
const LISTINGS: Record<string, [string, string]> = {
  IDP_PEOPLE: ["IdP 사람 목록", "IdP people"], ISSUED_CREDENTIALS: ["발급 목록", "Issued credentials"],
  DIRECTORY_ACCOUNTS: ["GitHub 신원 목록", "GitHub identities"], COVERAGE_REPORT: ["금고 대조 보고", "Vault comparison report"],
};
export function listingReason(code: string, L: Say) {
  const match = /^([A-Z_]+?)_(LIMIT_REACHED|CHANGED_WHILE_READ)$/.exec(code);
  const name = match ? LISTINGS[match[1]] : undefined;
  if (!match || !name) return code;
  return `${L(...name)}${match[2] === "LIMIT_REACHED" ? L(" 한도 초과", " past its limit") : L(" 읽는 중 변경", " changed while read")}`;
}
const IDPS = ["okta", "entra_id", "google_workspace", "keycloak", "github_identity"];

/** Every page of the people directory (keyset pages by name): a departed person is named wherever their name sorts. */
export async function everyPerson(path: string, read: (path: string) => Promise<People> = path => api<People>(path)): Promise<People> {
  const items: Person[] = [];
  let page: People, cursor: string | null | undefined;
  do {
    page = await read(cursor ? `${path}&cursor=${encodeURIComponent(cursor)}` : path);
    items.push(...page.items);
    cursor = page.next_cursor;
  } while (cursor);
  return { ...page, items };
}

export function Leavers({ session, route, setParams, go, can }: ViewProps) {
  const L = useL();
  const locale = useLocale();
  const toast = useToast();
  const saved = useSaved();
  const admin = session.role === "Admin";
  const summary = useApi<Summary>("leavers/summary", { every: 60_000 });
  const orphans = useApi<Orphans>("leavers/orphans?limit=200", { every: 60_000 });
  const departed = useApi<{ items: LeaverPerson[]; total: number }>("leavers/people?limit=200");
  const candidates = useApi<{ items: Candidate[]; total: number }>("leavers/candidates");
  // Read once (every: 0): the whole directory, not re-read on every refresh.
  const directory = useRead<People>(PEOPLE_PATH, everyPerson, "every-person", { every: 0 });
  const chooser = useMenu();
  const [busy, setBusy] = useState(false);
  const p = route.params;
  const tab = (["people", "candidates"] as const).find(value => value === p.get("tab")) ?? "orphans";
  const verdict = p.get("verdict") ?? "all";
  const personFilter = p.get("person");
  const nameOf = useMemo(() => {
    const byRef = new Map<string, Person>();
    for (const person of directory.data?.items ?? []) for (const ref of person.refs ?? [person.id]) byRef.set(ref, person);
    return (ref: string, fallback: string) => byRef.get(ref) ?? { name: fallback } as Pick<Person, "name"> & Partial<Person>;
  }, [directory.data]);

  const title = L("퇴사자 Credential", "Departed owners");
  const meta = L("IdP에서 퇴사로 확인된 사람이 남긴 Credential", "Credentials left by people the IdPs show as gone");
  const evaluate = async () => {
    setBusy(true);
    try {
      const result = await send<{ status?: string }>("leavers/evaluate", "POST");
      if (result?.status === "PARTIAL") toast(L("목록을 끝까지 읽지 못해 판정을 바꾸지 않았습니다", "A listing could not be read whole; no verdict changed"), "bad");
      else toast(L("퇴사자 점검을 다시 했습니다", "The departed-owner check ran again"));
      saved();
    }
    catch (reason) { toast(reasonText(reason, L), "bad"); }
    finally { setBusy(false); }
  };
  const head = <PageHead title={title} meta={meta}>
    {admin ? <button type="button" className="ghost-btn" disabled={busy} onClick={() => void evaluate()}><Ic name="refresh" size={15} />{L("지금 점검", "Check now")}</button> : null}
  </PageHead>;
  if (summary.error) return <>{head}<ErrorLine onRetry={summary.reload}>{reasonText(summary.error, L)}</ErrorLine></>;
  if (!summary.data || !orphans.data) return <>{head}<Loading /></>;

  const s = summary.data;
  const idps = s.sources.filter(source => source.role === "idp");
  const rows = orphans.data.items.filter(item => (verdict === "all" || item.verdict === verdict) && (!personFilter || item.person.ref === personFilter));
  const selected = orphans.data.items.find(item => item.ref === p.get("id"));
  const filteredPerson = personFilter ? departed.data?.items.find(person => person.ref === personFilter) : undefined;

  return <>
    {head}
    {s.status === "PARTIAL" ? <Banner tone="warn" icon="alert">{L(
      `마지막 점검이 목록을 끝까지 읽지 못해 판정·연결을 새로 내리지 않았습니다(${(s.reasons ?? []).map(code => listingReason(code, L)).join(", ")}). 판정과 연결은 마지막으로 끝까지 마친 점검의 결과이고, 끝까지 읽은 IdP의 재직 상태는 반영했습니다.`,
      `The latest check could not read a listing whole and drew no new verdict or link (${(s.reasons ?? []).map(code => listingReason(code, L)).join(", ")}). Verdicts and links are those of the last check that finished; people's states come from the IdP listings read whole.`)}</Banner> : null}
    <Tiles>
      <Tile icon="userMinus" tone="violet" label={L("퇴사자", "Departed")} value={s.departed} onClick={() => setParams({ tab: "people", id: null })}
        tip={L("연결한 IdP가 비활성·삭제로 보는 사람입니다.", "People the connected IdPs show as disabled or deleted.")} />
      <Tile icon="key" tone={s.orphans ? "amber" : "green"} label={L("남은 Credential", "Credentials left")} value={s.orphans} of={L(`${s.departed_with_credentials}명`, `${s.departed_with_credentials} people`)}
        tip={L("퇴사자와 연결된 공급자 계정에 남은 Credential입니다.", "Credentials on provider accounts linked to a departed person.")} onClick={() => setParams({ tab: null, verdict: null, person: null })} />
      <Tile icon="alert" tone={s.by_verdict.USED_AFTER_DEPARTURE ? "red" : "green"} label={L("퇴사 후 사용", "Used after departure")} value={s.by_verdict.USED_AFTER_DEPARTURE ?? 0}
        tip={L("공급자가 알린 마지막 사용이 퇴사 뒤인 Credential입니다.", "Credentials whose last use the provider reported is after the departure.")}
        onClick={() => setParams({ tab: null, verdict: "USED_AFTER_DEPARTURE", person: null })} />
      <Tile icon="userQ" tone={s.candidates ? "amber" : "gray"} label={L("확정할 연결", "Links to confirm")} value={s.candidates}
        tip={L("로그인 이름처럼 약한 근거로만 이어진 계정과 사람입니다. 관리자가 확정하거나 거절합니다.", "Accounts tied to a person only by a weak match such as a login. An Admin confirms or rejects them.")}
        onClick={() => setParams({ tab: "candidates", id: null })} />
    </Tiles>

    {directory.data?.directory ? <Card className="list-card" title={L("대응 담당자 목록", "Responder directory")}><CardBody>
      <DirectoryStatus directory={directory.data.directory} admin={admin} onReload={directory.reload} />
    </CardBody></Card> : null}

    {!idps.length ? <Card className="list-card" title={L("IdP 연결", "IdP connection")}>
      <CardBody>
        <p className="meta">{L("Okta·Microsoft Entra ID·Keycloak 같은 IdP를 연결하면 퇴사한 사람과 그 사람이 남긴 Credential을 찾습니다.", "Connect an IdP such as Okta, Microsoft Entra ID or Keycloak to find people who left and the credentials they left behind.")}</p>
        {can("sources") ? <div className="md-actions"><button type="button" className="primary-btn" onClick={event => chooser.open(event.currentTarget)}><Ic name="plus" size={15} />{L("IdP 연동하기", "Connect an IdP")}</button></div> : null}
      </CardBody>
    </Card> : null}

    <Tabs value={tab} onChange={value => setParams({ tab: value === "orphans" ? null : value, id: null })} label={L("퇴사자 보기", "Departed owners view")}
      items={[{ id: "orphans" as const, label: L("남은 Credential", "Credentials left"), count: orphans.data.total },
        { id: "people" as const, label: L("퇴사자", "Departed people"), count: departed.data?.total ?? s.departed },
        { id: "candidates" as const, label: L("연결 후보", "Link candidates"), count: candidates.data?.total ?? s.candidates }]} />

    {tab === "orphans" ? <Card className="list-card">
      <div className="list-tools">
        <Seg value={verdict} onChange={value => setParams({ verdict: value === "all" ? null : value })} label={L("판정", "Verdict")}
          options={[{ id: "all", label: L("전체", "All") }, ...["USED_AFTER_DEPARTURE", "ACTIVE", "UNKNOWN", "REVOKED_OR_EXPIRED"]
            .filter(key => orphans.data!.facets.verdict.includes(key)).map(key => ({ id: key, label: L(...VERDICTS[key]) }))]} />
      </div>
      {filteredPerson ? <div className="applied"><span className="applied-chip"><span className="wrap-t">{L("사람: ", "Person: ")}{nameOf(filteredPerson.ref, filteredPerson.idp_user_id).name}</span>
        <button type="button" onClick={() => setParams({ person: null })} aria-label={L("사람 필터 해제", "Clear person filter")}><Ic name="close" size={13} /></button></span></div> : null}
      <div className="table-wrap"><table className="tbl">
        <thead><tr><th>{L("사람", "Person")}</th><th>{L("계정", "Account")}</th><th className="col-md">Credential</th><th>{L("판정", "Verdict")}</th><th className="col-sm">{L("퇴사", "Departed")}</th></tr></thead>
        <tbody>
          {rows.length ? rows.map(item => {
            const person = nameOf(item.person.ref, item.person.idp_user_id);
            return <tr key={item.ref} tabIndex={0} aria-selected={selected?.ref === item.ref} onClick={() => setParams({ id: item.ref })}
              onKeyDown={event => { if (event.key === "Enter") setParams({ id: item.ref }); }}>
              <td><div className="cred-cell"><Logo id={item.person.provider} size={28} /><div className="cred-text"><div className="cred-name">{person.name}</div>
                <div className="cred-hint">{person.department ?? serviceName(item.person.provider)}</div></div></div></td>
              <td><div className="cred-cell"><Logo id={item.account.provider} size={24} /><span className="cell-wrap">{item.account.label}</span></div></td>
              <td className="col-md">{item.credential ? <>{item.credential.name || typeLabel(item.credential.type, L)}<div className="subtle small">{typeLabel(item.credential.type, L)}</div></>
                : <span className="subtle">{L("계정 전체", "Whole account")}</span>}</td>
              <td><StateChip tone={VERDICT_TONE[item.verdict]}>{words(VERDICTS, item.verdict, L)}</StateChip></td>
              <td className="col-sm">{item.person.departed_at ? <span data-tip={fmtDT(item.person.departed_at, locale)}>{rel(item.person.departed_at, locale)}</span> : "—"}</td>
            </tr>;
          }) : <EmptyRow colSpan={5}>{idps.length ? L("퇴사자가 남긴 Credential이 없습니다.", "No departed person left a credential.") : L("IdP를 연결하면 여기에 보입니다.", "Shown here once an IdP is connected.")}</EmptyRow>}
        </tbody>
      </table></div>
      <div className="list-foot"><span>{L(`${rows.length}건`, `${rows.length}`)}</span>{s.evaluated_at ? <span>{L(`마지막 점검 ${rel(s.evaluated_at, locale)}`, `Last checked ${rel(s.evaluated_at, locale)}`)}</span> : null}</div>
    </Card> : null}

    {tab === "people" ? <Card className="list-card">
      <div className="table-wrap"><table className="tbl">
        <thead><tr><th>{L("사람", "Person")}</th><th className="col-sm">{L("퇴사", "Departed")}</th><th className="col-md">{L("퇴사 시각 근거", "Departure basis")}</th><th>{L("연결된 계정", "Linked accounts")}</th><th>{L("남은 Credential", "Credentials left")}</th></tr></thead>
        <tbody>
          {departed.data?.items.length ? departed.data.items.map(person => {
            const named = nameOf(person.ref, person.idp_user_id);
            const left = Object.values(person.verdicts).reduce((sum, n) => sum + n, 0);
            return <tr key={person.ref} tabIndex={0} onClick={() => setParams({ tab: null, person: person.ref, verdict: null })}
              onKeyDown={event => { if (event.key === "Enter") setParams({ tab: null, person: person.ref, verdict: null }); }}>
              <td><div className="cred-cell"><Logo id={person.provider} size={28} /><div className="cred-text"><div className="cred-name">{named.name}</div>
                <div className="cred-hint">{named.department ?? person.idp_user_id}</div></div></div></td>
              <td className="col-sm">{person.departed_at ? <span data-tip={fmtDT(person.departed_at, locale)}>{rel(person.departed_at, locale)}</span> : "—"}</td>
              <td className="col-md">{words(DEPARTURE, person.departure_basis, L)}</td>
              <td>{person.accounts.length ? <span className="where-cell">{person.accounts.slice(0, 4).map(account => <Logo key={account.ref} id={account.provider} size={22} />)}
                <span className="subtle small">{person.accounts.map(account => account.label).slice(0, 2).join(", ")}{person.accounts.length > 2 ? ` +${person.accounts.length - 2}` : ""}</span></span> : <span className="subtle">—</span>}</td>
              <td>{left ? <>{left}{person.verdicts.USED_AFTER_DEPARTURE ? <span className="tag tone-bad" style={{ marginLeft: 6 }}>{L(`퇴사 후 사용 ${person.verdicts.USED_AFTER_DEPARTURE}`, `${person.verdicts.USED_AFTER_DEPARTURE} used after`)}</span> : null}</> : <span className="subtle">0</span>}</td>
            </tr>;
          }) : <EmptyRow colSpan={5}>{L("퇴사로 확인된 사람이 없습니다.", "Nobody is shown as departed.")}</EmptyRow>}
        </tbody>
      </table></div>
    </Card> : null}

    {tab === "candidates" ? <Card className="list-card" info={L("로그인 이름처럼 약한 근거로만 이어진 계정입니다. 확정하면 판정에 넣고, 거절하면 다시 후보로 올리지 않습니다.", "Accounts tied only by a weak match such as a login. Confirming adds them to the verdicts; a rejected one is not offered again.")}
      title={L("확정할 연결", "Links to confirm")}>
      <div className="table-wrap"><table className="tbl">
        <thead><tr><th>{L("계정", "Account")}</th><th>{L("사람", "Person")}</th><th>{L("근거", "Basis")}</th><th className="rule-acts-h"><span className="sr">{L("결정", "Decision")}</span></th></tr></thead>
        <tbody>
          {candidates.data?.items.length ? candidates.data.items.map(item => <tr key={`${item.account_ref}:${item.person_ref}`}>
            <td><div className="cred-cell"><Logo id={item.account_provider} size={24} /><span className="cell-wrap">{item.account_label}</span></div></td>
            <td>{nameOf(item.person_ref, item.person.idp_user_id).name}<div className="subtle small">{serviceName(item.person.provider)}{item.person.departed_at ? ` · ${L("퇴사", "departed")} ${rel(item.person.departed_at, locale)}` : ""}</div></td>
            <td>{words(LINK, item.basis, L)}</td>
            <td className="rule-acts">{admin ? <>
              <button type="button" className="ghost-btn" disabled={busy} onClick={() => void decide(item, "CONFIRMED")}>{L("같은 사람", "Same person")}</button>
              <button type="button" className="ghost-btn" disabled={busy} onClick={() => void decide(item, "REJECTED")}>{L("다른 사람", "Different person")}</button></> : null}</td>
          </tr>) : <EmptyRow colSpan={4}>{L("확정할 연결이 없습니다.", "No link waits for a decision.")}</EmptyRow>}
        </tbody>
      </table></div>
    </Card> : null}

    {idps.length ? <Card className="list-card" title={L("IdP 연결", "IdP connections")} meta={L(`${idps.length}곳 · 퇴사 후 ${s.retention_days}일 보관`, `${idps.length} · kept ${s.retention_days} days after departure`)}
      right={can("sources") ? <button type="button" className="ghost-btn" onClick={event => chooser.open(event.currentTarget)}><Ic name="plus" size={15} />{L("IdP 연동하기", "Connect an IdP")}</button> : undefined}>
      <div className="table-wrap"><table className="tbl">
        <thead><tr><th>{L("연결", "Connection")}</th><th>{L("상태", "Status")}</th><th className="col-sm">{L("마지막 수집", "Last collected")}</th></tr></thead>
        <tbody>{s.sources.map(source => <tr key={source.connection_id}>
          <td><div className="cred-cell"><Logo id={source.provider} size={26} /><div className="cred-text"><div className="cred-name">{source.name}</div>
            <div className="cred-hint">{source.role === "idp" ? L("재직 상태", "Employment state") : L("계정 신원 연결", "Account identities")}</div></div></div></td>
          <td><StateChip tone={!source.enabled ? undefined : source.latest_run?.status === "COMPLETE" ? "ok" : source.latest_run ? "warn" : "running"}>
            {!source.enabled ? L("꺼짐", "Off") : source.latest_run?.status === "COMPLETE" ? L("정상", "Healthy") : source.latest_run ? L("일부 수집", "Partly collected") : L("첫 수집 전", "Not collected yet")}</StateChip></td>
          <td className="col-sm">{source.latest_run?.finished_at ? <span data-tip={fmtDT(source.latest_run.finished_at, locale)}>{rel(source.latest_run.finished_at, locale)}</span> : "—"}</td>
        </tr>)}</tbody>
      </table></div>
    </Card> : null}

    {selected ? <OrphanDrawer item={selected} name={nameOf(selected.person.ref, selected.person.idp_user_id)} actor={{ id: session.id, role: session.role }}
      onClose={() => setParams({ id: null })} /> : null}
    {chooser.anchor ? <Menu anchor={chooser.anchor} onClose={chooser.close} restore={chooser.opener} label={L("연동할 IdP", "IdP to connect")}>
      {IDPS.map(provider => <MenuItem key={provider} onSelect={() => { chooser.close(); go("sources", { connect: provider }); }}>
        <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}><Logo id={provider} size={20} />{serviceName(provider)}</span></MenuItem>)}
    </Menu> : null}
  </>;

  async function decide(item: Candidate, decision: "CONFIRMED" | "REJECTED") {
    setBusy(true);
    try {
      await send("leavers/links", "POST", { account_ref: item.account_ref, person_ref: item.person_ref, decision });
      toast(decision === "CONFIRMED" ? L("같은 사람으로 확정했습니다. 다음 점검부터 판정에 넣습니다.", "Confirmed as the same person. The next check includes it.")
        : L("다른 사람으로 거절했습니다", "Rejected as a different person"));
      saved();
    } catch (reason) { toast(reasonText(reason, L), "bad"); }
    finally { setBusy(false); }
  }
}

function OrphanDrawer({ item, name, actor, onClose }: { item: Orphan; name: Partial<Person> & { name: string }; actor: Actor; onClose: () => void }) {
  const L = useL();
  const locale = useLocale();
  const credential = item.credential;
  return <Drawer label={L("퇴사자 Credential 상세", "Departed owner's credential")} onClose={onClose}>
    <div className="drawer-head">
      <div className="dh-top">
        <div className="dh-logo"><Logo id={item.account.provider} size={34} /></div>
        <div className="dh-main">
          <div className="md-crumb">{L("퇴사자 Credential", "Departed owners")} › {name.name}</div>
          <h2 className="dh-title">{credential ? credential.name || typeLabel(credential.type, L) : item.account.label}</h2>
          <div className="dh-badges"><StateChip tone={VERDICT_TONE[item.verdict]}>{words(VERDICTS, item.verdict, L)}</StateChip>
            {credential ? <span className="tag">{typeLabel(credential.type, L)}</span> : null}{item.ticket_id ? <span className="tag">{L("티켓 열림", "Ticket open")}</span> : null}</div>
        </div>
        <div className="dh-actions"><button type="button" className="icon-btn" aria-label={L("상세 닫기", "Close details")} data-tip={L("상세 닫기", "Close details")} onClick={onClose}><Ic name="panelClose" size={19} /></button></div>
      </div>
    </div>
    <div className="drawer-body" id="drawer-body">
      <Card level={3} title={L("사람", "Person")}>
        <CardBody><Facts>
          <Fact label={L("이름", "Name")}>{name.name}{name.department ? <div className="subtle small">{name.department}</div> : null}</Fact>
          <Fact label="IdP">{serviceName(item.person.provider)}<div className="subtle small mono">{item.person.idp_user_id}</div></Fact>
          <Fact label={L("퇴사", "Departed")}>{item.person.departed_at ? fmtDT(item.person.departed_at, locale) : "—"}<div className="subtle small">{words(DEPARTURE, item.person.departure_basis, L)}</div></Fact>
          <Fact label={L("IdP 상태", "IdP state")}>{item.person.idp_state}{item.person.idp_disagreement ? <div className="tone-warn small">{L("IdP마다 상태가 다릅니다", "The IdPs disagree")}</div> : null}</Fact>
        </Facts></CardBody>
      </Card>
      <Card level={3} title={L("계정과 Credential", "Account and credential")}>
        <CardBody><Facts>
          <Fact label={L("계정", "Account")}><span className="cell-wrap">{item.account.label}</span><div className="subtle small">{serviceName(item.account.provider)}</div></Fact>
          <Fact label={L("연결 근거", "Link basis")}>{words(LINK, item.account.link_basis, L)}</Fact>
          {credential ? <>
            <Fact label={L("공급자 상태", "Provider state")}>{credential.state}</Fact>
            <Fact label={L("마지막 사용", "Last used")}>{credential.last_used_at ? fmtDT(credential.last_used_at, locale) : <span className="subtle">{L("알려 주지 않음", "Not reported")}</span>}</Fact>
            <Fact label={L("만료", "Expires")}>{credential.expires_at ? fmtDT(credential.expires_at, locale) : <span className="subtle">—</span>}</Fact>
            <Fact label={L("노출", "Exposure")}>{credential.exposed === true ? <span className="tone-bad">{L("노출됨", "Exposed")}</span> : credential.exposed === false ? L("노출 관측 없음", "Not observed") : <span className="subtle">—</span>}</Fact>
          </> : null}
        </Facts>
          {item.reasons.length ? <ul className="md-gaps" style={{ marginTop: 12 }}>{item.reasons.map(code => <li key={code}>{words(REASONS, code, L)}</li>)}</ul> : null}
        </CardBody>
      </Card>
      {item.actionable ? <KeyPlans credentialId={item.ref} name={credential?.name || item.account.label} actor={actor}
        path={`leavers/orphans/${item.ref}/action-plans`} only={["DISABLE_ACCESS_KEY"]} reasons={["OWNER_DEPARTED"]} />
        : <section className="card"><div className="card-body pad-top"><p className="meta">{L("이 Credential은 공급자에서 직접 폐기합니다. 퇴사자 티켓에 확인과 조치 결과를 남깁니다.", "Revoke this credential at the provider, and record the check and the result on the departed-owner ticket.")}</p></div></section>}
    </div>
  </Drawer>;
}
