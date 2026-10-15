"use client";

/* The company's domains (cremore/domains.py), in the design's integration window: add a domain, publish the TXT
 * record CreMore shows, and CreMore asks the DNS of the network it runs in. A verified domain is asked again every
 * day; a record that is gone lapses it, with a new value to publish. The external exposure scan (website/) reads
 * only verified domains (their subdomains included) and is set up from here. */

import { useState } from "react";

import { useLocale } from "@/components/locale";
import { reasonText, send, useApi } from "@/console/data";
import { Ic } from "@/console/icons";
import { Modal, useToast } from "@/console/layer";
import { rel, type Say, useL } from "@/console/text";
import { Banner, Loading, StateChip, Switch, TextField } from "@/console/ui";

export const DOMAINS_PATH = "settings/domains";
/** What any analyst may read: which domains are verified. */
export const DOMAIN_STATUS_PATH = "domains";

export type DomainStatus = "PENDING" | "VERIFIED" | "LAPSED";
export type DomainResult = "VERIFIED" | "TXT_NOT_FOUND" | "TXT_MISMATCH" | "DNS_UNAVAILABLE";
export type Domain = {
  name: string; status: DomainStatus; allow_internal: boolean; verified_at: string | null; checked_at: string | null;
  result: DomainResult | null; added_at?: string; added_by?: string;
  /** The record to publish: an admin's view only. */
  record?: { name: string; type: "TXT"; value: string };
};
export type DomainList = { domains: Domain[]; limit: number };

export const STATUS_WORDS: Record<DomainStatus, [string, string]> = {
  PENDING: ["확인 대기", "Awaiting verification"], VERIFIED: ["확인됨", "Verified"], LAPSED: ["확인 만료", "Lapsed"],
};
const STATUS_TONE: Record<DomainStatus, "ok" | "warn" | "partial"> = { PENDING: "warn", VERIFIED: "ok", LAPSED: "partial" };
export const RESULT_WORDS: Record<DomainResult, [string, string]> = {
  VERIFIED: ["레코드가 맞습니다", "The record matches"],
  TXT_NOT_FOUND: ["레코드가 없습니다", "No record found"],
  TXT_MISMATCH: ["레코드에 다른 값이 있습니다", "The record holds another value"],
  DNS_UNAVAILABLE: ["DNS가 응답하지 않았습니다", "The DNS did not answer"],
};

/** The Other settings line: how many domains are verified, or what waits. */
export function domainState(list: DomainList | undefined, L: Say): string {
  const domains = list?.domains ?? [];
  const verified = domains.filter(item => item.status === "VERIFIED").length;
  if (verified) return L(`${verified}개 확인됨`, `${verified} verified`);
  const waiting = domains.length;
  return waiting ? L(`확인 대기 ${waiting}`, `${waiting} awaiting`) : L("설정 안 됨", "Not set up");
}

type Busy = "" | "add" | `${"verify" | "renew" | "remove" | "internal"}:${string}`;

/** ``scans``: the website integrations; ``scanned``: the domains they read; ``onConnect`` starts a new one with the
 * verified domains none of them reads. */
export function DomainsModal({ onClose, onConnect, scans = 0, scanned = new Set<string>() }: {
  onClose: () => void; onConnect?: (fresh: string[]) => void; scans?: number; scanned?: ReadonlySet<string>;
}) {
  const L = useL();
  const locale = useLocale();
  const toast = useToast();
  const view = useApi<DomainList>(DOMAINS_PATH);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState<Busy>("");
  const [armed, setArmed] = useState("");  // "renew:<name>" or "remove:<name>": a second press does it
  const [error, setError] = useState<string | null>(null);
  const copy = (text: string) => navigator.clipboard?.writeText(text).then(() => toast(L("복사했습니다", "Copied")), () => toast(L("복사하지 못했습니다", "Could not copy"), "bad"));

  const head = <h2 id="dm-title"><span className="ig-cm"><Ic name="globe" size={18} /></span>{L("도메인 검증", "Domain verification")} <small>{L("외부 노출 검사", "External exposure scan")}</small></h2>;
  if (!view.data) {
    return <Modal onClose={onClose} labelledBy="dm-title" className="integ mi">
      {head}{view.error ? <Banner tone="bad" icon="alert">{reasonText(view.error, L)}</Banner> : <Loading />}
      <div className="modal-foot"><button type="button" className="ghost-btn" onClick={onClose}>{L("닫기", "Close")}</button></div>
    </Modal>;
  }
  const data = view.data;
  const verified = data.domains.filter(domain => domain.status === "VERIFIED").map(domain => domain.name);
  const fresh = verified.filter(domain => !scanned.has(domain));

  async function act(key: Busy, run: () => Promise<unknown>, done: string) {
    setBusy(key); setError(null); setArmed("");
    try { await run(); view.reload(); toast(done); } catch (reason) { setError(reasonText(reason, L)); }
    finally { setBusy(""); }
  }
  const path = (domain: string, rest = "") => `${DOMAINS_PATH}/${encodeURIComponent(domain)}${rest}`;
  const add = () => act("add", async () => { await send<Domain>(DOMAINS_PATH, "POST", { name: name.trim() }); setName(""); },
    L("도메인을 추가했습니다. 아래 TXT 레코드를 DNS에 등록한 뒤 확인하세요.", "Domain added. Publish the TXT record below, then verify."));
  const verify = async (domain: Domain) => {
    setBusy(`verify:${domain.name}`); setError(null); setArmed("");
    try {
      const next = await send<Domain>(path(domain.name, "/verify"), "POST");
      view.reload();
      if (next.status === "VERIFIED") toast(L(`${domain.name} 소유를 확인했습니다.`, `${domain.name} is verified.`));
      else setError(`${domain.name} · ${L(...RESULT_WORDS[next.result ?? "TXT_NOT_FOUND"])}`);
    } catch (reason) { setError(reasonText(reason, L)); }
    finally { setBusy(""); }
  };

  return <Modal onClose={onClose} labelledBy="dm-title" className="integ mi" dismissable={!busy}>
    {head}
    <p className="ig-sub mi-intro">{L("외부 노출 검사 대상 도메인을 소유했는지 DNS TXT 레코드로 확인합니다. CreMore가 설치된 망의 DNS에 묻기 때문에 사내 전용 도메인도 확인할 수 있습니다. 확인된 도메인은 매일 다시 확인하며, 레코드가 사라지면 확인이 끊기고 새 값을 게시해야 다시 확인됩니다.",
      "Confirms you own the domains for external exposure checks, by a DNS TXT record. CreMore asks the DNS of the network it runs in, so an intranet-only domain can be verified too. A verified domain is asked again every day; when its record is gone, verification lapses and a new value must be published.")}</p>
    {error ? <Banner tone="bad" icon="alert" onClose={() => setError(null)}>{error}</Banner> : null}

    <div className="ig-section">
      <div className="ig-section-head"><h3>{L("도메인 추가", "Add a domain")}</h3></div>
      <div className="dm-add">
        <TextField label={L("도메인", "Domain")} value={name} onChange={setName} placeholder="example.com" maxLength={234} />
        <button type="button" className="primary-btn" disabled={Boolean(busy) || !name.trim() || data.domains.length >= data.limit} onClick={() => void add()}>
          <Ic name="plus" size={15} />{busy === "add" ? L("추가 중", "Adding") : L("추가", "Add")}</button>
      </div>
    </div>

    <div className="ig-section">
      <div className="ig-section-head"><h3>{L("도메인", "Domains")}</h3><span className="ig-sub">{`${data.domains.length}/${data.limit}`}</span></div>
      {data.domains.length ? <ul className="dm-list">{data.domains.map(domain => {
        const acting = busy.endsWith(`:${domain.name}`);
        return <li key={domain.name} className="dm-row">
          <div className="dm-head">
            <span className="mono dm-name">{domain.name}</span>
            <StateChip tone={STATUS_TONE[domain.status]}>{L(...STATUS_WORDS[domain.status])}</StateChip>
            <span className="ig-sub dm-when">{domain.checked_at
              ? `${L("마지막 확인", "Last asked")} ${rel(domain.checked_at, locale)}${domain.result && domain.result !== "VERIFIED" ? ` · ${L(...RESULT_WORDS[domain.result])}` : ""}`
              : L("아직 확인하지 않았습니다", "Not asked yet")}</span>
          </div>
          {domain.status === "LAPSED" ? <p className="ig-sub">{L("확인이 끊겨 새 값을 만들었습니다. 아래 레코드로 바꾼 뒤 확인하세요.",
            "Verification lapsed, so a new value was made. Publish the record below, then verify.")}</p> : null}
          {domain.record ? <div className="dm-record">
            <span className="dm-label">{L("이름", "Name")}</span><code className="mono">{domain.record.name}</code>
            <button type="button" className="icon-btn" aria-label={L("이름 복사", "Copy the name")} onClick={() => void copy(domain.record!.name)}><Ic name="copy" size={14} /></button>
            <span className="dm-label">{L("값", "Value")} · TXT</span><code className="mono">{domain.record.value}</code>
            <button type="button" className="icon-btn" aria-label={L("값 복사", "Copy the value")} onClick={() => void copy(domain.record!.value)}><Ic name="copy" size={14} /></button>
          </div> : null}
          <div className="dm-acts">
            <Switch checked={domain.allow_internal} disabled={acting} label={L("사내 주소 허용", "Allow internal addresses")}
              tip={L("외부 노출 검사가 이 도메인의 사설 IP 사이트도 요청하도록 허용합니다. 루프백·링크 로컬·메타데이터 주소는 제외하며, 확인이 끊기면 꺼집니다.",
                "Lets the external exposure scan reach this domain's sites on private addresses. Loopback, link-local and metadata addresses stay excluded; it turns off when verification lapses.")}
              onChange={value => void act(`internal:${domain.name}`, () => send(path(domain.name, "/internal"), "PUT", { allow_internal: value }),
                value ? L("사내 주소를 허용했습니다.", "Internal addresses allowed.") : L("사내 주소 허용을 껐습니다.", "Internal addresses no longer allowed."))} />
            <span className="dm-switch-label">{L("사내 주소 허용", "Allow internal addresses")}</span>
            <span className="dm-gap" />
            <button type="button" className="ghost-btn" disabled={Boolean(busy)} onClick={() => void verify(domain)}>
              <Ic name="refresh" size={15} />{busy === `verify:${domain.name}` ? L("확인 중", "Asking") : L("지금 확인", "Verify now")}</button>
            <button type="button" className={armed === `renew:${domain.name}` ? "danger-btn" : "ghost-btn"} disabled={Boolean(busy)}
              onClick={() => armed === `renew:${domain.name}`
                ? void act(`renew:${domain.name}`, () => send(path(domain.name, "/challenge"), "POST"), L("새 값을 만들었습니다. DNS 레코드를 바꾼 뒤 다시 확인하세요.", "New value made. Update the DNS record, then verify again."))
                : setArmed(`renew:${domain.name}`)}>
              {armed === `renew:${domain.name}` ? L("새 값 만들기 · 다시 확인 필요", "Make a new value · verify again") : L("값 재발급", "New value")}</button>
            <button type="button" className={armed === `remove:${domain.name}` ? "danger-btn" : "ghost-btn"} disabled={Boolean(busy)}
              onClick={() => armed === `remove:${domain.name}`
                ? void act(`remove:${domain.name}`, () => send(path(domain.name), "DELETE"), L(`${domain.name}을(를) 뺐습니다.`, `${domain.name} removed.`))
                : setArmed(`remove:${domain.name}`)}>
              {armed === `remove:${domain.name}` ? L("한 번 더 눌러 삭제", "Press again to remove") : L("삭제", "Remove")}</button>
          </div>
        </li>;
      })}</ul> : <p className="ig-sub">{L("추가한 도메인이 없습니다.", "No domain added yet.")}</p>}
    </div>

    {onConnect ? <div className="ig-section">
      <div className="ig-section-head"><h3>{L("외부 노출 검사", "External exposure scan")}</h3>
        {scans ? <span className="ig-sub">{L(`연동 ${scans}개 · 연동 현황에서 관리`, `${scans} integration${scans === 1 ? "" : "s"} · managed in Connected services`)}</span> : null}</div>
      <div className="dm-add">
        <p className="ig-sub">{L("확인된 도메인의 시작 페이지, 페이지가 불러오는 스크립트, 스크립트 소스맵의 원본 소스를 검사합니다.",
          "Scans the start pages of verified domains, the scripts they load and the original sources in the scripts' maps.")}</p>
        <button type="button" className="primary-btn" disabled={Boolean(busy) || !fresh.length} data-tip={fresh.length ? undefined
          : verified.length ? L("확인된 도메인마다 검사 연동이 있습니다. 시작 페이지는 연동 현황에서 바꿉니다.", "Every verified domain has a scan; change its start pages in Connected services.")
            : L("먼저 도메인을 확인하세요.", "Verify a domain first.")}
          onClick={() => onConnect(fresh)}><Ic name="scan" size={15} />{L("검사 연동하기", "Set up the scan")}</button>
      </div>
    </div> : null}

    <div className="modal-foot">
      <button type="button" className="ghost-btn" style={{ marginLeft: "auto" }} onClick={onClose} disabled={Boolean(busy)}>{L("닫기", "Close")}</button>
    </div>
  </Modal>;
}
