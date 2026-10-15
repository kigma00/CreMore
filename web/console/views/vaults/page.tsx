"use client";

/* Secret stores: the vaults CreMore compares with, whether their comparison scope is confirmed, the
 * credentials none of them holds, and the issuance and storage records an administrator submitted.
 * "Not in a vault" is only a verdict once the stores are declared to be all of them and each one's
 * latest listing is complete and current; until then the screen says what still blocks it. */

import { useMemo, useState } from "react";

import { useLocale } from "@/components/locale";
import { reasonText, send, useApi, useSaved } from "@/console/data";
import { Ic } from "@/console/icons";
import { typeLabel } from "@/console/labels";
import { Menu, MenuItem, useMenu, useToast } from "@/console/layer";
import { Logo, serviceName } from "@/console/logos";
import { type CredentialRecord, RECORDS_PATH, type RecordsResponse } from "@/console/records";
import type { ViewProps } from "@/console/shell";
import { fmtDT, rel, type Say, useL } from "@/console/text";
import { Card, cls, EmptyRow, ErrorLine, Loading, PageHead, Tile, Tiles } from "@/console/ui";
import {
  type Catalog, CATALOG_PATH, CONNECTIONS_PATH, type Health, HEALTH_PATH, type HealthItem, label, type ProviderConnection,
} from "@/console/views/integrations/model";
import { Receipts } from "@/console/views/vaults/receipts";
import { type StoreState, storeDetails, StoreModal } from "@/console/views/vaults/store";

type Report = { scope_confirmed: boolean; scope_revision: string; scope_reasons: string[]; absence_basis: string | null; connections: StoreState[] };

// Why "not in a vault" is not a verdict yet, in the reader's words.
const REASONS: Record<string, [string, string]> = {
  VAULT_SCOPE_NOT_CONFIRMED: ["저장소 목록이 전부라고 아직 확정하지 않았습니다", "The store list is not confirmed as complete"],
  NO_VAULT_CONNECTED: ["연결한 저장소가 없습니다", "No secret store is connected"],
  NEVER_COLLECTED: ["아직 한 번도 수집하지 않은 저장소가 있습니다", "A store has never been collected"],
  STALE_OR_RUNNING: ["마지막 수집이 오래됐거나 진행 중인 저장소가 있습니다", "A store's last collection is old or still running"],
  SCOPE_CHANGED: ["저장소 설정이 바뀐 뒤 다시 수집하지 않았습니다", "A store changed and has not been collected since"],
  CONTRACT_CHANGED: ["탐지 룰이 바뀐 뒤 다시 수집하지 않았습니다", "Detection rules changed and a store has not been collected since"],
  CONNECTION_DISABLED: ["꺼 둔 저장소가 있습니다", "A store is turned off"],
  COLLECTION_PARTIAL: ["일부만 수집한 저장소가 있습니다", "A store was collected only in part"],
  COLLECTION_FAILED: ["수집에 실패한 저장소가 있습니다", "A store's collection failed"],
  HISTORICAL_VERSION_SCOPE: ["현재 값이 아닌 과거 버전만 읽는 저장소가 있습니다", "A store reads past versions, not the current value"],
  CURRENT_VERSION_NOT_CONFIRMED: ["현재 버전인지 확인하지 않는 저장소가 있습니다", "A store does not confirm the current version"],
  REPORT_LIMIT_REACHED: ["대조할 수 있는 항목 수를 넘었습니다", "More items than one comparison holds"],
  UNRESOLVED_ITEMS: ["확인하지 못한 항목이 남은 저장소가 있습니다", "A store has items it could not resolve"],
};
export function reasonWords(code: string, L: Say): string {
  const known = REASONS[code];
  if (known) return L(...known);
  return code.split("_").filter(Boolean).map(word => word[0] + word.slice(1).toLowerCase()).join(" ");
}

const BASIS: Record<string, [string, string]> = {
  API_LISTING: ["저장소 API가 목록 전체를 줌", "The store's API listed everything"],
  READER_REPORTED: ["읽기 플러그인이 전체라고 보고함", "A reader plugin reported everything"],
  OPERATOR_DECLARED: ["운영자가 전체라고 선언함", "An operator declared it complete"],
};

/** The vault stores an installation compares with: the owned records of provider connections for the vault purpose. */
export function storesOf(connections: ProviderConnection[], health: HealthItem[]) {
  return connections.filter(c => c.plans.vault).flatMap(c => c.children.filter(child => child.purpose === "vault")
    .map(child => ({ conn: c, child, health: health.find(item => item.key === `${child.kind === "metadata" ? "coverage" : child.kind === "coverage" ? "coverage" : child.kind}:${child.id}`) })));
}

export function Vaults({ session, go, can }: ViewProps) {
  const L = useL();
  const locale = useLocale();
  const toast = useToast();
  const saved = useSaved();
  const admin = session.role === "Admin";
  const records = useApi<RecordsResponse>(RECORDS_PATH, { every: 60_000 });
  const report = useApi<Report>("coverage?limit=1");
  const connections = useApi<ProviderConnection[]>(CONNECTIONS_PATH);
  const health = useApi<Health>(HEALTH_PATH, { every: 60_000 });
  const catalog = useApi<Catalog>(CATALOG_PATH);
  const [busy, setBusy] = useState(false);
  const chooser = useMenu();
  const stores = useMemo(() => storesOf(connections.data ?? [], health.data?.items ?? []), [connections.data, health.data]);
  const [detail, setDetail] = useState<ReturnType<typeof storesOf>[number] | null>(null);
  const [shown, setShown] = useState(50);

  const title = L("Secret 저장소", "Secret stores");
  const meta = L("노출·발급된 값이 저장소에 보관돼 있는지 대조합니다", "Checks whether exposed and issued values are kept in a secret store");
  // A read that fails after one that worked keeps the page (and an open store's details) as it was.
  const failed = (!records.data && records.error) || (!report.data && report.error) || (!connections.data && connections.error);
  if (failed) return <><PageHead title={title} meta={meta} /><ErrorLine onRetry={() => { records.reload(); report.reload(); connections.reload(); }}>{reasonText(failed, L)}</ErrorLine></>;
  if (!records.data || !report.data || !connections.data) return <><PageHead title={title} meta={meta} /><Loading /></>;

  const items = records.data.items;
  const stored = items.filter(c => c.vault.state === "stored");
  const missing = items.filter(c => c.vault.state === "none" && c.status !== "fp");
  // The declaration is the store list confirmed; a verdict needs that and nothing else blocking.
  const confirmed = report.data.scope_reasons.length === 0;
  const blockers = report.data.scope_reasons.filter(code => code !== "VAULT_SCOPE_NOT_CONFIRMED");
  const declared = report.data.scope_confirmed;
  const reasonsOf = new Map(report.data.connections.map(state => [state.id, state]));
  const vaultProviders = (catalog.data?.providers ?? []).filter(d => d.purposes.vault);

  const declare = async (value: boolean) => {
    setBusy(true);
    try {
      await send("coverage/scope", "PUT", { revision: report.data!.scope_revision, confirmed: value });
      toast(value ? L("이 저장소 목록을 대조 범위로 확정했습니다", "This store list is confirmed as the comparison scope")
        : L("대조 범위 확정을 풀었습니다", "The comparison scope is no longer confirmed"));
      saved();
    } catch (reason) { toast(reasonText(reason, L), "bad"); }
    finally { setBusy(false); }
  };
  const collect = async (child: { kind: string; id: string }) => {
    try {
      await send(child.kind === "metadata" ? `v2/coverage/connections/${child.id}/collect` : `coverage/connections/${child.id}/collect`, "POST");
      toast(L("수집을 시작했습니다", "Collection started"));
      saved();
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : "";
      toast(message.startsWith("VAULT_COLLECTION_RUNS_IN_CUSTOMER_ENVIRONMENT") ? L("고객 환경의 CLI가 실행할 때 수집합니다", "Collected when the CLI in your environment runs") : reasonText(reason, L), "bad");
    }
  };

  return <>
    <PageHead title={title} meta={meta} />
    <Tiles>
      <Tile icon="vault" tone="blue" label={L("연결한 저장소", "Connected stores")} value={stores.length}
        tip={L("값을 대조하는 Secret 저장소 수집 연결입니다.", "Secret store collections values are compared with.")} />
      <Tile icon="checkCircle" tone="green" label={L("보관 확인", "Confirmed stored")} value={stored.length} onClick={() => go("inventory", { tab: "vault" })}
        tip={L("같은 값이 저장소에 있다고 지문으로 확인한 Credential입니다.", "Credentials whose value a store holds, confirmed by fingerprint.")} />
      <Tile icon="alert" tone={missing.length ? "amber" : "green"} label={L("저장소에 없음", "Not in a store")} value={confirmed ? missing.length : "—"}
        tip={confirmed ? L("확정한 저장소 어디에도 같은 값이 없는 Credential입니다.", "Credentials none of the confirmed stores holds.")
          : L("저장소 목록을 확정하고 모든 저장소의 수집이 최신이어야 판단합니다.", "Decided once the store list is confirmed and every store's collection is current.")} />
      <Tile icon="shield" tone={confirmed ? "green" : "gray"} label={L("대조 범위", "Comparison scope")} value={confirmed ? L("확정", "Confirmed") : declared ? L("판단 보류", "On hold") : L("확정 필요", "Not confirmed")}
        tip={confirmed ? L("저장소 목록이 전부라고 확정했고 모든 수집이 최신입니다.", "The store list is confirmed and every collection is current.")
          : report.data.scope_reasons.map(code => reasonWords(code, L)).join(" · ")} />
    </Tiles>

    <Card className="list-card" title={L("연결한 저장소", "Connected stores")} meta={L(`${stores.length}곳`, `${stores.length} stores`)}
      right={admin && vaultProviders.length ? <button type="button" className="primary-btn" onClick={event => chooser.open(event.currentTarget)}><Ic name="plus" size={15} />{L("저장소 연동하기", "Connect a store")}</button> : undefined}>
      <div className="table-wrap"><table className="tbl">
        <thead><tr><th>{L("저장소", "Store")}</th><th>{L("상태", "Status")}</th><th className="col-sm">{L("마지막 수집", "Last collected")}</th>
          <th className="col-sm">{L("항목", "Items")}</th><th className="col-md">{L("목록 근거", "Listing basis")}</th><th className="rule-acts-h"><span className="sr">{L("작업", "Actions")}</span></th></tr></thead>
        <tbody>
          {stores.length ? stores.map(({ conn, child, health: item }) => {
            const state = reasonsOf.get(child.id);
            const latest = state?.latest;
            const reasons = state?.reasons ?? [];
            const tone = !item ? "setup" : item.auth_state === "READY" && item.last_status === "COMPLETE" && !reasons.length ? "ok"
              : item.auth_state === "REAUTH_REQUIRED" || item.last_status === "FAILED" ? "partial" : item.last_success_at ? "warn" : "running";
            const word = tone === "ok" ? L("정상", "Healthy") : tone === "partial" ? L("확인 필요", "Needs attention") : tone === "warn" ? L("판단 보류", "On hold") : tone === "running" ? L("첫 수집 전", "Not collected yet") : L("준비 중", "Setting up");
            const when = item?.last_success_at ?? latest?.finished_at ?? null;
            return <tr key={child.id}>
              <td><div className="cred-cell"><Logo id={item?.provider ?? conn.provider} size={30} />
                <div className="cred-text"><div className="cred-name">{item?.name ?? child.name ?? conn.name}</div>
                  <div className="cred-hint">{serviceName(item?.provider ?? conn.provider)} · {conn.name}</div></div></div></td>
              <td><span className={cls("igs", tone)}><span className="dot" />{word}</span>
                {reasons.length ? <div className="ig-note">{reasons.slice(0, 2).map(code => reasonWords(code, L)).join(" · ")}</div> : null}</td>
              <td className="col-sm">{when ? <span data-tip={fmtDT(when, locale)}>{rel(when, locale)}</span> : <span className="subtle">—</span>}</td>
              <td className="col-sm num">{latest ? latest.item_count : "—"}</td>
              <td className="col-md">{latest?.completeness && BASIS[latest.completeness] ? L(...BASIS[latest.completeness]) : <span className="subtle">—</span>}</td>
              <td className="rule-acts">
                {/* A store with details of its own: an AWS Secrets Manager store's rotation, a customer-side store's collector token. */}
                {Object.values(storeDetails(state, conn, admin)).some(Boolean)
                  ? <button type="button" className="icon-btn" aria-label={L("저장소 상세", "Store details")} data-tip={L("저장소 상세", "Store details")}
                    onClick={() => setDetail({ conn, child, health: item })}><Ic name="info" size={17} /></button> : null}
                {admin ? <button type="button" className="icon-btn" aria-label={L("지금 수집", "Collect now")} data-tip={L("지금 수집", "Collect now")} onClick={() => void collect(child)}><Ic name="refresh" size={17} /></button> : null}
                {can("sources") ? <button type="button" className="icon-btn" aria-label={L("연동 설정", "Integration settings")} data-tip={L("연동 설정", "Integration settings")} onClick={() => go("sources", { edit: conn.id })}><Ic name="sliders" size={17} /></button> : null}
              </td>
            </tr>;
          }) : <EmptyRow colSpan={6}>{L("아직 연결한 Secret 저장소가 없습니다. 저장소를 연동하면 노출·발급된 값이 보관돼 있는지 대조합니다.", "No secret store is connected yet. Connect one to check whether exposed and issued values are kept there.")}</EmptyRow>}
        </tbody>
      </table></div>
    </Card>

    <Card className="list-card" title={L("대조 범위", "Comparison scope")} info={L("연결한 저장소가 조직이 비밀을 두는 곳 전부라고 확정해야, 어디에도 없는 값을 '저장소에 없음'으로 판단합니다.", "Only once the connected stores are confirmed to be all the places the organization keeps secrets is a value found nowhere judged 'not in a store'.")}>
      <div className="card-body">
        <div className={cls("ig-result", confirmed ? "ok" : "none")}><Ic name={confirmed ? "checkCircle" : "info"} size={16} />
          <span>{confirmed ? L("저장소 목록을 확정했고 모든 저장소의 수집이 최신입니다. 어디에도 없는 값을 '저장소에 없음'으로 판단합니다.", "The store list is confirmed and every collection is current. A value found nowhere is judged 'not in a store'.")
            : declared ? L("저장소 목록은 확정했지만 아래 이유로 아직 판단하지 않습니다.", "The store list is confirmed, but the reasons below still hold the verdict.")
              : L("저장소 목록을 확정하지 않아 '저장소에 없음'을 판단하지 않습니다.", "The store list is not confirmed, so 'not in a store' is not judged.")}</span></div>
        {blockers.length ? <ul className="md-gaps">{blockers.map(code => <li key={code}>{reasonWords(code, L)}</li>)}</ul> : null}
        {report.data.absence_basis && BASIS[report.data.absence_basis] ? <p className="meta">{L("목록 근거: ", "Listing basis: ")}{L(...BASIS[report.data.absence_basis])}</p> : null}
        {admin ? <div className="md-actions">
          {declared ? <button type="button" className="ghost-btn" disabled={busy} onClick={() => void declare(false)}>{L("확정 풀기", "Undo the confirmation")}</button>
            : <button type="button" className="primary-btn" disabled={busy || !stores.length} onClick={() => void declare(true)}><Ic name="shield" size={15} />{L("이 저장소 목록으로 확정", "Confirm this store list")}</button>}
        </div> : null}
      </div>
    </Card>

    <Card className="list-card" title={L("저장소에 없는 Credential", "Credentials in no store")} meta={confirmed ? L(`${missing.length}건`, `${missing.length}`) : L("대조 범위 확정 뒤 판단", "Judged once the scope is confirmed")}>
      <div className="table-wrap"><table className="tbl">
        <thead><tr><th>Credential</th><th className="col-md">{L("유형", "Type")}</th><th>{L("출처", "Where from")}</th><th className="col-sm">{L("근거", "Basis")}</th></tr></thead>
        <tbody>
          {confirmed && missing.length ? missing.slice(0, shown).map((c: CredentialRecord) => <tr key={c.id} tabIndex={0} onClick={() => go(c.exposed ? "exposed" : "inventory", { id: c.id })}
            onKeyDown={event => { if (event.key === "Enter") go(c.exposed ? "exposed" : "inventory", { id: c.id }); }}>
            <td><div className="cred-cell"><Logo id={c.provider} size={28} /><div className="cred-text"><div className="cred-name">{c.name || typeLabel(c.credential_type, L)}</div>
              <div className="cred-hint mono">{c.hint ?? c.issued?.object_id ?? ""}</div></div></div></td>
            <td className="col-md">{typeLabel(c.credential_type, L)}</td>
            <td>{c.exposed ? <span className="tag">{L("노출", "Exposed")}</span> : null} {c.issued ? <span className="tag">{L("발급 목록", "Inventory")}</span> : null}</td>
            <td className="col-sm">{c.vault.absence_basis && BASIS[c.vault.absence_basis] ? L(...BASIS[c.vault.absence_basis]) : "—"}</td>
          </tr>) : <EmptyRow colSpan={4}>{confirmed ? L("확정한 저장소에 모두 보관돼 있습니다.", "The confirmed stores hold every value.") : L("대조 범위를 확정하면 여기에 보입니다.", "Shown here once the comparison scope is confirmed.")}</EmptyRow>}
        </tbody>
      </table></div>
      {confirmed && missing.length > shown ? <div className="list-foot"><span>{L(`${missing.length}건 중 ${shown}건`, `${shown} of ${missing.length}`)}</span>
        <button type="button" className="link-btn" onClick={() => setShown(value => value + 50)}>{L("50건 더 보기", "Show 50 more")}</button></div> : null}
    </Card>

    <Receipts admin={admin} />
    {detail ? <StoreModal conn={detail.conn} child={detail.child} state={reasonsOf.get(detail.child.id)} admin={admin} onClose={() => setDetail(null)} /> : null}

    {chooser.anchor ? <Menu anchor={chooser.anchor} onClose={chooser.close} restore={chooser.opener} label={L("연동할 저장소", "Store to connect")}>
      {vaultProviders.map(d => <MenuItem key={d.provider} onSelect={() => { chooser.close(); go("sources", { connect: d.provider }); }}>
        <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}><Logo id={d.provider} size={20} />{label(d, L)}</span></MenuItem>)}
    </Menu> : null}
  </>;
}
