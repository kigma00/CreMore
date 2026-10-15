"use client";

/* One secret store's details, opened from its row on the Secret stores screen: for an AWS Secrets Manager store the
 * server collects, which of its account's secrets rotate (the Secrets Manager inventory, when the installation keeps it
 * on); for a store a customer-side CLI collects, the collector token it uploads with (re-issued here, shown once). */

import { useEffect, useRef, useState } from "react";

import { isConflict, reasonText, send, useApi, useSaved } from "@/console/data";
import { Ic } from "@/console/icons";
import { Modal, useToast } from "@/console/layer";
import { Logo, serviceName } from "@/console/logos";
import { type Say, useL } from "@/console/text";
import { Banner, ErrorLine, Loading, StateChip } from "@/console/ui";
import { CUSTOMER_SIDE } from "@/console/views/integrations/copy";
import type { Child, ProviderConnection } from "@/console/views/integrations/model";
import { api, DashboardAPIError } from "@/lib/dashboard-api";

/** A store's own collection as the comparison report lists it (cremore/coverage/correlation.py public_connection). */
export type StoreState = {
  id: string; revision: number; enabled: boolean; reasons: string[];
  spec: { name: string; provider: string; account_id?: string; regions?: string[]; server_collection?: boolean };
  latest: { status: string; finished_at: string | null; item_count: number; completeness: string | null } | null;
};
/** The Secrets Manager inventory of one account, in the installation's region (cremore/api/routes/secrets.py). */
export type SecretsInventory = {
  region: string; collection_status: string; total: number; without_rotation: number;
  secrets: { arn: string; name: string; rotation_enabled: boolean }[];
};

/** What a store's details hold: an AWS Secrets Manager store the server collects has its account's rotation (a
 * customer-side one registers no account); a store a customer-side CLI collects has its token, which an Admin re-issues. */
export function storeDetails(state: StoreState | undefined, conn: ProviderConnection, admin: boolean): { rotation: boolean; token: boolean } {
  return {
    rotation: state?.spec.provider === "aws_secrets_manager" && Boolean(state.spec.account_id) && Boolean(state.spec.server_collection),
    token: admin && CUSTOMER_SIDE.has(conn.auth_method),
  };
}

/** Where a store's collector token is re-issued: a schema 2 collection's own record, or a schema 1 store's. */
export function tokenPath(child: Child): string {
  return child.kind === "metadata" ? `v2/coverage/connections/${child.id}` : `coverage/connections/${child.id}`;
}

/** What the inventory says, in a few words; null where it has nothing to say beyond its rows. */
export function inventoryText(inv: SecretsInventory, L: Say): string | null {
  if (inv.collection_status === "NOT_CONFIGURED") return L("관리자가 AWS 연동 설정의 '발견한 Credential 조사 기능'에서 Secrets Manager 인벤토리를 켜면 보입니다.",
    "Shown once an Admin turns the Secrets Manager inventory on, under 'Investigations of discovered credentials' in an AWS integration's settings.");
  if (inv.collection_status === "FAILED") return L("이 계정의 Secrets Manager 목록을 읽지 못했습니다.", "This account's Secrets Manager list could not be read.");
  if (inv.collection_status !== "COMPLETE") return L(`목록을 다 읽지 못했습니다 (${inv.collection_status}).`, `The list was not read in full (${inv.collection_status}).`);
  return null;
}

/** Why the inventory could not be read, in words; the store's own account is what CreMore could not open. */
export function inventoryError(error: unknown, L: Say): string {
  const code = error instanceof DashboardAPIError ? error.message.split(":", 1)[0].trim() : "";
  return code === "ACCOUNT_NOT_CONNECTED" ? L("이 저장소의 AWS 계정이 AWS 연동에 없습니다.", "This store's AWS account is not in an AWS integration.") : reasonText(error, L);
}

function Rotation({ accountId, regions }: { accountId: string; regions: string[] }) {
  const L = useL();
  const view = useApi<SecretsInventory>(`secret-managers/aws/inventory?account_id=${encodeURIComponent(accountId)}`, { every: 0 });
  const [shown, setShown] = useState(50);
  if (view.error) return <ErrorLine onRetry={view.reload}>{inventoryError(view.error, L)}</ErrorLine>;
  if (!view.data) return <Loading />;
  const inv = view.data;
  const note = inventoryText(inv, L);
  if (note) return <p className="ig-sub">{note}</p>;
  // The inventory reads the installation's region only: a store in other regions is not what it lists.
  if (regions.length && !regions.includes(inv.region)) return <p className="ig-sub">{L(`Secrets Manager 인벤토리는 이 설치의 리전(${inv.region})을 읽습니다. 이 저장소의 리전(${regions.join(", ")})은 읽지 않습니다.`,
    `The Secrets Manager inventory reads the installation's region (${inv.region}), not this store's (${regions.join(", ")}).`)}</p>;
  return <>
    <p className="ig-sub">{L(`${inv.region} · Secret ${inv.total}개 중 로테이션이 꺼진 ${inv.without_rotation}개`, `${inv.region} · ${inv.without_rotation} of ${inv.total} secrets without rotation`)}</p>
    {inv.secrets.length ? <div className="sub-scroll"><table className="sub-tbl">
      <thead><tr><th>Secret</th><th>{L("로테이션", "Rotation")}</th></tr></thead>
      <tbody>{inv.secrets.slice(0, shown).map(secret => <tr key={secret.arn}>
        <td data-label="Secret"><span className="mono cell-wrap" title={secret.arn}>{secret.name}</span></td>
        <td data-label={L("로테이션", "Rotation")}><StateChip tone={secret.rotation_enabled ? "ok" : "partial"}>{secret.rotation_enabled ? L("켜짐", "On") : L("꺼짐", "Off")}</StateChip></td>
      </tr>)}</tbody>
    </table></div> : null}
    {inv.secrets.length > shown ? <div className="aws-set-acts"><span className="ig-sub">{L(`${inv.secrets.length}개 중 ${shown}개`, `${shown} of ${inv.secrets.length}`)}</span>
      <button type="button" className="link-btn" onClick={() => setShown(value => value + 50)}>{L("50개 더 보기", "Show 50 more")}</button></div> : null}
  </>;
}

/** The token a customer-side CLI uploads this store's collection with: re-issued here, shown only while the details
 * stay open (the details then do not close on Escape or a click outside). */
function CollectorToken({ child, state, token, busy, onBusy, onIssued }: {
  child: Child; state: StoreState | undefined; token: string | null; busy: boolean; onBusy: (busy: boolean) => void; onIssued: (token: string | null) => void;
}) {
  const L = useL();
  const toast = useToast();
  const saved = useSaved();
  const [confirming, setConfirming] = useState(false);
  // The question takes focus (Cancel) and hands it back to the re-issue button when it is answered without a token.
  const reissueButton = useRef<HTMLButtonElement>(null);
  const asked = useRef(false);
  useEffect(() => {
    if (asked.current && !confirming && !token) reissueButton.current?.focus();
    asked.current = confirming;
  }, [confirming, token]);
  const reissue = async () => {
    onBusy(true);
    try {
      // A schema 2 collection's revision is read from its own record; a schema 1 store's comes with the comparison
      // report, or else with the integration's list.
      const path = tokenPath(child);
      const revision = child.kind === "metadata" ? (await api<{ revision: number }>(path)).revision : state?.revision ?? child.revision;
      const result = await send<{ collector_token: string | null }>(path, "PATCH", { revision, rotate_token: true });
      onIssued(result.collector_token);
      saved();
    } catch (reason) {
      toast(reasonText(reason, L), "bad");
      // A store changed since it was read: read it again, so the next try carries its revision.
      if (isConflict(reason)) saved();
    } finally { onBusy(false); setConfirming(false); }
  };
  const copy = () => navigator.clipboard ? navigator.clipboard.writeText(token ?? "").then(() => toast(L("토큰을 복사했습니다", "Copied the token")), () => toast(L("복사하지 못했습니다", "Could not copy"), "bad"))
    : toast(L("이 브라우저에서는 복사할 수 없습니다", "This browser cannot copy"), "bad");
  return <div className="ig-section">
    <div className="ig-section-head"><h3>{L("수집기 토큰", "Collector token")}</h3></div>
    <p className="ig-sub">{L("고객 환경의 CLI가 이 토큰으로 수집 결과를 올립니다. 다시 발급하면 이전 토큰은 바로 쓸 수 없습니다.",
      "The CLI in your environment uploads this store's collection with this token. Re-issuing it ends the previous one at once.")}</p>
    {token ? <>
      <Banner tone="warn" icon="alert">{L("토큰은 지금 한 번만 보여 줍니다. 복사해 CLI 설정에 넣으세요.", "The token is shown only now. Copy it into the CLI's settings.")}</Banner>
      <div className="ig-token">
        <code className="mono">{token}</code>
        <button type="button" className="ghost-btn" autoFocus onClick={() => void copy()}><Ic name="copy" size={15} />{L("복사", "Copy")}</button>
      </div>
    </> : <>
      <div role="status">{confirming ? <Banner tone="warn" icon="alert">{L("다시 발급하면 대조 범위를 다시 확정해야 하고, CLI가 새 토큰으로 수집하기 전까지 이 저장소로는 '저장소에 없음'을 판단하지 않습니다.",
        "Re-issuing asks for the comparison scope to be confirmed again, and this store decides no 'not in a store' until the CLI collects with the new token.")}</Banner> : null}</div>
      {confirming ? <div className="aws-set-acts">
        <button type="button" className="primary-btn" disabled={busy} onClick={() => void reissue()}>{L("이전 토큰을 끊고 새로 발급", "End the previous token and issue a new one")}</button>
        <button type="button" className="ghost-btn" disabled={busy} autoFocus onClick={() => setConfirming(false)}>{L("취소", "Cancel")}</button>
      </div> : <div className="aws-set-acts">
        <button type="button" className="ghost-btn" ref={reissueButton} onClick={() => setConfirming(true)}><Ic name="refresh" size={15} />{L("토큰 다시 발급", "Re-issue the token")}</button>
      </div>}
    </>}
  </div>;
}

export function StoreModal({ conn, child, state, admin, onClose }: {
  conn: ProviderConnection; child: Child; state: StoreState | undefined; admin: boolean; onClose: () => void;
}) {
  const L = useL();
  // The token lives here: the details keep it while open and drop it when closed, and stay open while it is asked for
  // (the previous one ends with the request).
  const [token, setToken] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const provider = state?.spec.provider ?? child.provider ?? conn.provider;
  const title = state?.spec.name ?? child.name ?? conn.name;
  const has = storeDetails(state, conn, admin);
  return <Modal onClose={onClose} labelledBy="store-title" className="integ" dismissable={!token && !busy}>
    <h2 id="store-title"><Logo id={provider} size={26} />{title} <small>{[serviceName(provider), conn.name !== title ? conn.name : null].filter(Boolean).join(" · ")}</small></h2>
    {has.rotation && state?.spec.account_id ? <div className="ig-section">
      <div className="ig-section-head"><h3>{L("로테이션", "Rotation")}</h3></div>
      <Rotation accountId={state.spec.account_id} regions={state.spec.regions ?? []} />
    </div> : null}
    {has.token ? <CollectorToken child={child} state={state} token={token} busy={busy} onBusy={setBusy} onIssued={setToken} /> : null}
    <div className="modal-foot"><button type="button" className="ghost-btn" disabled={busy} onClick={onClose}>{L("닫기", "Close")}</button></div>
  </Modal>;
}
