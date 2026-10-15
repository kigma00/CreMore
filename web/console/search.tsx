"use client";

/* Search from anywhere: credentials by name, hint, type, owner or where they were found; and the
 * integrations, the accounts they reach, catalogued assets and issued objects the server search returns. */

import { useEffect, useMemo, useState } from "react";

import { api } from "@/lib/dashboard-api";
import type { Session } from "@/lib/dashboard-session";
import { useApi } from "@/console/data";
import { Ic } from "@/console/icons";
import { typeLabel } from "@/console/labels";
import { Menu, MenuLabel, useMenu, useSlashKey } from "@/console/layer";
import { Logo, serviceName } from "@/console/logos";
import type { ViewId } from "@/console/nav";
import { RECORDS_PATH, type RecordsResponse } from "@/console/records";
import { useL } from "@/console/text";

type Hit = { kind: string; id: string; label: string; provider?: string; context?: string; detail?: string; connection_id?: string };
type SearchPayload = { groups: { kind: string; permitted: boolean; items: Hit[]; total: number }[] };

export function GlobalSearch({ go, session }: { go: (view: ViewId, params?: Record<string, string | null | undefined>) => void; session: Session }) {
  const L = useL();
  const menu = useMenu();
  const [q, setQ] = useState("");
  const [server, setServer] = useState<SearchPayload | null>(null);
  const records = useApi<RecordsResponse>(menu.anchor ? RECORDS_PATH : null);
  useSlashKey(() => { const button = document.getElementById("global-search-button"); if (button) menu.open(button); });

  useEffect(() => {
    if (!menu.anchor) return;
    const needle = q.trim();
    if (needle.length < 2) { setServer(null); return; }
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      api<SearchPayload>(`search?q=${encodeURIComponent(needle)}&limit=8`, { signal: controller.signal })
        .then(setServer).catch(() => { if (!controller.signal.aborted) setServer(null); });
    }, 250);
    return () => { window.clearTimeout(timer); controller.abort(); };
  }, [q, menu.anchor]);

  const credentials = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (needle.length < 2) return [];
    return (records.data?.items ?? []).filter(c => [c.name, c.hint, typeLabel(c.credential_type, L), c.credential_type, serviceName(c.provider),
      c.owner?.name, c.owner?.team, c.issuer?.name, ...c.exposures.map(e => `${e.resource_name} ${e.location}`), ...c.tags]
      .some(value => value?.toLowerCase().includes(needle))).slice(0, 8);
  }, [q, records.data, L]);

  const groups = (server?.groups ?? []).filter(group => group.permitted && group.items.length && group.kind !== "finding");
  const groupName: Record<string, string> = { connection: L("연동", "Integrations"), aws_account: L("연동 대상 계정", "Integration accounts"),
    asset: L("검사 대상", "Scan targets"), managed_object: L("발급·보관 항목", "Issued and stored objects") };
  const open = (hit: Hit) => {
    menu.close(); setQ("");
    if (hit.kind === "aws_account") go("sources", { account: hit.id });
    else if (hit.kind === "managed_object") go("inventory", { entity: hit.id });
    else if (hit.kind === "asset") go("scans", { connection: hit.connection_id });
    else go("sources");
  };
  const admin = session.role === "Admin";

  return <>
    <button type="button" id="global-search-button" className="icon-btn" aria-label={L("검색", "Search")} data-tip={L("검색 (/)", "Search (/)")}
      onClick={event => menu.open(event.currentTarget)}><Ic name="search" size={19} /></button>
    {menu.anchor ? <Menu anchor={menu.anchor} onClose={menu.close} restore={menu.opener} label={L("검색", "Search")}>
      <label className="menu-search"><Ic name="search" size={15} /><span className="sr">{L("검색어", "Search text")}</span>
        <input value={q} onChange={event => setQ(event.target.value)} placeholder={L("Credential·연동·계정 검색", "Search credentials, integrations, accounts")} />
      </label>
      {q.trim().length < 2 ? <div className="help-box muted">{L("두 글자 이상 입력하세요.", "Type at least two characters.")}</div> : null}
      {credentials.length ? <><MenuLabel>{L("Credential", "Credentials")}</MenuLabel>
        {credentials.map(c => <button type="button" role="menuitem" className="menu-item" key={c.id}
          onClick={() => { menu.close(); setQ(""); go(c.exposed ? "exposed" : "inventory", { id: c.id }); }}>
          <Logo id={c.provider} size={20} />
          <span className="mi-text"><span>{c.name || typeLabel(c.credential_type, L)}</span>
            <span className="person-sub">{[c.hint, c.exposures[0]?.resource_name].filter(Boolean).join(" · ")}</span></span>
        </button>)}</> : null}
      {groups.map(group => <div key={group.kind}>
        <MenuLabel>{groupName[group.kind] ?? group.kind}</MenuLabel>
        {group.items.map(hit => <button type="button" role="menuitem" className="menu-item" key={`${group.kind}:${hit.id}`}
          aria-disabled={(hit.kind === "connection" || hit.kind === "aws_account") && !admin ? true : undefined}
          onClick={() => { if ((hit.kind === "connection" || hit.kind === "aws_account") && !admin) return; open(hit); }}>
          <Logo id={hit.provider} size={20} />
          <span className="mi-text"><span>{hit.label}</span><span className="person-sub">{[hit.context, hit.detail].filter(Boolean).join(" · ")}</span></span>
        </button>)}
      </div>)}
      {q.trim().length >= 2 && !credentials.length && !groups.length ? <div className="help-box muted">{L("찾은 항목이 없습니다.", "Nothing found.")}</div> : null}
    </Menu> : null}
  </>;
}
