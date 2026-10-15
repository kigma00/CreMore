"use client";

/* The bell: what needs attention now. New exposures from the last day, owner replies past their
 * due date, sign-ins about to expire, and connections whose sign-in or collection failed. */

import { useMemo } from "react";

import { useLocale } from "@/components/locale";
import { useApi } from "@/console/data";
import { Ic } from "@/console/icons";
import { typeLabel } from "@/console/labels";
import { Menu, MenuLabel, useMenu } from "@/console/layer";
import type { ViewId } from "@/console/nav";
import { type CredentialRecord, overdue, RECORDS_PATH, type RecordsResponse } from "@/console/records";
import { DAY, rel, time, useL } from "@/console/text";
import { CONNECTIONS_PATH, expiringConnections, type HealthItem, type ProviderConnection } from "@/console/views/integrations/model";

type Health = { items: { key: string; kind: string; name: string; provider: string; auth_state: string; last_status: string; last_failure_at: string | null; freshness: string; expires_at?: string | null }[] };

type Note = { key: string; icon: "alert" | "clock" | "activity" | "hourglass"; title: string; sub: string; open: () => void };

export function Notifications({ go, admin }: { go: (view: ViewId, params?: Record<string, string | null | undefined>) => void; admin: boolean }) {
  const L = useL();
  const locale = useLocale();
  const records = useApi<RecordsResponse>(RECORDS_PATH, { every: 60_000 });
  const health = useApi<Health>("operations/connections", { every: 60_000 });
  const connections = useApi<ProviderConnection[]>(CONNECTIONS_PATH, { every: 60_000 });
  const menu = useMenu();
  const notes = useMemo<Note[]>(() => {
    const now = Date.now(), out: Note[] = [];
    const name = (c: CredentialRecord) => c.name || typeLabel(c.credential_type, L);
    const fresh = (records.data?.items ?? []).filter(c => c.exposed && c.status === "pending" && (time(c.first_seen_at) ?? 0) > now - DAY)
      .sort((a, b) => (time(b.first_seen_at) ?? 0) - (time(a.first_seen_at) ?? 0));
    for (const c of fresh.slice(0, 5)) {
      const place = c.exposures[0];
      out.push({ key: `new:${c.id}`, icon: "alert", title: L(`새 노출 · ${name(c)}`, `New exposure · ${name(c)}`),
        sub: `${place ? `${place.resource_name} · ` : ""}${rel(c.first_seen_at, locale)}`, open: () => go("exposed", { id: c.id }) });
    }
    for (const c of (records.data?.items ?? []).filter(item => overdue(item, now)).slice(0, 5)) {
      const days = Math.max(1, Math.floor((now - (time(`${c.contact!.due_at}T23:59:59`) ?? now)) / DAY));
      out.push({ key: `due:${c.id}`, icon: "clock", title: L(`회신 기한 지남 · ${name(c)}`, `Reply overdue · ${name(c)}`),
        sub: L(`${days}일 지남`, `${days} day${days > 1 ? "s" : ""} overdue`), open: () => go("exposed", { id: c.id, tab: "owner" }) });
    }
    // A sign-in about to expire (the provider's date or the one an admin entered): once per connection, although
    // every record it serves carries the date.
    for (const item of expiringConnections((health.data?.items ?? []) as HealthItem[], connections.data ?? []).slice(0, 5)) {
      const days = Math.max(0, Math.ceil(((time(item.expires_at) ?? now) - now) / DAY));
      out.push({ key: `expiring:${item.key}`, icon: "hourglass", title: L(`인증 만료 ${days}일 전 · ${item.name}`, `Sign-in expires in ${days} day${days === 1 ? "" : "s"} · ${item.name}`),
        sub: L("연동 설정에서 새 자격증명으로 바꾸세요", "Replace the credential in the integration's settings"), open: () => go(admin ? "sources" : "scans") });
    }
    const failing = (health.data?.items ?? []).filter(item => ["REAUTH_REQUIRED", "SECRET_UNAVAILABLE", "PERMISSION_LIMITED"].includes(item.auth_state)
      || item.last_status === "FAILED" || item.freshness === "STALE");
    for (const item of failing.slice(0, 5)) {
      const why = item.auth_state === "REAUTH_REQUIRED" ? L("다시 인증 필요", "Sign-in required")
        : item.auth_state === "SECRET_UNAVAILABLE" ? L("저장된 자격 증명을 읽지 못함", "Stored credential unreadable")
          : item.auth_state === "PERMISSION_LIMITED" ? L("권한 부족", "Missing permission")
            : item.last_status === "FAILED" ? L("수집 실패", "Collection failed") : L("수집이 오래됨", "Collection overdue");
      out.push({ key: `conn:${item.key}`, icon: "activity", title: `${why} · ${item.name}`,
        sub: item.last_failure_at ? rel(item.last_failure_at, locale) : L("연동 상태 확인", "Check the integration"),
        open: () => go(admin ? "sources" : "scans") });
    }
    return out;
  }, [records.data, health.data, connections.data, L, locale, go, admin]);
  const count = notes.length;
  return <>
    <button type="button" className="icon-btn" aria-label={L(`알림 ${count}개`, `${count} notifications`)} data-tip={L("알림", "Notifications")}
      onClick={event => menu.open(event.currentTarget)}>
      <Ic name="bell" size={19} />{count ? <span className="bell-badge">{count > 9 ? "9+" : count}</span> : null}
    </button>
    {menu.anchor ? <Menu anchor={menu.anchor} onClose={menu.close} restore={menu.opener} label={L("알림", "Notifications")}>
      <MenuLabel>{L("알림", "Notifications")}</MenuLabel>
      {notes.length ? notes.map(note => <button type="button" role="menuitem" className="menu-item" key={note.key}
        onClick={() => { menu.close(); note.open(); }}>
        <Ic name={note.icon} size={17} /><span className="mi-text"><span>{note.title}</span><span className="person-sub">{note.sub}</span></span>
      </button>) : <div className="help-box muted">{L("새 알림이 없습니다.", "No new notifications.")}</div>}
    </Menu> : null}
  </>;
}
