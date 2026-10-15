"use client";

import { useCallback, useContext, useEffect, useId, useRef, useState } from "react";

import { useLocale } from "@/components/locale";
import { api, DashboardAPIError } from "@/lib/dashboard-api";
import { ChangesContext, reasonText } from "@/console/data";
import { Ic } from "@/console/icons";
import { Menu, useMenu } from "@/console/layer";
import { type DirectoryPage, type DirectoryPerson, peoplePath, selectablePerson } from "@/console/people";
import { DirectoryStatus, directoryCollecting, directoryText } from "@/console/people-directory";
import { fmtDT, useL } from "@/console/text";
import { Field } from "@/console/ui";

const REASONS: Record<string, [string, string]> = {
  INACTIVE: ["비활성 계정", "Inactive account"], NO_CONTACT: ["이메일 없음", "No email"], AMBIGUOUS_EMAIL: ["이메일 중복 확인 필요", "Duplicate email needs review"],
  STALE: ["오래된 관측", "Stale observation"], PARTIAL: ["부분 수집", "Partial collection"], NOT_SYNCED: ["미수집", "Not collected"], UNAVAILABLE: ["상태 미확인", "Availability unknown"],
};
/** One server-side result page at a time. Query edits revoke selection and abort older reads. */
export function PersonPicker({ label, value, onChange, disabled = false, admin = false }: {
  label: string; value: DirectoryPerson | null; onChange: (person: DirectoryPerson | null) => void; disabled?: boolean; admin?: boolean;
}) {
  const L = useL(), locale = useLocale(), id = useId(), menu = useMenu();
  const { authLost } = useContext(ChangesContext);
  const [query, setQuery] = useState(""), [cursor, setCursor] = useState<string | null>(null);
  const [page, setPage] = useState<DirectoryPage>(), [rows, setRows] = useState<DirectoryPerson[]>([]);
  const [loading, setLoading] = useState(false), [error, setError] = useState<unknown>(), [retry, setRetry] = useState(0);
  const generation = useRef(0), request = useRef<AbortController | null>(null), change = useRef(onChange);
  change.current = onChange;
  const opened = !!menu.anchor;
  useEffect(() => {
    if (!opened) return;
    const current = ++generation.current;
    const controller = new AbortController(); request.current = controller;
    setLoading(true); setError(undefined);
    const timer = window.setTimeout(() => {
      api<DirectoryPage>(peoplePath(query, cursor), { signal: controller.signal }).then(next => {
        if (controller.signal.aborted || current !== generation.current) return;
        setPage(next);
        setRows(old => cursor ? [...new Map([...old, ...next.items].map(person => [person.person_ref, person])).values()] : next.items);
        if (!next.directory?.usable) change.current(null);
      }).catch(reason => {
        if (controller.signal.aborted || current !== generation.current) return;
        setError(reason); setPage(undefined); setRows([]); change.current(null);
        if (reason instanceof DashboardAPIError && reason.status === 401) authLost(reason);
      }).finally(() => { if (!controller.signal.aborted && current === generation.current) setLoading(false); });
    }, query && !cursor ? 250 : 0);
    return () => { window.clearTimeout(timer); controller.abort(); };
  }, [opened, query, cursor, retry, authLost]);
  const search = (text: string) => {
    request.current?.abort(); generation.current++;
    setQuery(text); setCursor(null); setRows([]); setPage(undefined); setError(undefined); setLoading(true); onChange(null);
  };
  const reload = useCallback((clearSelection = true) => {
    request.current?.abort(); generation.current++;
    setCursor(null); setRows([]); setLoading(true); setRetry(tick => tick + 1);
    if (clearSelection) change.current(null);
  }, []);
  useEffect(() => {
    if (!opened || !directoryCollecting(page?.directory)) return;
    const timer = window.setTimeout(() => reload(false), 10_000);
    return () => window.clearTimeout(timer);
  }, [opened, page, reload]);
  const listId = `${id}-list`, expired = error instanceof DashboardAPIError && error.message === "DIRECTORY_CURSOR_EXPIRED";
  return <Field label={label} htmlFor={id}>
    <button id={id} type="button" role="combobox" aria-haspopup="listbox" aria-expanded={opened} aria-controls={opened ? listId : undefined}
      className="multi-select" disabled={disabled} onClick={event => { if (!opened) { setQuery(""); setCursor(null); setRows([]); setPage(undefined); } menu.open(event.currentTarget); }}>
      <span className="cell-wrap">{value ? `${value.name} · ${value.email ?? ""}` : L("로그인 IdP에서 담당자 검색", "Search the sign-in IdP for a responder")}</span><Ic name="down" size={16} />
    </button>
    {value ? <span className="meta cell-wrap">{[value.department, value.title].filter(Boolean).join(" · ")}</span> : null}
    {page?.directory ? <span className={`meta ${page.directory.usable ? "" : "tone-warn"}`}>{directoryText(page.directory, L)}
      {page.directory.observed_at ? ` · ${fmtDT(page.directory.observed_at, locale)}` : ""}</span> : null}
    {opened ? <Menu anchor={menu.anchor!} onClose={menu.close} restore={menu.opener} label={label}>
      <div className="menu-search"><Ic name="search" size={15} /><input aria-label={L("IdP 사람 검색", "Search IdP people")} value={query}
        placeholder={L("이름·이메일·부서", "Name, email or department")} maxLength={200} autoComplete="off" onChange={event => search(event.target.value)} /></div>
      <div className="menu-label" role="status">{loading ? L("검색 중…", "Searching…") : page ? L(`${page.total}명 중 ${rows.length}명 표시`, `${rows.length} of ${page.total} people shown`) : ""}</div>
      {error ? <div className="menu-label tone-warn">{expired ? L("검색 중 디렉터리가 갱신됐습니다. 처음부터 다시 검색하세요.", "The directory changed during this search. Restart the search.") : reasonText(error, L)}
        <button type="button" className="link-btn" onClick={() => { setCursor(null); setRows([]); setRetry(tick => tick + 1); }}>{L("다시 검색", "Search again")}</button></div> : null}
      {page?.directory ? <div className="menu-label"><DirectoryStatus directory={page.directory} onReload={reload} admin={admin} disabled={disabled || loading} /></div> : null}
      <div id={listId} role="listbox" aria-label={label} style={{ maxHeight: 280, overflowY: "auto" }}>
        {rows.map(person => {
          const available = !!page?.directory?.usable && selectablePerson(person);
          return <button key={person.person_ref} type="button" role="option" aria-selected={value?.person_ref === person.person_ref}
            aria-disabled={!available || undefined} className="menu-item" onClick={() => { if (available && !loading) { onChange(person); menu.close(); menu.opener.current?.focus(); } }}>
            <span className="mi-text" style={{ display: "grid", whiteSpace: "normal", overflowWrap: "anywhere" }}><strong>{person.name}</strong>
              <span className="meta">{[person.email, person.department].filter(Boolean).join(" · ")}</span>
              {!available ? <span className="meta tone-warn">{L(...(REASONS[person.reason ?? ""] ?? REASONS.UNAVAILABLE))}</span> : null}
            </span>
          </button>;
        })}
      </div>
      {!loading && !error && page?.directory?.usable && !rows.length ? <div className="menu-label">{L("검색 결과가 없습니다.", "No matching people.")}</div> : null}
      {page?.next_cursor ? <button type="button" className="menu-item" disabled={loading} onClick={() => setCursor(page.next_cursor)}>{L("다음 결과 더 보기", "Load more results")}</button> : null}
    </Menu> : null}
  </Field>;
}
