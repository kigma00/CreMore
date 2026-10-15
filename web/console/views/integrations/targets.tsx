"use client";

/* Scan targets, in the design's window. Step 1 lists what each place of an integration's exposure scan can
 * read -- an AWS account's buckets, a source's repositories or pages -- and lets an admin choose and narrow
 * them; step 2 reviews the choice, the schedule and the reason, then saves it as the approved scope and can
 * start the scan. Only resources the provider listed can be chosen, and listing never approves reading. */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { useDisplayTimezone } from "@/components/display-timezone";
import { useLocale } from "@/components/locale";
import { reasonText, send, useApi, useSaved } from "@/console/data";
import { Ic, Tick } from "@/console/icons";
import { Modal } from "@/console/layer";
import { Logo } from "@/console/logos";
import type { ViewProps } from "@/console/shell";
import { rel, type Say, useL } from "@/console/text";
import { AreaField, Banner, Check, cls, EmptyRow, Loading, SearchBox, Seg, StateChip, Switch, Tabs, TextField } from "@/console/ui";
import { CONNECTIONS_PATH, detailText, type ProviderConnection } from "@/console/views/integrations/model";
import { type ScopeTarget, scopeTargets, unitOf } from "@/console/views/integrations/scope";
import {
  type Change, changes, defaultRoot, defaultText, facts, fullScanText, INSTALLATION_DEFAULT, kindName, lines, narrowed, narrowOf, pickable,
  profileBody, reachText, readiness, FULL_SCHEDULES, placeChoice, rootProblem, type SavedProfile, SCHEDULES, scheduleText, sharedChoice,
} from "@/console/views/integrations/targets-model";
import { projectScopeCatalog, type ScopeCatalog, type ScopeResource, type ScopeSelection } from "@/lib/scan-scope";
import { api, DashboardAPIError } from "@/lib/dashboard-api";

type Only = "all" | "chosen";
type Query = { q: string; type: string; only: Only };
type Board = {
  saved: SavedProfile | null; savedReady: boolean; savedError: string | null;
  chosen: Map<string, ScopeSelection>; known: Map<string, ScopeResource>;
  page: ScopeCatalog | null; loading: boolean; error: string | null; refreshing: boolean;
  query: Query; cursors: string[]; open: string | null;
};
type Outcome = { target: ScopeTarget; state: "saved" | "started" | "failed" | "kept"; count: number; code?: string };
// The installation's full-scan default, which a place saved without a cadence of its own follows, and whether its change
// feeds run (settings/scan-triggers).
type Cadence = { schedules?: { enabled?: boolean; full_scan_default_minutes?: number; full_scan_start_minute?: number };
  change_feeds?: { enabled?: boolean } };

const PAGE = 50;
const REFRESHING = new Set(["REFRESH_QUEUED", "REFRESH_RUNNING"]);
const sleep = (ms: number) => new Promise(resolve => window.setTimeout(resolve, ms));
const base = (target: ScopeTarget) => `connections/${target.kind}/${encodeURIComponent(target.id)}`;
const blank = (): Board => ({
  saved: null, savedReady: false, savedError: null, chosen: new Map(), known: new Map(), page: null, loading: false, error: null,
  refreshing: false, query: { q: "", type: "", only: "all" }, cursors: [""], open: null,
});

function targetName(target: ScopeTarget, L: Say) {
  return target.kind === "aws" ? L(`계정 ${target.name}`, `Account ${target.name}`) : target.name || L("연결된 소스", "Connected source");
}

function errorCode(reason: unknown) {
  return reason instanceof DashboardAPIError ? reason.message.split(":", 1)[0].trim() : "UNREACHABLE";
}

function problemText(code: string, L: Say) {
  return ({
    BUCKET_OBJECT_SELECTION_REQUIRED: L("읽을 객체를 정하지 않은 버킷이 있습니다. 모든 객체를 고르거나 접두어를 넣으세요.", "A bucket has no objects chosen. Choose every object or enter prefixes."),
    DATA_SOURCE_ROWS_REQUIRED: L("행을 고르지 않은 데이터베이스가 있습니다.", "A database has no rows chosen."),
    DATA_SOURCE_PAGE_MODE_INVALID: L("데이터베이스는 행을 골라서 읽습니다.", "A database is read through the rows you choose."),
    FUTURE_DESCENDANTS_NOT_SUPPORTED: L("나중에 생길 하위 항목은 미리 고를 수 없습니다.", "Future descendants cannot be chosen in advance."),
    SCOPE_CATALOG_CHANGED: L("그사이 목록이 새로 바뀌었습니다. 1단계에서 목록을 다시 확인한 뒤 저장하세요.", "The list changed in the meantime. Review it in step 1, then save."),
    SCOPE_CATALOG_NOT_COLLECTED: L("목록을 아직 가져오지 않았습니다. 목록을 새로 고친 뒤 고르세요.", "The list has not been read yet. Refresh it, then choose."),
    SCOPE_VERSION_CONFLICT: L("다른 관리자가 먼저 저장했습니다. 다시 열어 새 내용에서 고르세요.", "Another admin saved first. Reopen and choose on the new version."),
    SCOPE_PLAN_NOT_EXECUTABLE: L("저장했지만 지금 실행할 수 없는 대상이 있습니다. 수집·탐지 현황에서 이유를 확인하세요.", "Saved, but it cannot run right now. See why under Collection & detection status."),
    CONNECTION_PAUSED: L("연동이 꺼져 있어 저장할 수 없습니다.", "The integration is turned off."),
    CONNECTION_DISABLED: L("연동이 꺼져 있어 저장할 수 없습니다.", "The integration is turned off."),
    CATALOG_REFRESH_TIMEOUT: L("목록을 가져오는 데 시간이 오래 걸립니다. 잠시 뒤 다시 열어 보세요.", "Reading the list is taking long. Open it again in a moment."),
  } as Record<string, string>)[code];
}

type Props = { conn: ProviderConnection; onClose: () => void; go: ViewProps["go"]; can: ViewProps["can"] };

/** The window reads the connection itself: the list of integrations does not carry what each place is called. */
export function TargetsModal({ conn, onClose, go, can }: Props) {
  const L = useL();
  const detail = useApi<ProviderConnection>(`${CONNECTIONS_PATH}/${conn.id}`);
  if (detail.data) return <TargetsWindow conn={detail.data} onClose={onClose} go={go} can={can} />;
  return <Modal onClose={onClose} labelledBy="tg-title" className="integ tg">
    <h2 id="tg-title"><Logo id={conn.provider} size={26} />{conn.name} <small>{L("검사 대상", "Scan targets")}</small></h2>
    {detail.error ? <Banner tone="bad" icon="alert">{reasonText(detail.error, L)}</Banner> : <Loading />}
    <div className="modal-foot"><button type="button" className="ghost-btn" onClick={onClose}>{L("닫기", "Close")}</button></div>
  </Modal>;
}

function TargetsWindow({ conn, onClose, go, can }: Props) {
  const L = useL();
  const locale = useLocale();
  const zone = useDisplayTimezone();
  const changed = useSaved();
  const triggerView = useApi<Cadence>("settings/scan-triggers", { every: 0 }).data;
  const installation = triggerView?.schedules;
  const feedsOn = triggerView?.change_feeds?.enabled;
  const targets = useMemo(() => scopeTargets(conn), [conn]);
  const [active, setActive] = useState(targets[0]?.id ?? "");
  const [boards, setBoards] = useState<Record<string, Board>>(() => Object.fromEntries(targets.map(t => [t.id, blank()])));
  const [step, setStep] = useState<1 | 2 | 3>(1);
  // The admin's choices for every place; null until touched, when each place keeps its own saved value.
  const [schedule, setSchedule] = useState<number | null>(null);
  const [fullSchedule, setFullSchedule] = useState<number | null>(null);
  const [events, setEvents] = useState<boolean | null>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState<"save" | "start" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [outcomes, setOutcomes] = useState<Outcome[]>([]);
  // Answers that arrive after the window closed are dropped (a development re-mount opens it again).
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);

  const update = useCallback((id: string, change: (board: Board) => Partial<Board>) =>
    setBoards(all => ({ ...all, [id]: { ...(all[id] ?? blank()), ...change(all[id] ?? blank()) } })), []);
  const boardsRef = useRef(boards);
  boardsRef.current = boards;
  const target = targets.find(t => t.id === active) ?? targets[0];
  const board = target ? boards[target.id] ?? blank() : blank();

  const loadPage = useCallback(async (t: ScopeTarget, query: Query, cursor: string, chosenIds: string[]) => {
    update(t.id, () => ({ loading: true, error: null }));
    try {
      const params = { q: query.q.trim(), resource_type: query.type, sort: "name_asc", page_size: PAGE, ...(cursor ? { cursor } : {}) };
      const raw = query.only === "chosen"
        ? await send<unknown>(`${base(t)}/resources/search`, "POST", { ...params, selected: "true", selected_ids: [...chosenIds].sort() })
        : await api<unknown>(`${base(t)}/resources?${new URLSearchParams(Object.entries(params).filter(([, v]) => v !== "").map(([k, v]) => [k, String(v)])).toString()}`);
      const page = projectScopeCatalog(raw, { kind: t.kind, connection_id: t.id });
      if (!alive.current) return page;
      update(t.id, board => {
        const known = new Map(board.known);
        for (const item of page.items) known.set(item.id, item);
        return { page, known, loading: false };
      });
      return page;
    } catch (reason) {
      if (alive.current) update(t.id, () => ({ loading: false, error: reasonText(reason, L) }));
      return null;
    }
  }, [update, L]);

  const refresh = useCallback(async (t: ScopeTarget) => {
    update(t.id, () => ({ refreshing: true, error: null }));
    try {
      let view = await send<{ reason_code?: string; catalog_snapshot_id: string }>(`${base(t)}/resources/refresh`, "POST");
      const began = Date.now();
      while (REFRESHING.has(view.reason_code ?? "")) {
        if (!alive.current) return;
        if (Date.now() - began > 180_000) { update(t.id, () => ({ refreshing: false, error: problemText("CATALOG_REFRESH_TIMEOUT", L) ?? null })); return; }
        await sleep(1500);
        view = await api<{ reason_code?: string; catalog_snapshot_id: string }>(`${base(t)}/resources?page_size=1`);
      }
      if (!alive.current) return;
      update(t.id, board => ({ refreshing: false, cursors: [""], query: { ...board.query, only: "all" } }));
      await loadPage(t, { ...(boardsRef.current[t.id]?.query ?? blank().query), only: "all" }, "", []);
    } catch (reason) {
      if (alive.current) update(t.id, () => ({ refreshing: false, error: reasonText(reason, L) }));
    }
  }, [update, loadPage, L]);

  // Every place's saved choice is read at once (the tabs count it); a place's list is read when its tab opens,
  // so an integration over many accounts does not list them all together. A list never read is read now.
  useEffect(() => {
    for (const t of targets) {
      void (async () => {
        try {
          const saved = await api<{ profiles: SavedProfile[] }>(`${base(t)}/scan-scope-profiles`);
          const profile = saved.profiles[0] ?? null;
          if (!alive.current) return;
          update(t.id, () => ({
            saved: profile, savedReady: true,
            chosen: new Map((profile?.selected_roots ?? []).map(root => [root.resource_id, root])),
          }));
        } catch (reason) {
          if (alive.current) update(t.id, () => ({ savedReady: true, savedError: reasonText(reason, L) }));
        }
      })();
    }
    // Opening reads once; later reads follow the admin's search and paging.
  }, []); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    const t = targets.find(item => item.id === active) ?? targets[0];
    const b = t ? boardsRef.current[t.id] : undefined;
    if (!t || b?.page || b?.loading || b?.refreshing) return;
    void (async () => {
      const page = await loadPage(t, b?.query ?? blank().query, "", []);
      if (page && !page.items.length && !page.catalog_snapshot_id) await refresh(t);
    })();
  }, [active]); // eslint-disable-line react-hooks/exhaustive-deps

  const setQuery = (change: Partial<Query>) => {
    if (!target) return;
    const query = { ...board.query, ...change };
    update(target.id, () => ({ query, cursors: [""] }));
    void loadPage(target, query, "", [...board.chosen.keys()]);
  };

  // Typing searches after a short pause, so each keystroke does not ask the server.
  const [typed, setTyped] = useState("");
  useEffect(() => { setTyped(board.query.q); }, [active]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (!target || typed === board.query.q) return;
    const timer = window.setTimeout(() => setQuery({ q: typed }), 350);
    return () => window.clearTimeout(timer);
  }, [typed]); // eslint-disable-line react-hooks/exhaustive-deps

  const choose = (item: ScopeResource, on: boolean) => {
    if (!target) return;
    update(target.id, b => {
      const chosen = new Map(b.chosen);
      if (on) chosen.set(item.id, b.saved?.selected_roots.find(root => root.resource_id === item.id) ?? defaultRoot(item));
      else chosen.delete(item.id);
      return { chosen, open: on ? b.open : b.open === item.id ? null : b.open };
    });
  };
  const setRoot = (id: string, root: ScopeSelection) => {
    if (!target) return;
    update(target.id, b => { const chosen = new Map(b.chosen); chosen.set(id, root); return { chosen }; });
  };

  const pickableOnPage = (board.page?.items ?? []).filter(item => pickable(item).ok);
  const allOnPage = pickableOnPage.length > 0 && pickableOnPage.every(item => board.chosen.has(item.id));
  const toggleAll = () => {
    if (!target) return;
    update(target.id, b => {
      const chosen = new Map(b.chosen);
      for (const item of pickableOnPage) {
        if (allOnPage) chosen.delete(item.id);
        else if (!chosen.has(item.id)) chosen.set(item.id, b.saved?.selected_roots.find(root => root.resource_id === item.id) ?? defaultRoot(item));
      }
      return { chosen };
    });
  };

  const perTarget = targets.map(t => {
    const b = boards[t.id] ?? blank();
    const roots = [...b.chosen.values()];
    const diff: Change = changes(b.saved?.selected_roots ?? [], b.chosen);
    const problems = roots.map(root => {
      const item = b.known.get(root.resource_id);
      return item ? rootProblem(root, item.resource_type) : null;
    }).filter((code): code is string => Boolean(code));
    return { t, b, roots, diff, problems, dirty: diff.added + diff.removed + diff.changed > 0 };
  });
  const totalChosen = perTarget.reduce((sum, row) => sum + row.roots.length, 0);
  const anyDirty = perTarget.some(row => row.dirty);
  const eventsOf = (saved: SavedProfile) => saved.event_mode === "ENABLED";
  const savedPlaces = perTarget.filter(row => row.b.saved).map(row => row.b.saved!);
  // Before the admin touches them the review shows what every saved place shares; places that differ stay as saved.
  const sharedSchedule = sharedChoice(savedPlaces.map(saved => saved.schedule_minutes));
  const sharedFull = sharedChoice(savedPlaces.map(saved => saved.full_scan_minutes ?? INSTALLATION_DEFAULT));
  // A place saved for the first time follows the installation's full-scan default unless the admin picks a cadence.
  const shownFull = fullSchedule ?? sharedFull ?? INSTALLATION_DEFAULT;
  const fullOf = (b: Board) => placeChoice(fullSchedule, b.saved ? b.saved.full_scan_minutes ?? INSTALLATION_DEFAULT : undefined, shownFull);
  const sharedEvents = sharedChoice(savedPlaces.map(eventsOf));
  const shownSchedule = schedule ?? sharedSchedule ?? 0;
  const shownEvents = events ?? sharedEvents ?? false;
  const scheduleOf = (b: Board) => placeChoice(schedule, b.saved?.schedule_minutes, shownSchedule);
  const eventsFor = (b: Board) => placeChoice(events, b.saved ? eventsOf(b.saved) : undefined, shownEvents);
  const scheduleDirty = perTarget.some(row => row.b.saved && row.roots.length && (scheduleOf(row.b) !== row.b.saved.schedule_minutes
    || fullOf(row.b) !== (row.b.saved.full_scan_minutes ?? INSTALLATION_DEFAULT)));
  const eventsDirty = perTarget.some(row => row.b.saved && row.roots.length && eventsFor(row.b) !== eventsOf(row.b.saved));
  const problems = [...new Set(perTarget.flatMap(row => row.problems))];
  const ready = perTarget.every(row => row.b.savedReady);

  // The review names what was chosen; a choice from another page is looked up by id.
  useEffect(() => {
    if (step !== 2) return;
    for (const { t, b } of perTarget) {
      const missing = [...b.chosen.keys()].filter(id => !b.known.has(id));
      if (!missing.length) continue;
      void send<unknown>(`${base(t)}/resources/search`, "POST", { selected: "true", selected_ids: missing.slice(0, 200).sort(), sort: "name_asc", page_size: 200 })
        .then(raw => {
          const page = projectScopeCatalog(raw, { kind: t.kind, connection_id: t.id });
          update(t.id, board => { const known = new Map(board.known); for (const item of page.items) known.set(item.id, item); return { known }; });
        }).catch(() => undefined);
    }
  }, [step]); // eslint-disable-line react-hooks/exhaustive-deps

  async function finish(start: boolean) {
    setBusy(start ? "start" : "save");
    setError(null);
    if (perTarget.some(row => row.diff.added || row.diff.changed)) {
      try {
        let checked = await send<ProviderConnection>(`${CONNECTIONS_PATH}/${conn.id}/check`, "POST", { plans: conn.plans });
        const began = Date.now();
        while (!checked.checks.checked_at || Date.parse(checked.checks.checked_at) < Date.parse(checked.checks.requested_at ?? "") || checked.checks.stale) {
          if (!alive.current) return;
          if (Date.now() - began > 180_000) throw Error("PERMISSION_CHECK_REQUIRED");
          await sleep(1500);
          checked = await api<ProviderConnection>(`${CONNECTIONS_PATH}/${conn.id}`);
        }
        if (checked.checks.blockers?.length) {
          setError(checked.checks.blockers.map(row => `${row.subject ?? ""} ${row.permission ?? ""}: ${detailText(row.detail ?? row.status, L)}`).join(" · "));
          setBusy(null); return;
        }
      } catch (reason) { setError(reasonText(reason, L)); setBusy(null); return; }
    }
    const results: Outcome[] = [];
    const why = reason.trim() || L("검사 대상 화면에서 선택", "Chosen in the scan targets window");
    for (const { t, b, roots, dirty } of perTarget) {
      // A place with nothing chosen is saved only when its choice itself changed, never for the schedule or events.
      const scheduleChanged = Boolean(b.saved && roots.length) && (scheduleOf(b) !== b.saved!.schedule_minutes
        || fullOf(b) !== (b.saved!.full_scan_minutes ?? INSTALLATION_DEFAULT));
      const eventsChanged = Boolean(b.saved && roots.length) && eventsFor(b) !== eventsOf(b.saved!);
      if (!dirty && !scheduleChanged && !eventsChanged && !(start && roots.length)) { if (roots.length) results.push({ target: t, state: "kept", count: roots.length }); continue; }
      if (!roots.length && !b.saved) continue;
      try {
        let profile = b.saved;
        if (dirty || scheduleChanged || eventsChanged || !profile) {
          const snapshot = b.page?.catalog_snapshot_id || b.saved?.catalog_snapshot_id || "";
          const body = profileBody({ saved: b.saved ?? undefined, roots, snapshot, schedule: scheduleOf(b), fullScan: fullOf(b) === INSTALLATION_DEFAULT ? null : fullOf(b), reason: why,
            name: `${targetName(t, L)} · ${L("검사 대상", "Scan targets")}`, events: eventsFor(b) });
          profile = b.saved ? await send<SavedProfile>(`scan-scope-profiles/${b.saved.id}`, "PATCH", body)
            : await send<SavedProfile>(`${base(t)}/scan-scope-profiles`, "POST", body);
          update(t.id, () => ({ saved: profile, chosen: new Map((profile?.selected_roots ?? []).map(root => [root.resource_id, root])) }));
        }
        if (!start || !roots.length || !profile) { results.push({ target: t, state: "saved", count: roots.length }); continue; }
        const plan = await send<{ plan_id: string; executable: boolean }>(`scan-scope-profiles/${profile.id}/preview`, "POST");
        if (!plan.executable) { results.push({ target: t, state: "failed", count: roots.length, code: "SCOPE_PLAN_NOT_EXECUTABLE" }); continue; }
        // A run is always queued: it starts beside other connections' scans as soon as a worker is free.
        await send("scan-runs", "POST", { plan_id: plan.plan_id, profile_version: profile.version, mode: "BASELINE" });
        results.push({ target: t, state: "started", count: roots.length });
      } catch (reason) {
        const code = errorCode(reason);
        results.push({ target: t, state: "failed", count: roots.length, code });
        if (code === "SCOPE_CATALOG_CHANGED" || code === "SCOPE_VERSION_CONFLICT") {
          setError(problemText(code, L) ?? reasonText(reason, L));
          setBusy(null);
          changed();
          return;
        }
      }
    }
    changed();
    setBusy(null);
    setOutcomes(results);
    setStep(3);
  }

  if (!target) {
    return <Modal onClose={onClose} labelledBy="tg-title" className="integ tg">
      <h2 id="tg-title"><Logo id={conn.provider} size={26} />{conn.name} <small>{L("검사 대상", "Scan targets")}</small></h2>
      <p className="ig-sub">{L("이 연동에는 노출을 검사할 곳이 없습니다.", "This integration has nowhere to scan for exposures.")}</p>
      <div className="modal-foot"><button type="button" className="ghost-btn" onClick={onClose}>{L("닫기", "Close")}</button></div>
    </Modal>;
  }

  const head = <h2 id="tg-title"><Logo id={conn.provider} size={26} />{conn.name} <small>{L("검사 대상", "Scan targets")}</small></h2>;

  if (step === 3) {
    const started = outcomes.filter(o => o.state === "started");
    const failed = outcomes.filter(o => o.state === "failed");
    return <Modal onClose={onClose} labelledBy="tg-title" className="integ tg">
      <div className="ig-done">
        <div className="big"><Ic name="checkCircle" size={30} /></div>
        <h2 id="tg-title">{started.length ? L("검사를 시작했습니다", "The scan started") : L("검사 대상을 저장했습니다", "Scan targets saved")}</h2>
        <p>{started.length ? L("결과는 수집·탐지 현황과 노출된 Credential에 나타납니다.", "Results appear under Collection & detection status and on exposed credentials.")
          : L("저장한 주기에 맞춰 검사합니다. 바로 검사하려면 연동 메뉴의 ‘지금 수집’을 누르세요.", "Scans follow the saved schedule. To scan now, use Collect now in the integration menu.")}</p>
      </div>
      <div className="tg-outcomes">{outcomes.map(o => <div key={o.target.id} className="tg-outcome">
        <span className="tg-outcome-name">{targetName(o.target, L)}</span>
        <span className="ig-sub">{L(`${unitOf(o.target.sourceType, L)} ${o.count}개`, `${o.count} ${unitOf(o.target.sourceType, L)}`)}</span>
        {o.state === "started" ? <StateChip tone="running" tip={L("다른 연결의 검사와 함께 진행합니다", "Runs alongside other connections' scans")}>{L("검사 시작", "Scan started")}</StateChip>
          : o.state === "failed" ? <StateChip tone="bad" tip={o.code}>{problemText(o.code ?? "", L) ?? L("저장하지 못했습니다", "Not saved")}</StateChip>
            : o.state === "kept" ? <StateChip>{L("바뀐 것 없음", "Unchanged")}</StateChip>
              : <StateChip tone="ok">{L("저장함", "Saved")}</StateChip>}
      </div>)}</div>
      {failed.length ? <p className="ig-sub tg-note">{L("저장하지 못한 대상은 다시 열어 확인하세요.", "Open it again to look at what was not saved.")}</p> : null}
      <div className="modal-foot ig-foot-center">
        {can("scans") ? <button type="button" className="ghost-btn" onClick={() => { onClose(); go("scans", { connection: conn.id }); }}>{L("수집·탐지 현황 보기", "View collection & detection status")}</button> : null}
        <button type="button" className="primary-btn" onClick={onClose}>{L("닫기", "Close")}</button>
      </div>
    </Modal>;
  }

  const stepper = <ol className="ig-steps">
    {[L("대상 고르기", "Choose targets"), L("확인", "Review")].map((text, index) => {
      const n = index + 1;
      return <li key={text} aria-current={n === step ? "step" : undefined} className={n < step ? "done" : undefined}><span className="n">{n < step ? <Tick /> : n}</span>{text}</li>;
    })}
  </ol>;

  if (step === 2) {
    const saving = perTarget.filter(row => row.roots.length || row.b.saved);
    const mixedSchedule = schedule === null && sharedSchedule === null && savedPlaces.length > 1;
    const mixedEvents = events === null && sharedEvents === null && savedPlaces.length > 1;
    const options = [...new Set<number>([...SCHEDULES, shownSchedule, ...savedPlaces.map(saved => saved.schedule_minutes)])];
    return <Modal onClose={onClose} labelledBy="tg-title" className="integ tg" dismissable={!busy}>
      {head}{stepper}
      {error ? <Banner tone="bad" icon="alert" onClose={() => setError(null)}>{error}</Banner> : null}
      <div className="tg-review">{saving.map(({ t, b, roots, diff, problems: rowProblems }) => {
        // A narrowed choice says how far it reaches; the rest are named alone.
        const names = roots.map(root => {
          const item = b.known.get(root.resource_id);
          if (!item) return null;
          return narrowed(root, item.resource_type) ? `${item.display_name} · ${reachText(root, item.resource_type, L)}` : item.display_name;
        });
        const shown = names.filter((name): name is string => Boolean(name)).slice(0, 8);
        const more = roots.length - shown.length;
        return <section key={t.id} className="tg-rev">
          <div className="tg-rev-head"><b>{targetName(t, L)}</b>
            <span className="ig-sub">{L(`${unitOf(t.sourceType, L)} ${roots.length}개`, `${roots.length} ${unitOf(t.sourceType, L)}`)}
              {diff.added || diff.removed || diff.changed ? L(` · 추가 ${diff.added} · 빠짐 ${diff.removed} · 범위 바뀜 ${diff.changed}`, ` · ${diff.added} added · ${diff.removed} removed · ${diff.changed} narrowed`) : L(" · 바뀐 것 없음", " · unchanged")}</span></div>
          {roots.length ? <div className="pill-wrap">{shown.map((name, index) => <span key={`${name}-${index}`} className="tag">{name}</span>)}
            {more > 0 ? <span className="tag">{L(`외 ${more}개`, `+${more} more`)}</span> : null}</div>
            : <span className="ig-sub">{L("저장하면 이 곳은 검사하지 않습니다", "Saving leaves this place unscanned")}</span>}
          {rowProblems.length ? <div className="ig-result bad"><Ic name="alert" size={16} />{problemText(rowProblems[0], L)}</div> : null}
        </section>;
      })}</div>
      <dl className="kv">
        <dt><label htmlFor="tg-full-sched">{L("전체 범위 검사", "Full scope scan")}</label></dt>
        <dd><select id="tg-full-sched" className="ig-select" value={fullSchedule === null && sharedFull === null && savedPlaces.length > 1 ? "mixed" : String(shownFull)} disabled={Boolean(busy)}
          onChange={event => setFullSchedule(Number(event.target.value))}>
          {fullSchedule === null && sharedFull === null && savedPlaces.length > 1 ? <option value="mixed" disabled>{L("곳마다 다름", "Differs by place")}</option> : null}
          {[...new Set([INSTALLATION_DEFAULT, ...FULL_SCHEDULES, shownFull, ...savedPlaces.map(saved => saved.full_scan_minutes ?? INSTALLATION_DEFAULT)])].map(minutes =>
            <option key={minutes} value={minutes}>{minutes === INSTALLATION_DEFAULT
              ? defaultText(installation?.enabled === false ? 0 : installation?.full_scan_default_minutes, installation?.full_scan_start_minute, zone, L)
              : fullScanText(minutes, L)}</option>)}</select>
          <p className="ig-sub">{L("선택한 범위 전체를 다시 확인하고, 바뀌지 않은 파일은 검증된 결과를 재사용합니다. 실행 시각은 환경 설정 > 스캔 시작 조건의 시작 시각부터 셉니다. 범위마다 정해진 시각에 시작 시각부터 최대 4시간 뒤(주기가 8시간보다 짧으면 주기의 절반) 사이에 시작합니다.",
            "Checks the whole selected scope again, reusing verified results for unchanged files. Runs count from the start time in Settings > What starts a scan; each scope starts at its own fixed time between the start time and up to 4 hours later (half the interval when it is shorter than 8 hours).")}</p></dd>
        <dt><label htmlFor="tg-sched">{L("변경분 검사 주기", "Incremental scan schedule")}</label></dt>
        <dd><select id="tg-sched" className="ig-select" value={mixedSchedule ? "mixed" : String(shownSchedule)} disabled={Boolean(busy)}
          onChange={event => setSchedule(Number(event.target.value))}>
          {mixedSchedule ? <option value="mixed" disabled>{L("곳마다 다름", "Differs by place")}</option> : null}
          {options.map(minutes => <option key={minutes} value={minutes}>{scheduleText(minutes, L)}</option>)}</select></dd>
        <dt>{L("변경되면 검사", "Scan when it changes")}</dt>
        <dd><span className="tg-events"><Switch checked={shownEvents} onChange={setEvents} disabled={Boolean(busy)} label={L("변경되면 검사", "Scan when it changes")} />
          <span className="ig-sub">{mixedEvents ? L("곳마다 다릅니다. 켜거나 끄면 대상을 고른 곳 모두 같게 저장합니다. ", "It differs by place; turning it on or off saves every place with targets the same way. ") : ""}
            {L("변경 감지·큐 알림·웹훅이 알린 바뀐 곳만 검사합니다.", "Only what a change feed, a queue notification or a webhook reports as changed is scanned.")}
            {feedsOn === true ? L(" 이 설치의 변경 감지는 켜져 있습니다.", " This installation's change feeds are on.")
              : feedsOn === false ? L(" 이 설치의 변경 감지는 꺼져 있습니다.", " This installation's change feeds are off.") : ""}
            {L(" 변경 감지와 큐·웹훅 연결은 환경 설정 > 스캔 시작 조건에서 정합니다.", " Change feeds, queues and webhooks are set in Settings > What starts a scan.")}</span></span></dd>
        <dt><label htmlFor="tg-why">{L("변경 이유", "Reason")}</label></dt>
        <dd><input id="tg-why" className="tg-why" value={reason} maxLength={200} placeholder={L("선택 입력 · 저장한 대상과 함께 기록됩니다", "Optional · recorded with the saved targets")} onChange={event => setReason(event.target.value)} /></dd>
      </dl>
      <div className="safety">
        <div className="ok"><Ic name="checkCircle" size={16} /><span>{L("저장한 대상만 읽습니다. 나중에 생긴 곳은 대상을 다시 고를 때 들어갑니다", "Only the saved targets are read. Places created later join when you choose again")}</span></div>
        <div className="ok"><Ic name="checkCircle" size={16} /><span>{L("값 원문은 저장하지 않고 지문(HMAC)만 남깁니다", "Raw values are never stored; only HMAC fingerprints are kept")}</span></div>
      </div>
      <div className="modal-foot">
        <button type="button" className="ghost-btn" disabled={Boolean(busy)} onClick={() => { setError(null); setStep(1); }}>{L("이전", "Back")}</button>
        <button type="button" className="ghost-btn" disabled={Boolean(busy) || problems.length > 0 || (!anyDirty && !scheduleDirty && !eventsDirty)} onClick={() => void finish(false)}>
          {busy === "save" ? L("저장 중", "Saving") : L("저장", "Save")}</button>
        <button type="button" className="primary-btn" disabled={Boolean(busy) || problems.length > 0 || totalChosen === 0} onClick={() => void finish(true)}>
          {busy === "start" ? L("시작하는 중", "Starting") : L("저장하고 지금 검사", "Save and scan now")}</button>
      </div>
    </Modal>;
  }

  /* ---------- step 1 ---------- */

  const page = board.page;
  const unit = unitOf(target.sourceType, L);
  const types = [...new Set((page?.items ?? []).map(item => item.resource_type))];
  const typeFilter = (page?.available_filters ?? []).includes("resource_type") && (types.length > 1 || board.query.type);
  const canPrev = board.cursors.length > 1;
  const canNext = Boolean(page?.has_more && page.next_cursor);
  const goPage = (forward: boolean) => {
    const cursors = forward ? [...board.cursors, page!.next_cursor!] : board.cursors.slice(0, -1);
    update(target.id, () => ({ cursors }));
    void loadPage(target, board.query, cursors[cursors.length - 1], [...board.chosen.keys()]);
  };
  const first = (board.cursors.length - 1) * PAGE;
  const listed = page?.known_count ?? 0;
  const partial = page?.catalog_completeness === "PARTIAL";
  // No snapshot means the list was never read; a list read without a recorded time still counts.
  const never = page ? !page.catalog_snapshot_id : false;
  const listedAt = page && !page.last_refreshed_at.startsWith("0001") ? rel(page.last_refreshed_at, locale) : null;
  const blocked = problems.length > 0;
  const rowDiff = perTarget.find(row => row.t.id === target.id)?.diff;

  return <Modal onClose={onClose} labelledBy="tg-title" className="integ tg wide-list" dismissable={!busy}>
    {head}{stepper}
    {targets.length > 1 ? <Tabs label={L("검사할 곳", "Places to scan")} value={target.id} onChange={setActive} className="tg-tabs"
      items={targets.map(t => ({ id: t.id, label: targetName(t, L), count: (boards[t.id]?.chosen.size ?? 0) }))} /> : null}
    <div className="tg-bar">
      <span className="tg-count">{board.refreshing ? <><span className="spinner" aria-hidden="true" />{L(`${unit} 목록을 가져오는 중`, `Reading the ${unit}`)}</>
        : page && !never ? (listedAt ? L(`${unit} ${listed}개 · ${listedAt} 목록`, `${listed} ${unit} · listed ${listedAt}`) : L(`${unit} ${listed}개`, `${listed} ${unit}`))
          : L("목록을 아직 가져오지 않았습니다", "Not listed yet")}</span>
      {partial ? <StateChip tone="warn" tip={L("공급자가 목록 일부만 돌려줬습니다. 보이지 않는 곳은 고를 수 없습니다", "The provider returned part of the list. Places not shown cannot be chosen")}>{L("일부만 읽음", "Partly listed")}</StateChip> : null}
      <button type="button" className="ghost-btn tg-refresh" disabled={board.refreshing} onClick={() => void refresh(target)}>
        <Ic name="refresh" size={15} />{L("목록 새로 고침", "Refresh list")}</button>
    </div>
    <div className="tg-tools">
      <SearchBox value={typed} onChange={setTyped} placeholder={L(`${unit} 이름으로 찾기`, `Find ${unit} by name`)} label={L("찾기", "Find")} />
      {typeFilter ? <select className="ig-select" aria-label={L("종류", "Kind")} value={board.query.type} onChange={event => setQuery({ type: event.target.value })}>
        <option value="">{L("모든 종류", "Every kind")}</option>
        {types.map(type => <option key={type} value={type}>{kindName(type, L)}</option>)}
      </select> : null}
      <Seg label={L("보기", "Show")} value={board.query.only} onChange={only => setQuery({ only })}
        options={[{ id: "all", label: L("전체", "All") }, { id: "chosen", label: L(`고른 것 ${board.chosen.size}`, `Chosen ${board.chosen.size}`) }]} />
    </div>
    {board.error ? <Banner tone="bad" icon="alert" onClose={() => update(target.id, () => ({ error: null }))}>{board.error}</Banner> : null}
    {board.savedError ? <Banner tone="bad" icon="alert">{board.savedError}</Banner> : null}
    <div className="tg-list">
      <table className="tbl tg-tbl">
        <thead><tr>
          <th className="tg-c"><button type="button" role="checkbox" aria-checked={allOnPage} disabled={!pickableOnPage.length}
            aria-label={allOnPage ? L("이 페이지 모두 빼기", "Unchoose this page") : L("이 페이지 모두 고르기", "Choose this page")} onClick={toggleAll}><Check on={allOnPage} /></button></th>
          <th>{L("이름", "Name")}</th><th className="col-md">{L("정보", "Details")}</th><th>{L("상태", "Status")}</th><th>{L("읽을 범위", "What is read")}</th>
        </tr></thead>
        <tbody>
          {board.loading && !page ? <EmptyRow colSpan={5}><Loading /></EmptyRow>
            : !page?.items.length ? <EmptyRow colSpan={5}>{board.refreshing ? L("목록을 가져오는 중입니다", "Reading the list")
              : board.query.only === "chosen" ? L("고른 것이 없습니다", "Nothing chosen")
                : board.query.q ? L("찾는 이름이 없습니다", "No names match") : never ? L("목록을 새로 고치면 여기에 나타납니다", "Refresh the list to see it here")
                  : L("연동 계정이 볼 수 있는 곳이 없습니다", "The connected account sees nothing here")}</EmptyRow>
              : page.items.map(item => <TargetRow key={item.id} item={item} root={board.chosen.get(item.id)} open={board.open === item.id}
                onChoose={on => choose(item, on)} onOpen={() => update(target.id, b => ({ open: b.open === item.id ? null : item.id }))}
                onRoot={root => setRoot(item.id, root)} target={target} />)}
        </tbody>
      </table>
    </div>
    {canPrev || canNext ? <div className="tg-pager">
      <span className="ig-sub">{L(`${first + 1}–${first + (page?.items.length ?? 0)}번째`, `${first + 1}–${first + (page?.items.length ?? 0)}`)}</span>
      <button type="button" className="ghost-btn" disabled={!canPrev || board.loading} onClick={() => goPage(false)}><Ic name="left" size={15} />{L("이전", "Previous")}</button>
      <button type="button" className="ghost-btn" disabled={!canNext || board.loading} onClick={() => goPage(true)}>{L("다음", "Next")}<Ic name="right" size={15} /></button>
    </div> : null}
    <div className="modal-foot">
      <span className="note">{L(`고른 곳 ${totalChosen}개`, `${totalChosen} chosen`)}
        {rowDiff && (rowDiff.added || rowDiff.removed || rowDiff.changed) ? L(` · 저장한 것과 비교해 추가 ${rowDiff.added} · 빠짐 ${rowDiff.removed}`, ` · vs saved: ${rowDiff.added} added, ${rowDiff.removed} removed`) : null}
        {blocked ? <span className="tg-warn"> · {problemText(problems[0], L)}</span> : null}</span>
      <button type="button" className="ghost-btn" onClick={onClose}>{L("취소", "Cancel")}</button>
      <button type="button" className="primary-btn" disabled={!ready || blocked || (!anyDirty && totalChosen === 0 && !perTarget.some(row => row.b.saved))}
        onClick={() => { setError(null); setStep(2); }}>{L("다음", "Next")}</button>
    </div>
  </Modal>;
}

/* ---------- one listed resource ---------- */

function TargetRow({ item, root, open, onChoose, onOpen, onRoot, target }: {
  item: ScopeResource; root?: ScopeSelection; open: boolean; target: ScopeTarget;
  onChoose: (on: boolean) => void; onOpen: () => void; onRoot: (root: ScopeSelection) => void;
}) {
  const L = useL();
  const can = pickable(item);
  const state = readiness(item, L);
  const details = facts(item, L, target.kind === "aws");
  const narrow = narrowOf(item.resource_type);
  const editable = Boolean(root) && ["bucket", "container", "repo", "tfvc", "rows"].includes(narrow);
  const problem = root ? rootProblem(root, item.resource_type) : null;
  return <>
    <tr aria-selected={Boolean(root)} className={cls(!can.ok && "tg-off")} onClick={() => { if (can.ok) onChoose(!root); }}>
      <td className="tg-c"><button type="button" role="checkbox" aria-checked={Boolean(root)} disabled={!can.ok}
        aria-label={root ? L(`${item.display_name} 빼기`, `Unchoose ${item.display_name}`) : L(`${item.display_name} 고르기`, `Choose ${item.display_name}`)}
        onClick={event => { event.stopPropagation(); if (can.ok) onChoose(!root); }}><Check on={Boolean(root)} /></button></td>
      <td><div className="tg-name"><b>{item.display_name}</b>
        {item.canonical_reference && item.canonical_reference !== item.display_name ? <span className="tg-ref mono">{item.canonical_reference}</span> : null}</div></td>
      <td className="col-md"><span className="tg-facts">{details.length ? details.join(" · ") : <span className="subtle">—</span>}</span></td>
      <td><StateChip tone={state.tone} tip={state.tip}>{state.text}</StateChip></td>
      <td>{root ? <span className="tg-reach">
        <span className={cls("tg-reach-text", problem && "bad", narrowed(root, item.resource_type) && "narrowed")}>{reachText(root, item.resource_type, L)}</span>
        {editable ? <button type="button" className="link-btn" aria-expanded={open} onClick={event => { event.stopPropagation(); onOpen(); }}>
          {open ? L("접기", "Close") : narrow === "rows" ? L("행 고르기", "Choose rows") : L("범위 좁히기", "Narrow")}</button> : null}
      </span> : <span className="subtle">{can.ok ? "—" : L("고를 수 없음", "Cannot choose")}</span>}</td>
    </tr>
    {open && root ? <tr className="tg-edit"><td colSpan={5} onClick={event => event.stopPropagation()}>
      <Narrowing item={item} root={root} onRoot={onRoot} target={target} />
    </td></tr> : null}
  </>;
}

function Narrowing({ item, root, onRoot, target }: { item: ScopeResource; root: ScopeSelection; onRoot: (root: ScopeSelection) => void; target: ScopeTarget }) {
  const L = useL();
  const narrow = narrowOf(item.resource_type);
  if (narrow === "bucket" || narrow === "container") {
    const some = !root.all_current_objects || root.prefixes.length > 0;
    return <div className="tg-narrow">
      <Seg label={L("읽을 객체", "Objects to read")} value={some ? "some" : "all"} onChange={value => onRoot(value === "all"
        ? { ...root, all_current_objects: true, prefixes: [] } : { ...root, all_current_objects: false })}
        options={[{ id: "all", label: L("모든 객체", "Every object") }, { id: "some", label: L("접두어로 지정", "By prefix") }]} />
      <div className="tg-narrow-grid">
        {some ? <LinesField label={L("읽을 접두어", "Prefixes to read")} values={root.prefixes} placeholder={L("예: config/\nbackups/2026/", "e.g. config/\nbackups/2026/")}
          hint={L("한 줄에 하나씩. 공백·쉼표도 이름의 일부로 유지합니다", "One per line. Spaces and commas are kept as part of the name")}
          onChange={prefixes => onRoot({ ...root, prefixes, all_current_objects: false })} /> : null}
        <LinesField label={L("제외할 접두어", "Prefixes to skip")} values={root.excluded_prefixes} placeholder={L("예: logs/", "e.g. logs/")}
          hint={L("선택 · 한 줄에 하나씩. 공백·쉼표를 그대로 유지합니다", "Optional · one per line. Spaces and commas are preserved")} onChange={excluded_prefixes => onRoot({ ...root, excluded_prefixes })} />
      </div>
    </div>;
  }
  if (narrow === "repo" || narrow === "tfvc") {
    return <div className="tg-narrow">
      <div className="tg-narrow-grid">
        {narrow === "repo" ? <TextField label={L("브랜치", "Branch")} value={(root.ref ?? "").replace(/^refs\/heads\//, "")}
          placeholder={item.default_branch ?? "main"} hint={L("비우면 기본 브랜치를 읽습니다", "Empty reads the default branch")}
          onChange={value => onRoot({ ...root, ref: value.trim() ? (value.trim().startsWith("refs/") ? value.trim() : `refs/heads/${value.trim()}`) : undefined })} /> : null}
        <LinesField label={L("읽을 경로", "Paths to read")} values={root.paths} placeholder={L("예: config/\ndeploy/", "e.g. config/\ndeploy/")}
          hint={L("비우면 전체를 읽습니다", "Empty reads everything")} onChange={paths => onRoot({ ...root, paths })} />
        <LinesField label={L("제외할 경로", "Paths to skip")} values={root.excluded_paths} placeholder={L("예: vendor/", "e.g. vendor/")}
          hint={L("선택", "Optional")} onChange={excluded_paths => onRoot({ ...root, excluded_paths })} />
      </div>
    </div>;
  }
  if (narrow === "rows") return <RowsChooser item={item} root={root} onRoot={onRoot} target={target} />;
  return null;
}

/* A database's rows are chosen one by one: a new row is never read until someone chooses it. Rows name
 * their database by its provider id, and a chosen row is kept by its provider page id. */
function RowsChooser({ item, root, onRoot, target }: { item: ScopeResource; root: ScopeSelection; onRoot: (root: ScopeSelection) => void; target: ScopeTarget }) {
  const L = useL();
  const [rows, setRows] = useState<ScopeResource[] | null>(null);
  const [failed, setFailed] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    const query = new URLSearchParams({ resource_type: "NOTION_PAGE", parent_id: item.provider_resource_id,
      known_root_id: item.provider_resource_id, sort: "name_asc", page_size: "200" });
    api<unknown>(`${base(target)}/resources?${query.toString()}`)
      .then(raw => { if (live) setRows(projectScopeCatalog(raw, { kind: target.kind, connection_id: target.id }).items.filter(row => row.resource_type === "NOTION_PAGE")); })
      .catch(reason => { if (live) setFailed(errorCode(reason)); });
    return () => { live = false; };
  }, [item.provider_resource_id, target]);
  const chosen = new Set(root.descendant_ids);
  const flip = (id: string) => {
    const next = new Set(chosen);
    if (next.has(id)) next.delete(id); else next.add(id);
    onRoot({ ...root, page_mode: "DATA_SOURCE_SELECTED_PAGES", descendant_ids: [...next] });
  };
  if (failed) return <div className="tg-narrow"><span className="ig-sub">{L("행 목록을 가져오지 못했습니다", "Could not read the rows")} ({failed})</span></div>;
  if (!rows) return <div className="tg-narrow"><Loading label={L("행을 가져오는 중", "Reading rows")} /></div>;
  if (!rows.length) return <div className="tg-narrow"><span className="ig-sub">{L("목록에 행이 없습니다. 목록을 새로 고친 뒤 다시 여세요", "No rows are listed. Refresh the list and open again")}</span></div>;
  return <div className="tg-narrow">
    <div className="ig-opts tg-rows">{rows.map(row => <button type="button" key={row.id} className="ig-opt" role="checkbox"
      aria-checked={chosen.has(row.provider_resource_id)} onClick={() => flip(row.provider_resource_id)}>
      <Check on={chosen.has(row.provider_resource_id)} /><span className="nm">{row.display_name}</span></button>)}</div>
  </div>;
}

/* Keep literal prefixes/paths as typed; only empty lines and exact duplicates are omitted. */
function LinesField({ label, values, onChange, placeholder, hint }: {
  label: string; values: string[]; onChange: (values: string[]) => void; placeholder?: string; hint?: string;
}) {
  const [text, setText] = useState(values.join("\n"));
  return <AreaField label={label} value={text} rows={3} mono className="short" placeholder={placeholder} hint={hint}
    onChange={value => { setText(value); onChange(lines(value)); }} />;
}
