"use client";

/* The console: the rail, the page head controls, the current screen and everything that floats
 * above it. It owns the language, theme and display-timezone preferences, the session gate and
 * the ?view= route. */

import { type ComponentType, useCallback, useEffect, useMemo, useState } from "react";

import { useDisplayTimezone } from "@/components/display-timezone";
import { type Locale, LocaleContext } from "@/components/locale";
import { setThemePreference, useThemePreference } from "@/components/theme";
import { DashboardAPIError, api } from "@/lib/dashboard-api";
import { hasRole, type Session } from "@/lib/dashboard-session";
import { ChangesContext, reasonText } from "@/console/data";
import { Ic } from "@/console/icons";
import { Menu, MenuItem, MenuLabel, MenuSep, ToastProvider, TooltipLayer, useMenu } from "@/console/layer";
import { NAV, navItem, readRoute, type Route, routeHref, type ViewId } from "@/console/nav";
import { Notifications } from "@/console/notifications";
import { GlobalSearch } from "@/console/search";
import { sayIn, useL } from "@/console/text";
import { Card, Loading, PageHead, TopbarContext } from "@/console/ui";

export type ViewProps = {
  session: Session;
  route: Route;
  go: (view: ViewId, params?: Record<string, string | null | undefined>, options?: { replace?: boolean }) => void;
  setParams: (params: Record<string, string | null | undefined>, options?: { replace?: boolean }) => void;
  // Whether this console has the screen and the reader's role opens it: links to it show only then.
  can: (view: ViewId) => boolean;
};

export type ViewTable = Partial<Record<ViewId, ComponentType<ViewProps>>>;

const LOCALE_KEY = "cremore.locale";

export function Console({ views }: { views: ViewTable }) {
  const [locale, setLocale] = useState<Locale>("ko");
  const [route, setRoute] = useState<Route | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [sessionError, setSessionError] = useState<unknown>(null);
  const [sessionTick, setSessionTick] = useState(0);
  const [revision, setRevision] = useState(0);
  useDisplayTimezone();

  useEffect(() => {
    try {
      const saved = window.localStorage.getItem(LOCALE_KEY);
      if (saved === "ko" || saved === "en") setLocale(saved);
    } catch { /* A blocked storage keeps the default language. */ }
    const read = () => setRoute(readRoute(window.location.search));
    read();
    window.addEventListener("popstate", read);
    return () => window.removeEventListener("popstate", read);
  }, []);

  useEffect(() => { document.documentElement.lang = locale; }, [locale]);
  // Saved only when the reader chooses: an effect writing the initial value would race the read above.
  const chooseLocale = useCallback((next: Locale) => {
    setLocale(next);
    try { window.localStorage.setItem(LOCALE_KEY, next); } catch { /* optional */ }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    api<Session>("session", { signal: controller.signal }).then(value => { setSession(value); setSessionError(null); })
      .catch(reason => { if (!controller.signal.aborted) { setSession(null); setSessionError(reason); } });
    return () => controller.abort();
  }, [sessionTick]);

  const saved = useCallback(() => setRevision(value => value + 1), []);
  const authLost = useCallback((reason: DashboardAPIError) => { setSession(null); setSessionError(reason); }, []);
  const changes = useMemo(() => ({ revision, saved, authLost }), [revision, saved, authLost]);

  const go = useCallback((view: ViewId, params?: Record<string, string | null | undefined>, options?: { replace?: boolean }) => {
    const href = routeHref(view, params);
    if (options?.replace) window.history.replaceState(null, "", href); else window.history.pushState(null, "", href);
    setRoute(readRoute(href));
    if (!options?.replace) window.scrollTo({ top: 0 });
  }, []);
  const setParams = useCallback((params: Record<string, string | null | undefined>, options?: { replace?: boolean }) => {
    const query = new URLSearchParams(window.location.search);
    for (const [key, value] of Object.entries(params)) { if (value) query.set(key, value); else query.delete(key); }
    const href = `?${query.toString()}`;
    if (options?.replace === false) window.history.pushState(null, "", href); else window.history.replaceState(null, "", href);
    setRoute(readRoute(href));
  }, []);

  const L = sayIn(locale);
  const allowed = session && route ? hasRole(session.role, navItem(route.view).role) : false;
  const View = route ? views[route.view] : undefined;
  const can = useCallback((view: ViewId) => Boolean(views[view]) && hasRole(session?.role, navItem(view).role), [views, session]);

  return <LocaleContext.Provider value={locale}>
    <ChangesContext.Provider value={changes}>
      <ToastProvider>
        <a className="sr skip" href="#main">{L("본문으로 이동", "Skip to content")}</a>
        <Rail current={route?.view ?? null} session={session} go={go} />
        <main className="main" id="main" tabIndex={-1}>
          <TopbarContext.Provider value={<TopbarRight locale={locale} setLocale={chooseLocale} session={session} go={go} />}>
            {!route || (!session && !sessionError) ? <Loading /> : !session ? <SessionGate error={sessionError} retry={() => setSessionTick(value => value + 1)} />
              : !allowed ? <NotAllowed go={go} role={session.role} />
                : !View ? <Pending view={route.view} go={go} />
                  : <View session={session} route={route} go={go} setParams={setParams} can={can} />}
          </TopbarContext.Provider>
        </main>
        <TooltipLayer />
      </ToastProvider>
    </ChangesContext.Provider>
  </LocaleContext.Provider>;
}

function Rail({ current, session, go }: { current: ViewId | null; session: Session | null; go: ViewProps["go"] }) {
  const L = useL();
  const entries = NAV.filter((entry, index) => {
    if ("group" in entry) {
      // A group shows when any of its items does.
      for (let next = index + 1; next < NAV.length && !("group" in NAV[next]); next++) {
        const item = NAV[next];
        if ("id" in item && (!session || hasRole(session.role, item.role))) return true;
      }
      return false;
    }
    return !session || hasRole(session.role, entry.role);
  });
  return <nav className="rail" id="rail" aria-label={L("주 메뉴", "Main menu")}>
    <div className="rail-brand"><Ic name="shield" size={26} /><b>CreMore</b></div>
    <div className="rail-scroll">
      {entries.map(entry => "group" in entry
        ? <div className="rail-group" key={entry.group[0]}><span>{L(...entry.group)}</span></div>
        : <a className="rail-item" key={entry.id} href={routeHref(entry.id)} aria-current={current === entry.id ? "page" : undefined}
          aria-label={L(...entry.label)} onClick={event => {
            if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
            event.preventDefault();
            go(entry.id);
            document.getElementById("main")?.focus({ preventScroll: true });
          }}><Ic name={entry.icon} size={20} /><span>{L(...entry.label)}</span></a>)}
    </div>
  </nav>;
}

function TopbarRight({ locale, setLocale, session, go }: { locale: Locale; setLocale: (value: Locale) => void; session: Session | null; go: ViewProps["go"] }) {
  const L = sayIn(locale);
  const theme = useThemePreference();
  const help = useMenu(), me = useMenu();
  const modes = [
    { id: "light" as const, icon: "sun" as const, label: L("라이트", "Light") },
    { id: "dark" as const, icon: "moon" as const, label: L("다크", "Dark") },
    { id: "system" as const, icon: "monitor" as const, label: L("시스템", "System") },
  ];
  const roleName = session ? { Viewer: L("조회자", "Viewer"), Analyst: L("분석가", "Analyst"), Remediator: L("조치 담당자", "Remediator"), Admin: L("관리자", "Admin") }[session.role] : "";
  const initial = session ? (session.name.trim()[0] ?? "?").toUpperCase() : "·";
  const accountLabel = session ? `${session.name}${session.email && session.email !== session.name ? ` (${session.email})` : ""} · ${roleName}` : L("세션 확인 중", "Checking session");
  return <div className="topbar-right">
    {session ? <GlobalSearch go={go} session={session} /> : null}
    <button type="button" className="icon-btn" aria-label={L("도움말", "Help")} data-tip={L("도움말", "Help")}
      onClick={event => help.open(event.currentTarget)}><Ic name="book" size={19} /></button>
    {help.anchor ? <Menu anchor={help.anchor} onClose={help.close} restore={help.opener} label={L("도움말", "Help")}>
      <div className="help-box">
        <b>{L("CreMore 사용 순서", "Getting started with CreMore")}</b>
        <div>{L("1. 연동 서비스에서 코드 저장소·클라우드·협업 도구를 연결합니다.", "1. Connect code hosts, clouds and collaboration tools under Integrations.")}</div>
        <div>{L("2. 수집이 끝나면 노출된 Credential과 발급 목록이 Credential 목록에 모입니다.", "2. When collection finishes, exposed credentials and issued inventories gather in the credential list.")}</div>
        <div>{L("3. 상세 패널에서 위험 근거를 보고 담당자에게 연락해 폐기·교체를 기록합니다.", "3. In the detail panel, review the risk evidence, contact the owner and record revocation and rotation.")}</div>
        <div className="muted">{L("단축키: / 검색 · Esc 닫기", "Shortcuts: / search · Esc close")}</div>
      </div>
    </Menu> : null}
    {session ? <Notifications go={go} admin={hasRole(session.role, "Admin")} /> : null}
    <div className="seg" role="group" aria-label={L("언어", "Language")}>
      <button type="button" aria-pressed={locale === "ko"} aria-label="한국어" onClick={() => setLocale("ko")}>KO</button>
      <button type="button" aria-pressed={locale === "en"} aria-label="English" onClick={() => setLocale("en")}>EN</button>
    </div>
    <div className="seg" role="group" aria-label={L("화면 테마", "Theme")}>
      {modes.map(mode => <button type="button" key={mode.id} aria-pressed={theme === mode.id} aria-label={mode.label}
        onClick={() => setThemePreference(mode.id)}><Ic name={mode.icon} size={15} /><span className="seg-label">{mode.label}</span></button>)}
    </div>
    <button type="button" className="avatar" aria-label={accountLabel}
      data-tip={session ? accountLabel : undefined} onClick={event => session && me.open(event.currentTarget)}>{initial}</button>
    {me.anchor && session ? <Menu anchor={me.anchor} onClose={me.close} restore={me.opener} label={L("내 정보", "Account")}>
      <MenuLabel>{L("로그인한 사용자", "Signed in as")}</MenuLabel>
      <div className="help-box cell-wrap"><b>{session.name}</b>
        {session.email && session.email !== session.name ? <div className="muted">{session.email}</div> : null}
        <div className="muted">{roleName}</div></div>
      <MenuSep />
      <MenuItem icon="settings" onSelect={() => { me.close(); go("settings"); }} disabled={!hasRole(session.role, "Admin")}>{L("환경 설정", "Settings")}</MenuItem>
    </Menu> : null}
  </div>;
}

function SessionGate({ error, retry }: { error: unknown; retry: () => void }) {
  const L = useL();
  const denied = error instanceof DashboardAPIError && (error.status === 401 || error.status === 403);
  return <>
    <PageHead title="CreMore" />
    <Card className="placeholder">
      <h2>{denied ? L("로그인이 필요합니다", "Sign-in required") : L("서버에 연결하지 못했습니다", "Could not reach the server")}</h2>
      <p>{denied ? L("조직의 로그인 페이지에서 다시 로그인한 뒤 새로 고치세요.", "Sign in again through your organization, then reload.") : reasonText(error, L)}</p>
      <button type="button" className="primary-btn" onClick={retry}>{L("다시 시도", "Try again")}</button>
    </Card>
  </>;
}

// A screen of the rail this build does not have yet.
function Pending({ view, go }: { view: ViewId; go: ViewProps["go"] }) {
  const L = useL();
  return <>
    <PageHead title={L(...navItem(view).label)} />
    <Card className="placeholder">
      <h2>{L("이 화면은 아직 연결하지 않았습니다", "This screen is not connected yet")}</h2>
      <p>{L("Credential 관리 현황과 Credential 화면에서 지금 구성을 확인하세요.", "See the current layout on Credential overview and Credentials.")}</p>
      <button type="button" className="primary-btn" onClick={() => go("dashboard")}>{L("Credential 관리 현황으로", "Go to Credential overview")}</button>
    </Card>
  </>;
}

function NotAllowed({ go, role }: { go: ViewProps["go"]; role: Session["role"] }) {
  const L = useL();
  return <>
    <PageHead title="CreMore" />
    <Card className="placeholder">
      <h2>{L("이 화면을 볼 권한이 없습니다", "You cannot open this screen")}</h2>
      <p>{L(`현재 역할(${role})로는 열 수 없습니다. 필요한 경우 관리자에게 역할 변경을 요청하세요.`, `Your role (${role}) cannot open it. Ask an admin to change your role if you need it.`)}</p>
      <button type="button" className="primary-btn" onClick={() => go("dashboard")}>{L("Credential 관리 현황으로", "Go to Credential overview")}</button>
    </Card>
  </>;
}
