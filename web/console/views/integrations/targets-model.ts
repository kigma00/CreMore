/* What the scan targets window decides, without React: how a listed resource is shown, what choosing it
 * selects, how far a choice was narrowed, what the server would refuse, and the body a save sends.
 *
 * A target is one place an exposure scan reads (a content source, or an AWS account's buckets). Its catalog
 * lists resources by metadata only; choosing one here and saving it is the admin's approval to read it. */

import type { DisplayTimezone } from "@/components/display-timezone";
import type { ScopeResource, ScopeSelection } from "@/lib/scan-scope";
import { defaultScopeInput } from "@/lib/scan-scope";
import type { Say } from "@/console/text";

export type Narrow = "bucket" | "container" | "repo" | "tfvc" | "page" | "doc" | "rows" | "site" | "none";

/** How a choice of this resource can be narrowed. */
export function narrowOf(resourceType: string): Narrow {
  switch (resourceType) {
    case "S3_BUCKET": case "GCS_BUCKET": return "bucket";
    case "AZURE_BLOB_CONTAINER": return "container";
    case "GITHUB_REPOSITORY": case "GITLAB_REPOSITORY": case "BITBUCKET_REPOSITORY": case "AZURE_DEVOPS_REPOSITORY": return "repo";
    case "AZURE_DEVOPS_TFVC": return "tfvc";
    case "NOTION_PAGE": return "page";
    case "CONFLUENCE_PAGE": return "doc";
    case "NOTION_DATA_SOURCE": return "rows";
    case "WEBSITE": return "site";  // the domain's start pages, as its integration lists them
    default: return "none";
  }
}

/** Whether a listed resource can be chosen, and why not. A resource the account can name but not open
 * stays on the list, disabled: "not listed" and "cannot read" are different facts. */
export function pickable(item: ScopeResource): { ok: boolean; reason?: string } {
  if (item.list_visibility === "DENIED") return { ok: false, reason: item.reason_code || "LIST_DENIED" };
  if (item.list_visibility !== "VISIBLE") return { ok: false, reason: item.reason_code || "NOT_LISTED" };
  if (!["READY", "NEEDS_RUNTIME_CHECK", "NOT_PROBED"].includes(item.content_readiness)) return { ok: false, reason: item.content_readiness || "NOT_READABLE" };
  if (narrowOf(item.resource_type) === "none") return { ok: false, reason: "UNSUPPORTED_RESOURCE" };
  return { ok: true };
}

/** What choosing a resource selects before anyone narrows it: every current object of a bucket, the default
 * branch of a repository, a page by itself, and no rows of a data source (rows are chosen one by one). */
export function defaultRoot(item: ScopeResource): ScopeSelection {
  const narrow = narrowOf(item.resource_type);
  const branch = item.default_branch ? `refs/heads/${item.default_branch.replace(/^refs\/heads\//, "")}` : undefined;
  return {
    resource_id: item.id,
    all_current_objects: narrow === "bucket" || narrow === "container",
    prefixes: [], excluded_prefixes: [],
    ref: narrow === "repo" ? branch : undefined,
    paths: [], excluded_paths: [],
    page_mode: narrow === "rows" ? "DATA_SOURCE_SELECTED_PAGES" : item.resource_type === "NOTION_PAGE" ? "PAGE_ONLY" : undefined,
    descendant_ids: [], include_future_descendants: false,
  };
}

/** The server's refusals for one choice, checked before a save (cremore/scanning/scope._root_problem). */
export function rootProblem(root: ScopeSelection, resourceType: string): string | null {
  if (root.include_future_descendants) return "FUTURE_DESCENDANTS_NOT_SUPPORTED";
  const narrow = narrowOf(resourceType);
  if ((narrow === "bucket" || narrow === "container") && !root.all_current_objects && !root.prefixes.length) return "BUCKET_OBJECT_SELECTION_REQUIRED";
  if (narrow === "rows" && !root.descendant_ids.length) return "DATA_SOURCE_ROWS_REQUIRED";
  if (narrow === "rows" && root.page_mode === "PAGE_ONLY") return "DATA_SOURCE_PAGE_MODE_INVALID";
  return null;
}

/** How far a choice reaches, in a few words for the list. */
export function reachText(root: ScopeSelection, resourceType: string, L: Say): string {
  const narrow = narrowOf(resourceType);
  const excluded = root.excluded_prefixes.length + root.excluded_paths.length;
  const minus = excluded ? L(` · 제외 ${excluded}개`, ` · ${excluded} excluded`) : "";
  if (narrow === "bucket" || narrow === "container") {
    if (root.prefixes.length) return L(`접두어 ${root.prefixes.length}개`, `${root.prefixes.length} prefix${root.prefixes.length > 1 ? "es" : ""}`) + minus;
    return (root.all_current_objects ? L("모든 객체", "Every object") : L("객체 미지정", "No objects chosen")) + minus;
  }
  if (narrow === "repo" || narrow === "tfvc") {
    const branch = root.ref ? root.ref.replace(/^refs\/heads\//, "") : L("기본 브랜치", "Default branch");
    const paths = root.paths.length ? L(` · 경로 ${root.paths.length}개`, ` · ${root.paths.length} path${root.paths.length > 1 ? "s" : ""}`) : "";
    return (narrow === "tfvc" ? L("TFVC 전체", "Whole TFVC tree") : branch) + paths + minus;
  }
  if (narrow === "page") return root.page_mode !== "PAGE_ONLY" && root.descendant_ids.length
    ? L("선택한 하위 페이지 포함", "With selected subpages") : L("이 페이지만", "This page only");
  if (narrow === "doc") return L("본문·첨부", "Body and attachments");
  if (narrow === "rows") return root.descendant_ids.length ? L(`행 ${root.descendant_ids.length}개`, `${root.descendant_ids.length} row${root.descendant_ids.length > 1 ? "s" : ""}`) : L("행을 고르세요", "Choose rows");
  if (narrow === "site") return L("시작 페이지·스크립트·소스맵", "Start pages, scripts and source maps");
  return "";
}

/** Whether the choice reaches less than the whole resource, so the list can show it was narrowed. */
export function narrowed(root: ScopeSelection, resourceType: string): boolean {
  const narrow = narrowOf(resourceType);
  if (root.excluded_prefixes.length || root.excluded_paths.length) return true;
  if (narrow === "bucket" || narrow === "container") return root.prefixes.length > 0;
  if (narrow === "repo" || narrow === "tfvc") return root.paths.length > 0;
  if (narrow === "page") return root.page_mode === "PAGE_WITH_DESCENDANTS";
  return narrow === "rows";
}

/** Literal prefixes/paths, one per line. Spaces and commas are resource-name characters. */
export function lines(text: string): string[] {
  return [...new Set(text.split(/\r?\n/).filter(item => item !== ""))];
}

/** The state chip a resource carries on the list. */
export function readiness(item: ScopeResource, L: Say): { tone: "ok" | "warn" | "partial" | "running"; text: string; tip?: string } {
  if (item.list_visibility === "DENIED") return { tone: "partial", text: L("목록 권한 없음", "Cannot list"), tip: L("연동 계정이 이 항목을 열 수 없습니다", "The connected account cannot open it") };
  switch (item.content_readiness) {
    case "READY": return { tone: "ok", text: L("읽기 가능", "Readable") };
    case "NEEDS_RUNTIME_CHECK": return { tone: "running", text: L("검사할 때 확인", "Checked when scanned"), tip: L("읽기 권한은 검사할 때 확인합니다", "Read access is checked when the scan runs") };
    case "NOT_PROBED": return { tone: "running", text: L("읽기 확인 전", "Not checked yet"), tip: L("목록만 읽었고 내용을 읽을 수 있는지는 검사할 때 확인합니다", "Only the list was read; read access is confirmed when the scan runs") };
    case "INSUFFICIENT_PERMISSION": return { tone: "partial", text: L("읽기 권한 없음", "No read access"), tip: L("연동 계정에 내용 읽기 권한이 없습니다", "The connected account cannot read its content") };
    default: return { tone: "warn", text: L("확인 필요", "Needs a look"), tip: item.content_readiness };
  }
}

/** The facts under a resource's name: where it lives and how it was last seen. ``inAccount`` leaves out the
 * account a tab already names. */
export function facts(item: ScopeResource, L: Say, inAccount = false): string[] {
  const out: string[] = [];
  const narrow = narrowOf(item.resource_type);
  if (item.account_id && !inAccount) out.push(L(`계정 ${item.account_id}`, `Account ${item.account_id}`));
  if (item.region) out.push(item.region);
  if (narrow === "repo") {
    if (item.visibility && item.visibility !== "UNKNOWN") out.push({ PUBLIC: L("공개", "Public"), PRIVATE: L("비공개", "Private"), INTERNAL: L("내부", "Internal") }[item.visibility] ?? item.visibility);
    if (item.default_branch) out.push(item.default_branch.replace(/^refs\/heads\//, ""));
    if (item.archived) out.push(L("보관됨", "Archived"));
    if (item.fork) out.push(L("포크", "Fork"));
  }
  if (item.resource_type === "NOTION_DATA_SOURCE") out.push(L("데이터베이스", "Database"));
  return out;
}

/** What a resource is, in one word, for a list that mixes types. */
export function kindName(resourceType: string, L: Say): string {
  return ({
    S3_BUCKET: L("S3 버킷", "S3 bucket"), GCS_BUCKET: L("Cloud Storage 버킷", "Cloud Storage bucket"),
    AZURE_BLOB_CONTAINER: L("Blob 컨테이너", "Blob container"), GITHUB_REPOSITORY: L("저장소", "Repository"),
    GITLAB_REPOSITORY: L("프로젝트", "Project"), BITBUCKET_REPOSITORY: L("저장소", "Repository"),
    AZURE_DEVOPS_REPOSITORY: L("Git 저장소", "Git repository"), AZURE_DEVOPS_TFVC: L("TFVC", "TFVC"),
    NOTION_PAGE: L("페이지", "Page"), NOTION_DATA_SOURCE: L("데이터베이스", "Database"), CONFLUENCE_PAGE: L("페이지", "Page"),
    WEBSITE: L("웹사이트", "Website"),
  } as Record<string, string>)[resourceType] ?? resourceType;
}

export type Change = { added: number; removed: number; changed: number };

/** What a save would change against the saved choice. */
export function changes(saved: ScopeSelection[], current: Map<string, ScopeSelection>): Change {
  const before = new Map(saved.map(root => [root.resource_id, root]));
  let added = 0, changed = 0;
  for (const [id, root] of current) {
    const was = before.get(id);
    if (!was) added++;
    else if (JSON.stringify(canonical(was)) !== JSON.stringify(canonical(root))) changed++;
  }
  const removed = [...before.keys()].filter(id => !current.has(id)).length;
  return { added, removed, changed };
}

function canonical(root: ScopeSelection) {
  return {
    all: root.all_current_objects, prefixes: [...root.prefixes].sort(), excludedPrefixes: [...root.excluded_prefixes].sort(),
    ref: root.ref || "", paths: [...root.paths].sort(), excludedPaths: [...root.excluded_paths].sort(), mode: root.page_mode || "",
    rows: [...root.descendant_ids].sort(),
  };
}

export type SavedProfile = {
  id: string; version: number; name: string; state: string; selected_roots: ScopeSelection[]; excluded_ids: string[];
  budgets: { bytes: number; requests: number; seconds: number }; schedule_minutes: number; full_scan_minutes?: number | null; event_mode: string;
  catalog_snapshot_id: string; approved_by?: string; approved_at?: string;
};

// How often a saved choice is scanned again; 0 runs only when started.
export const SCHEDULES = [0, 5, 15, 30, 60, 360, 1440, 10080] as const;
// How often a scope is scanned in full: 1, 2, 3, 4, 6, 8, 12 or 24 times a day, or off (0); the installation default
// takes the same choices (cremore/scanning/trigger_settings.py FULL_SCAN_CHOICES). A scope saved with null follows it.
export const FULL_SCHEDULES = [1440, 720, 480, 360, 240, 180, 120, 60, 0] as const;
// The choice that saves full_scan_minutes as null: the installation default, whatever it is when the scan comes due
// (-1 is the onboarding review's "keep the existing schedule").
export const INSTALLATION_DEFAULT = -2;

/** A full-scan cadence as runs per day. */
export function fullScanText(minutes: number, L: Say): string {
  if (!minutes) return L("끄기", "Off");
  const runs = 1440 / minutes;
  if (!Number.isInteger(runs)) return scheduleText(minutes, L);
  return runs === 1 ? L("하루 1회", "Once a day") : L(`하루 ${runs}회`, `${runs} times a day`);
}

/** The display zone's offset from UTC in minutes at ``at``: KST +540, UTC 0, the device's own otherwise. */
export function zoneOffset(zone: DisplayTimezone, at = new Date()): number {
  return zone === "Asia/Seoul" ? 540 : zone === "UTC" ? 0 : -at.getTimezoneOffset();
}

/** A minute of the day moved by an offset, wrapped into 0-1439 (UTC to local with +offset, back with -offset). */
export function shiftMinute(minute: number, offset: number): number {
  return (((minute + offset) % 1440) + 1440) % 1440;
}

/** A minute of the day as hh:mm. */
export function clock(minute: number): string {
  return `${String(Math.floor(minute / 60)).padStart(2, "0")}:${String(minute % 60).padStart(2, "0")}`;
}

/** The display zone's short name, as the console's times carry it. */
export function zoneName(zone: DisplayTimezone, L: Say): string {
  return zone === "Asia/Seoul" ? "KST" : zone === "UTC" ? "UTC" : Intl.DateTimeFormat().resolvedOptions().timeZone || L("기기 시간", "device time");
}

/** A UTC minute of the day as the display zone's clock: 1020 is "02:00 KST". */
export function startText(start: number, zone: DisplayTimezone, L: Say): string {
  return `${clock(shiftMinute(start, zoneOffset(zone)))} ${zoneName(zone, L)}`;
}

/** How long after the start minute a scope's full scan may start: min(4 hours, half the cadence), as the worker
 * spreads each slot's full scans at a stable time per scope (cremore/scanning/triggers.py full_scan_offset). */
export function spreadText(minutes: number, L: Say): string {
  const spread = Math.min(240, minutes / 2);
  if (spread % 60) return L(`${spread}분`, `${spread} minutes`);
  const hours = spread / 60;
  return L(`${hours}시간`, hours === 1 ? "1 hour" : `${hours} hours`);
}

/** What the installation default means now, for the choice that follows it: "Installation default · once a day from 02:00 KST, within 4 hours". */
export function defaultText(minutes: number | undefined, start: number | undefined, zone: DisplayTimezone, L: Say): string {
  if (minutes === undefined) return L("설치 기본값", "Installation default");
  const when = minutes && start !== undefined
    ? L(`, ${startText(start, zone, L)}부터 ${spreadText(minutes, L)} 안`, ` from ${startText(start, zone, L)}, within ${spreadText(minutes, L)}`) : "";
  return L(`설치 기본값 · ${fullScanText(minutes, L)}${when}`, `Installation default · ${fullScanText(minutes, L)}${when}`);
}

export function scheduleText(minutes: number, L: Say): string {
  if (!minutes) return L("직접 실행할 때만", "Only when started");
  if (minutes === 60) return L("1시간마다", "Every hour");
  if (minutes === 360) return L("6시간마다", "Every 6 hours");
  if (minutes === 1440) return L("매일", "Daily");
  if (minutes === 10080) return L("매주", "Weekly");
  if (minutes % 1440 === 0) return L(`${minutes / 1440}일마다`, `Every ${minutes / 1440} days`);
  if (minutes % 60 === 0) return L(`${minutes / 60}시간마다`, `Every ${minutes / 60} hours`);
  return L(`${minutes}분마다`, `Every ${minutes} minutes`);
}

/** The value every saved place shares, which the review shows before the admin touches it; null when they differ
 * (or none is saved). */
export function sharedChoice<T>(values: T[]): T | null {
  return values.length && values.every(value => value === values[0]) ? values[0] : null;
}

/** What one place saves for a choice the review offers for all of them: the admin's when they touched it, else the
 * place's own saved value; a place saved for the first time takes what the review shows. An untouched choice never
 * rewrites another place's saved value. */
export function placeChoice<T>(chosen: T | null, saved: T | undefined, shown: T): T {
  return chosen !== null ? chosen : saved !== undefined ? saved : shown;
}

/** The body that saves a target's choice: exact resource ids from the catalog snapshot the admin saw. */
export function profileBody(options: {
  saved?: SavedProfile; roots: ScopeSelection[]; snapshot: string; schedule: number; fullScan?: number | null; reason: string; name: string; events?: boolean;
}) {
  const { saved, roots } = options;
  const chosen = new Set(roots.map(root => root.resource_id));
  return {
    ...defaultScopeInput(),
    expected_version: saved?.version ?? 0,
    name: saved?.name || options.name,
    selected_roots: roots.map(root => ({ ...root, ref: root.ref || undefined, page_mode: root.page_mode || undefined })),
    // An exclusion of something chosen again would cancel the choice; the rest are kept as saved.
    excluded_ids: (saved?.excluded_ids ?? []).filter(id => !chosen.has(id)),
    budgets: saved?.budgets ?? defaultScopeInput().budgets,
    schedule_minutes: options.schedule,
    full_scan_minutes: options.fullScan === undefined ? saved?.full_scan_minutes ?? null : options.fullScan,
    // Whether a change feed or a queue notification may scan what changed (Settings > What starts a scan).
    event_mode: options.events === undefined ? saved?.event_mode ?? "DISABLED" : options.events ? "ENABLED" : "DISABLED",
    change_reason: options.reason,
    catalog_snapshot_id: options.snapshot,
  };
}
