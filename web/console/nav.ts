/* Where the console can go, who may go there, and how a URL names it.
 *
 * The rail keeps the design's groups. Screens the design did not draw sit in the group their
 * work belongs to. A role here only decides what the rail offers; every route re-checks the
 * role on the server. */

import type { IconName } from "@/console/icons";
import type { PlatformRole } from "@/lib/dashboard-session";

export type ViewId =
  | "dashboard" | "exposed" | "inventory"
  | "assign" | "leavers" | "approvals"
  | "sources" | "metadata" | "scans"
  | "vaults"
  | "rules" | "audit" | "operations" | "settings";

export type NavGroup = { group: [string, string] };
export type NavItem = { id: ViewId; label: [string, string]; icon: IconName; role: PlatformRole };

export const NAV: (NavGroup | NavItem)[] = [
  { group: ["개요", "Overview"] },
  { id: "dashboard", label: ["Credential 관리 현황", "Credential overview"], icon: "grid", role: "Viewer" },
  { group: ["발견", "Discover"] },
  { id: "exposed", label: ["노출된 Credential", "Exposed credentials"], icon: "alert", role: "Viewer" },
  { id: "inventory", label: ["Credential 목록", "Credential inventory"], icon: "key", role: "Viewer" },
  { group: ["대응", "Response"] },
  { id: "assign", label: ["담당자 및 부서 배정", "Owner & team assignment"], icon: "users", role: "Viewer" },
  { id: "leavers", label: ["퇴사자 Credential", "Departed owners"], icon: "userMinus", role: "Analyst" },
  { id: "approvals", label: ["조치 승인", "Action approvals"], icon: "checkList", role: "Viewer" },
  { group: ["수집 관리", "Collection"] },
  { id: "sources", label: ["연동 서비스", "Integrations"], icon: "plug", role: "Admin" },
  { id: "metadata", label: ["메타데이터 수집 현황", "Metadata coverage"], icon: "columns", role: "Viewer" },
  { id: "scans", label: ["수집·탐지 현황", "Collection & detection status"], icon: "scan", role: "Viewer" },
  { group: ["Secret 관리", "Secret management"] },
  { id: "vaults", label: ["Secret 저장소", "Secret stores"], icon: "vault", role: "Viewer" },
  { group: ["설정", "Settings"] },
  { id: "rules", label: ["탐지 룰 설정", "Detection rules"], icon: "sliders", role: "Admin" },
  { id: "audit", label: ["Audit Log", "Audit Log"], icon: "list", role: "Admin" },
  { id: "operations", label: ["운영 상태", "Operations"], icon: "server", role: "Admin" },
  { id: "settings", label: ["환경 설정", "Settings"], icon: "settings", role: "Admin" },
];

export const VIEWS = NAV.filter((entry): entry is NavItem => "id" in entry);

export function isView(value: string | null): value is ViewId {
  return VIEWS.some(item => item.id === value);
}

export function navItem(id: ViewId): NavItem {
  return VIEWS.find(item => item.id === id)!;
}

/** The query parameters one screen reads, beside ?view=. */
export type Route = { view: ViewId; params: URLSearchParams };

export function readRoute(search: string): Route {
  const params = new URLSearchParams(search);
  const view = params.get("view");
  params.delete("view");
  return { view: isView(view) ? view : "dashboard", params };
}

export function routeHref(view: ViewId, params?: Record<string, string | null | undefined>) {
  const query = new URLSearchParams({ view });
  for (const [key, value] of Object.entries(params ?? {})) if (value) query.set(key, value);
  return `?${query.toString()}`;
}
