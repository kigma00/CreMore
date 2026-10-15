"use client";

/* The access map: where the value is written (exposure path) or what it can reach (access scope).
 * Dashed nodes and edges are links nothing has confirmed. */

import { useLocale } from "@/components/locale";
import { Ic, type IconName } from "@/console/icons";
import { typeLabel, visLabel } from "@/console/labels";
import { markOf, serviceName } from "@/console/logos";
import { awsPermissionEvidence, type CredentialRecord, exposureService, revoked } from "@/console/records";
import { useL } from "@/console/text";
import { accessBasis, inHistory, locKind, vaultWhere } from "@/console/views/credentials/risk";

type Node = { id: string; label: string; sub?: string; logo?: string; icon?: IconName; main?: boolean; unknown?: boolean; tone?: "bad" | "warn" | "good" | null; tip: string };
type Edge = [string, string, boolean?];

function data(c: CredentialRecord, view: "exposure" | "access", L: (ko: string, en: string) => string, name: string) {
  const cols: Node[][] = [[], [], [], []], edges: Edge[] = [];
  const node = (col: number, n: Node) => { cols[col].push(n); return n.id; };
  const cred: Node = { id: "cred", label: name, sub: typeLabel(c.credential_type, L), logo: c.provider, main: true,
    tone: c.risk === "critical" || c.risk === "high" ? "bad" : null, tip: [name, c.hint].filter(Boolean).join(" · ") };
  if (view === "exposure") {
    node(0, c.issuer ? { id: "iss", label: c.issuer.name, sub: c.issuer.role === "IAM_USER" ? L("소유 계정 · IAM 사용자", "Owning account · IAM user") : L("소유 계정", "Owning account"), icon: "user",
      tip: `${L("소유 계정", "Owning account")} · ${L("근거: ", "basis: ")}${serviceName(c.issuer.basis, c.issuer.basis)}` }
      : { id: "iss", label: L("소유 계정 미확인", "Owning account unknown"), sub: L("근거 없음", "No evidence"), icon: "userQ", unknown: true, tip: L("발급 서비스에서 소유 계정 정보를 받지 못했습니다.", "The issuer provided no owning account details.") });
    node(1, cred);
    edges.push(["iss", "cred"]);
    const seen = new Set<string>();
    c.exposures.filter(e => e.current).forEach((e, index) => {
      const place = exposureService(e.source_type), key = `loc:${place}:${e.resource_name}`;
      if (!seen.has(key)) {
        seen.add(key);
        node(2, { id: key, label: e.resource_name, sub: serviceName(place), logo: place, tip: `${serviceName(place)} · ${e.resource_name}` });
        edges.push(["cred", key]);
      }
      const kind = locKind(e.source_type), file = `file:${index}`;
      node(3, { id: file, label: `${e.location.split("/").pop()?.trim() || e.location}${e.line ? `:${e.line}` : ""}`, sub: visLabel(e.visibility, L),
        icon: kind === "doc" ? "page" : kind === "git" ? "git" : kind === "web" ? "globe" : "bucket", tone: e.visibility === "public" ? "bad" : e.visibility === "org" ? "warn" : null,
        tip: `${e.location}${e.line ? L(` · ${e.line}번째 줄`, ` · line ${e.line}`) : ""} · ${visLabel(e.visibility, L)}${inHistory(e.source_type) ? L(" · 이력에 남음", " · kept in history") : ""}` });
      edges.push([key, file]);
    });
    // Who can read the exposed repository, as its code host listed them.
    const read = c.access ? c.exposures.find(e => e.current && e.resource_name === c.access!.repository) : undefined;
    if (c.access && read) {
      const count = `${c.access.count}${c.access.truncated ? "+" : ""}`;
      node(3, { id: "ppl", label: L(`${count}개 접근 관련 주체`, `${count} access-related principals`), sub: L("접근 관련 관측", "Access observations"), icon: "users",
        tip: `${c.access.repository} · ${accessBasis(c.access.basis, L)}` });
      edges.push([`loc:${exposureService(read.source_type)}:${read.resource_name}`, "ppl"]);
    }
    if (!c.exposures.some(e => e.current)) {
      node(2, { id: "none", label: L("노출 관측 없음", "Not observed"), sub: L("검사 범위 안", "Within scan coverage"), icon: "checkCircle", unknown: true, tip: L("연결한 위치를 검사한 범위에서 발견되지 않았습니다.", "Not found within the scanned locations.") });
      edges.push(["cred", "none", true]);
    }
    if (c.vault.state === "stored") {
      const where = vaultWhere(c);
      node(2, { id: "vault", label: where.split(" · ")[0] || L("Vault", "Vault"), sub: L("Vault 보관", "Stored in Vault"), icon: "vault", tone: "good", tip: where });
      edges.push(["cred", "vault", true]);
    }
  } else {
    const iam = awsPermissionEvidence(c);
    node(0, cred);
    node(1, { id: "svc", label: serviceName(c.provider), sub: L("발급 서비스", "Issuer"), logo: c.provider, tip: L("발급 서비스", "Issuer") });
    edges.push(["cred", "svc"]);
    if (c.scopes?.length) {
      c.scopes.forEach((scope, index) => {
        node(2, { id: `sc${index}`, label: scope.name, sub: scope.write ? L("쓰기 가능", "Can write") : scope.write === false ? L("읽기", "Read") : L("권한", "Permission"),
          icon: scope.write ? "pencil" : "book", tone: scope.write && !revoked(c) ? (c.verification.state === "active" ? "bad" : "warn") : null, tip: scope.name });
        edges.push(["svc", `sc${index}`]);
      });
    } else if (iam.policyObserved || iam.simulationObserved) {
      const entries = [
        ...iam.policies.map(name => ({ name, sub: L("IAM 정책", "IAM policy") })),
        ...iam.actions.map(action => ({ name: action.action, sub: L("시뮬레이션 · 잠재 권한", "Simulated · potential") })),
      ];
      const note = L("수집한 정책·시뮬레이션 근거입니다. 실제 리소스 접근이나 자격증명 유효성을 입증하지 않습니다.",
        "Collected policies and simulations; not proof of effective resource access or credential validity.");
      const shown = entries.length ? entries.slice(0, 5) : [{ name: L("권한 조회 완료", "Permissions checked"), sub: L("허용 근거 없음", "No grants observed") }];
      shown.forEach((entry, index) => {
        node(2, { id: `sc${index}`, label: entry.name, sub: iam.historical ? L("과거 관측", "Historical") : iam.partial ? L("부분 수집", "Partial collection") : entry.sub,
          icon: "book", tip: `${entry.name} · ${note}` });
        edges.push(["svc", `sc${index}`]);
      });
      if (entries.length > shown.length) node(2, { id: "more", label: L(`외 ${entries.length - shown.length}개`, `${entries.length - shown.length} more`),
        sub: L("아래 권한 카드에서 확인", "See permissions below"), icon: "info", tip: entries.slice(shown.length).map(e => e.name).join(", ") });
    } else {
      node(2, { id: "sc", label: L("권한 미확인", "Permissions unknown"), sub: L("발급 정보 없음", "No issuance info"), icon: "userQ", unknown: true, tip: L("발급 서비스에서 권한 정보를 받지 못했습니다.", "The issuer provided no permission info.") });
      edges.push(["svc", "sc", true]);
    }
    node(3, { id: "rsx", label: L("접근 대상 미확인", "Targets unknown"), sub: L("근거 없음", "No evidence"), icon: "userQ", unknown: true, tip: L("접근할 수 있는 자원을 확인하지 못했습니다.", "Reachable resources could not be confirmed.") });
    edges.push([c.scopes?.length || iam.policyObserved || iam.simulationObserved ? "sc0" : "sc", "rsx", true]);
  }
  return { cols, edges };
}

function trunc(value: string, n: number) {
  return value.length > n ? `${value.slice(0, n - 1)}…` : value;
}

export function AccessGraph({ c, view, big, zoom, name }: { c: CredentialRecord; view: "exposure" | "access"; big: boolean; zoom: number; name: string }) {
  const L = useL();
  useLocale();
  const g = data(c, view, L, name);
  const colW = big ? 220 : 190, gapY = big ? 96 : 84, R = big ? 24 : 21;
  const used = g.cols.filter(col => col.length);
  const W = 90 * 2 + (used.length - 1) * colW;
  const maxN = Math.max(...used.map(col => col.length));
  const H = Math.max(big ? 360 : 230, maxN * gapY + 70);
  const pos: Record<string, { x: number; y: number; n: Node }> = {};
  used.forEach((col, i) => {
    const start = H / 2 - (col.length - 1) * gapY / 2 - 8;
    col.forEach((n, j) => { pos[n.id] = { x: 90 + i * colW, y: start + j * gapY, n }; });
  });
  const maxChars = big ? 24 : 17, cx = W / 2, cy = H / 2, marker = big ? "arrb" : "arrc";
  return <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet" role="img" aria-label={L(`${name} 관계 그림`, `${name} relationship map`)}>
    <defs><marker id={marker} viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 1L8 5L0 9z" fill="var(--line-strong)" /></marker></defs>
    <g transform={`translate(${cx} ${cy}) scale(${zoom}) translate(${-cx} ${-cy})`}>
      {g.edges.map(([from, to, dashed]) => {
        const a = pos[from], b = pos[to];
        if (!a || !b) return null;
        const x1 = a.x + R, x2 = b.x - R - 5, mx = (x1 + x2) / 2;
        return <path key={`${from}>${to}`} className={dashed ? "g-edge dash" : "g-edge"} d={`M${x1} ${a.y} C${mx} ${a.y} ${mx} ${b.y} ${x2} ${b.y}`} markerEnd={`url(#${marker})`} />;
      })}
      {Object.values(pos).map(({ x, y, n }) => {
        const mark = n.logo ? markOf(n.logo) : null;
        const color = n.tone === "bad" ? "var(--crit)" : n.tone === "warn" ? "var(--high)" : "var(--ok)";
        return <g key={n.id} className={["g-node", mark?.src && "logo-node", n.main && "main", n.unknown && "unknown"].filter(Boolean).join(" ")} transform={`translate(${x} ${y})`} data-tip={n.tip || n.label}>
          <circle className="bg" r={R} />
          {mark?.src ? <foreignObject x={-R * 0.62} y={-R * 0.62} width={R * 1.24} height={R * 1.24}>
            <div style={{ width: "100%", height: "100%", display: "grid", placeItems: "center" }}>
              <img src={mark.src} alt="" style={{ width: "100%", height: "100%", objectFit: "contain" }} />
            </div>
          </foreignObject> : <g transform="translate(-10 -10)"><Ic name={mark?.glyph ?? n.icon ?? (n.logo ? "key" : "info")} size={20} /></g>}
          {n.tone ? <g transform={`translate(${R * 0.72} ${-R * 0.72})`}>
            <circle r="7.5" fill={color} stroke="var(--surface)" strokeWidth="2" />
            {n.tone === "good" ? <path d="M-3 0l2 2 4-4" fill="none" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
              : <path d="M0 -3.5v3.5M0 2.6v.2" stroke="#fff" strokeWidth="1.9" strokeLinecap="round" />}
          </g> : null}
          <text y={R + 17}>{trunc(n.label, maxChars)}</text>
          <text className="sub" y={R + 31}>{trunc(n.sub || "", maxChars + 2)}</text>
        </g>;
      })}
    </g>
  </svg>;
}

export function ZoomControl({ onZoom }: { onZoom: (direction: "in" | "out" | "fit") => void }) {
  const L = useL();
  return <div className="zoom">
    <button type="button" onClick={() => onZoom("in")} aria-label={L("확대", "Zoom in")}><Ic name="plus" size={16} /></button>
    <button type="button" onClick={() => onZoom("out")} aria-label={L("축소", "Zoom out")}><Ic name="minus" size={16} /></button>
    <button type="button" onClick={() => onZoom("fit")} aria-label={L("원래 크기", "Reset zoom")}><Ic name="fit" size={16} /></button>
  </div>;
}

export function nextZoom(current: number, direction: "in" | "out" | "fit") {
  if (direction === "fit") return 1;
  return Math.min(2.2, Math.max(0.6, current * (direction === "in" ? 1.2 : 1 / 1.2)));
}
