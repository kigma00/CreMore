"use client";

/* The design's building blocks, in the design's own markup and class names. Screens compose
 * these; the few blocks the design did not draw (loading, errors, empty states, form rows)
 * reuse its classes or the small additions at the end of console.css. */

import { createContext, type CSSProperties, type ReactNode, useContext, useId, useRef, useState } from "react";

import { Ic, type IconName, Tick } from "@/console/icons";
import { Menu, MenuItem, MenuSep, useMenu } from "@/console/layer";
import { useL } from "@/console/text";

export function cls(...names: (string | false | null | undefined)[]) {
  return names.filter(Boolean).join(" ");
}

/* ---------- page head ---------- */

/** The global controls on the right of every page title; the shell provides them. */
export const TopbarContext = createContext<ReactNode>(null);

export function PageHead({ title, meta, children }: { title: ReactNode; meta?: ReactNode; children?: ReactNode }) {
  const right = useContext(TopbarContext);
  return <div className="topbar"><h1>{title}</h1>{meta ? <span className="meta">{meta}</span> : null}{children}{right}</div>;
}

export function SubBar({ children }: { children: ReactNode }) {
  return <div className="subbar">{children}</div>;
}

/* ---------- tiles and cards ---------- */

export type Tone = "blue" | "red" | "violet" | "amber" | "green" | "pink" | "teal" | "gray";

export function Tile({ icon, tone, label, value, sub, tip, onClick, className, of }: {
  icon: IconName; tone: Tone; label: ReactNode; value: ReactNode; sub?: ReactNode; tip?: string; onClick?: () => void;
  className?: string; of?: ReactNode;
}) {
  const body = <>
    <span className={`tile-ic t-${tone}`}><Ic name={icon} size={19} /></span>
    <span className="tile-text">
      <span className="tile-label" style={{ display: "block" }}>{label}</span>
      <span className="tile-value num" style={{ display: "block" }}>{value}{of !== undefined ? <span className="tile-of">/{of}</span> : null}{tip ? <Ic name="info" size={13} className="tile-i" /> : null}</span>
      {sub ? <span className="tile-sub">{sub}</span> : null}
    </span>
  </>;
  return onClick
    ? <button type="button" className={cls("tile", className)} data-tip={tip} onClick={onClick}>{body}</button>
    : <div className={cls("tile", className)} data-tip={tip}>{body}</div>;
}

export function Tiles({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cls("tiles", className)}>{children}</div>;
}

export function Card({ title, info, meta, right, children, className, headClass, level = 2, id }: {
  title?: ReactNode; info?: string; meta?: ReactNode; right?: ReactNode; children?: ReactNode; className?: string;
  headClass?: string; level?: 2 | 3; id?: string;
}) {
  const heading = title === undefined ? null : level === 3 ? <h3>{title}</h3> : <h2>{title}</h2>;
  return <section className={cls("card", className)} id={id}>
    {heading || right || meta ? <div className={cls("card-head", headClass)}>
      {heading}{info ? <InfoTip text={info} /> : null}{meta ? <span className="meta">{meta}</span> : null}
      {right ? <div className="right">{right}</div> : null}
    </div> : null}
    {children}
  </section>;
}

export function CardBody({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cls("card-body", className)}>{children}</div>;
}

export function InfoTip({ text }: { text: string }) {
  return <span className="info-dot" tabIndex={0} data-tip={text} role="img" aria-label={text}><Ic name="info" size={15} /></span>;
}

export function Banner({ children, onClose, tone, icon = "info" }: { children: ReactNode; onClose?: () => void; tone?: "bad" | "warn" | "ok"; icon?: IconName }) {
  const L = useL();
  return <div className={cls("banner", tone)} role={tone === "bad" ? "alert" : undefined}>
    <Ic name={icon} size={18} /><span>{children}</span>
    {onClose ? <button type="button" onClick={onClose} aria-label={L("안내 닫기", "Dismiss")}><Ic name="close" size={16} /></button> : null}
  </div>;
}

/* ---------- switches between views ---------- */

export function Seg<T extends string>({ value, options, onChange, label, className }: {
  value: T; options: { id: T; label: ReactNode; icon?: IconName; aria?: string }[]; onChange: (id: T) => void; label: string; className?: string;
}) {
  return <div className={cls("seg", className)} role="group" aria-label={label}>
    {options.map(option => <button type="button" key={option.id} aria-pressed={value === option.id} aria-label={option.aria}
      onClick={() => onChange(option.id)}>{option.icon ? <Ic name={option.icon} size={15} /> : null}{option.label}</button>)}
  </div>;
}

export function MiniToggle<T extends string>({ value, options, onChange, label }: {
  value: T; options: { id: T; icon: IconName; label: string }[]; onChange: (id: T) => void; label: string;
}) {
  return <div className="mini-toggle" role="group" aria-label={label}>
    {options.map(option => <button type="button" key={option.id} aria-pressed={value === option.id} aria-label={option.label}
      data-tip={option.label} onClick={() => onChange(option.id)}><Ic name={option.icon} size={15} /></button>)}
  </div>;
}

export function Tabs<T extends string>({ value, items, onChange, label, className }: {
  value: T; items: { id: T; label: ReactNode; count?: number }[]; onChange: (id: T) => void; label: string; className?: string;
}) {
  return <div className={cls("tabs", className)} role="tablist" aria-label={label}>
    {items.map(item => <button type="button" role="tab" key={item.id} aria-selected={value === item.id} onClick={() => onChange(item.id)}>
      {item.label}{item.count !== undefined ? <span className="count num">{item.count}</span> : null}
    </button>)}
  </div>;
}

export function TabCards<T extends string>({ value, items, onChange, label }: {
  value: T; items: { id: T; label: ReactNode; value: ReactNode; icon: IconName; tone: Tone }[]; onChange: (id: T) => void; label: string;
}) {
  return <div className="tab-cards" role="tablist" aria-label={label}>
    {items.map(item => <button type="button" className="tab-card" role="tab" key={item.id} aria-selected={value === item.id} onClick={() => onChange(item.id)}>
      <span className={`tile-ic t-${item.tone}`}><Ic name={item.icon} size={19} /></span>
      <span className="tile-text">
        <span className="tile-label" style={{ display: "block" }}>{item.label}</span>
        <span className="tile-value num" style={{ display: "block" }}>{item.value}</span>
      </span>
    </button>)}
  </div>;
}

export function DTabs<T extends string>({ value, items, onChange, label }: {
  value: T; items: { id: T; label: ReactNode; count?: number }[]; onChange: (id: T) => void; label: string;
}) {
  return <div className="dtabs" role="tablist" aria-label={label}>
    {items.map(item => <button type="button" role="tab" key={item.id} aria-selected={value === item.id} onClick={() => onChange(item.id)}>
      {item.label}{item.count ? <span className="count num">{item.count}</span> : null}
    </button>)}
  </div>;
}

/* ---------- badges ---------- */

export function Pill({ children, unknown, tip }: { children: ReactNode; unknown?: boolean; tip?: string }) {
  return <span className={unknown ? "pill unknown" : "pill"} data-tip={tip}>{children}</span>;
}

export function Tag({ children, tip, className, onRemove, removeLabel }: {
  children: ReactNode; tip?: string; className?: string; onRemove?: () => void; removeLabel?: string;
}) {
  return <span className={cls("tag", className)} data-tip={tip}>{children}
    {onRemove ? <button type="button" onClick={onRemove} aria-label={removeLabel}><Ic name="close" size={12} /></button> : null}
  </span>;
}

export type Risk = "critical" | "high" | "medium" | "low" | "info";
export const RISK_RANK: Record<Risk, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

export function riskLabel(level: Risk, L: (ko: string, en: string) => string) {
  return { critical: L("심각", "Critical"), high: L("높음", "High"), medium: L("보통", "Medium"), low: L("낮음", "Low"), info: L("정보", "Info") }[level];
}

function RiskBars({ level }: { level: Risk }) {
  const n = { critical: 3, high: 3, medium: 2, low: 1, info: 0 }[level];
  return <svg width="18" height="18" viewBox="0 0 22 20" aria-hidden="true">
    <rect width="22" height="20" rx="4" fill="currentColor" />
    {[4, 8, 12].map((h, i) => <rect key={h} x={5 + i * 4.6} y={16 - h} width="3" height={h} rx="1" fill={i < n ? "#fff" : "rgba(255,255,255,.45)"} />)}
  </svg>;
}

export function RiskTag({ level }: { level: Risk }) {
  const L = useL();
  const label = riskLabel(level, L);
  return <span className={`risk risk-${level}`} data-tip={label}><RiskBars level={level} /><span className="risk-text">{label}</span></span>;
}

export type Status = "pending" | "review" | "action" | "done" | "fp" | "ignored";

export function statusLabel(status: Status, L: (ko: string, en: string) => string) {
  return { pending: L("검토 대기", "Pending review"), review: L("검토 중", "In review"), action: L("조치 중", "Remediating"),
    done: L("조치 완료", "Remediated"), fp: L("오탐", "False positive"), ignored: L("예외 처리", "Accepted") }[status];
}

export function StatusTag({ status }: { status: Status | null }) {
  const L = useL();
  if (!status) return <span className="st st-none">{L("노출 없음", "Not exposed")}</span>;
  return <span className={`st st-${status === "ignored" ? "fp" : status}`}>{statusLabel(status, L)}</span>;
}

export type Verify = "active" | "revoked" | "inactive" | "failed" | "expired" | "unknown";

export function verifyLabel(state: Verify, L: (ko: string, en: string) => string, basis?: string | null) {
  if (basis === "ISSUER_REPORTED") return {
    active: L("발급처 상태: 활성", "Issuer status: active"), inactive: L("발급처 상태: 비활성", "Issuer status: inactive"),
    revoked: L("발급처 상태: 폐기", "Issuer status: revoked"), expired: L("발급처 상태: 만료", "Issuer status: expired"),
    failed: L("발급처 상태: 실패", "Issuer status: failed"), unknown: L("발급처 상태 미확인", "Issuer status unknown"),
  }[state];
  return { active: L("활성 확인", "Active"), revoked: L("폐기 확인", "Revoked"), inactive: L("비활성", "Inactive"),
    failed: L("인증 실패", "Auth failed"), expired: L("만료됨", "Expired"), unknown: L("미확인", "Unknown") }[state];
}

export function VerifyTag({ state, tip, basis }: { state: Verify; tip?: string; basis?: string | null }) {
  const L = useL();
  const tone = state === "expired" ? "v-inactive" : `v-${state}`;
  return <span className={`vchip ${tone}`} data-tip={tip}>{verifyLabel(state, L, basis)}</span>;
}

/** A state chip in the integrations list style (.igs): ok, warn, partial, running or neutral. */
export function StateChip({ tone, children, tip }: { tone?: "ok" | "warn" | "partial" | "running" | "bad"; children: ReactNode; tip?: string }) {
  return <span className={cls("igs", tone === "bad" ? "partial" : tone)} data-tip={tip}><span className="dot" />{children}</span>;
}

/* ---------- inputs ---------- */

export function Switch({ checked, onChange, label, disabled, tip }: {
  checked: boolean; onChange: (next: boolean) => void; label: string; disabled?: boolean; tip?: string;
}) {
  return <button type="button" role="switch" className="switch" aria-checked={checked} aria-label={label} disabled={disabled}
    data-tip={tip} onClick={() => onChange(!checked)} style={disabled ? { opacity: 0.45, cursor: "not-allowed" } : undefined} />;
}

export function Check({ on, mixed }: { on: boolean; mixed?: boolean }) {
  return <span className={on || mixed ? "check on" : "check"} aria-hidden="true">{on ? <Tick /> : mixed ? <span className="check-dash" /> : null}</span>;
}

export function Field({ label, children, hint, htmlFor, tip }: { label: ReactNode; children: ReactNode; hint?: ReactNode; htmlFor?: string; tip?: string }) {
  const caption = htmlFor ? <label htmlFor={htmlFor}>{label}</label> : <span className="lbl">{label}</span>;
  return <div className="field">
    {tip ? <div className="field-label">{caption}<InfoTip text={tip} /></div> : caption}
    {children}
    {hint ? <span className="meta">{hint}</span> : null}
  </div>;
}

export function TextField({ label, value, onChange, placeholder, hint, tip, type = "text", masked, required, autoFocus, disabled, inputMode, maxLength, min, max }: {
  label: ReactNode; value: string; onChange: (value: string) => void; placeholder?: string; hint?: ReactNode; type?: string;
  masked?: boolean; required?: boolean; autoFocus?: boolean; disabled?: boolean; inputMode?: "numeric" | "text" | "url" | "email"; maxLength?: number;
  min?: string; max?: string; tip?: string;
}) {
  const id = useId();
  return <Field label={label} hint={hint} htmlFor={id} tip={tip}>
    <input id={id} type={type} value={value} placeholder={placeholder} onChange={event => onChange(event.target.value)}
      className={masked ? "masked" : undefined} autoComplete={masked ? "off" : undefined} spellCheck={masked ? false : undefined}
      required={required} data-autofocus={autoFocus || undefined} disabled={disabled} inputMode={inputMode} maxLength={maxLength}
      min={min} max={max} />
  </Field>;
}

export function AreaField({ label, value, onChange, placeholder, hint, tip, rows, className, mono, maxLength }: {
  label: ReactNode; value: string; onChange: (value: string) => void; placeholder?: string; hint?: ReactNode; rows?: number;
  className?: string; mono?: boolean; maxLength?: number; tip?: string;
}) {
  const id = useId();
  return <Field label={label} hint={hint} htmlFor={id} tip={tip}>
    <textarea id={id} value={value} placeholder={placeholder} rows={rows} onChange={event => onChange(event.target.value)}
      className={cls(className, mono && "mono")} maxLength={maxLength} spellCheck={mono ? false : undefined} />
  </Field>;
}

export function SelectField<T extends string>({ label, value, options, onChange, hint, tip, disabled }: {
  label: ReactNode; value: T; options: { id: T; label: string }[]; onChange: (value: T) => void; hint?: ReactNode; disabled?: boolean; tip?: string;
}) {
  const id = useId();
  return <Field label={label} hint={hint} htmlFor={id} tip={tip}>
    <select id={id} value={value} onChange={event => onChange(event.target.value as T)} disabled={disabled}>
      {options.map(option => <option key={option.id} value={option.id}>{option.label}</option>)}
    </select>
  </Field>;
}

/** Known choices share the catalog; saved values absent from it stay selectable until explicitly removed. */
export function MultiSelectField({ label, value, options, onChange, hint, tip, disabled }: {
  label: string; value: string[]; options: { id: string; label: string }[];
  onChange: (value: string[]) => void; hint?: ReactNode; disabled?: boolean; tip?: string;
}) {
  const L = useL(), id = useId(), menu = useMenu();
  const [query, setQuery] = useState("");
  const [limit, setLimit] = useState(200);
  const selected = [...new Set(value)];
  const choices = [...options, ...selected.filter(item => !options.some(option => option.id === item))
    .map(item => ({ id: item, label: `${item} · ${L("기존 선택", "Saved selection")}` }))];
  const shown = choices.filter(option => `${option.id} ${option.label}`.toLowerCase().includes(query.trim().toLowerCase()));
  const summary = selected.length ? selected.length <= 2 ? selected.map(item => choices.find(option => option.id === item)?.label ?? item).join(", ")
    : L(`${selected.length}개 선택`, `${selected.length} selected`) : L("선택하세요", "Select options");
  return <Field label={label} htmlFor={id} hint={hint} tip={tip}>
    <button type="button" id={id} className="multi-select" disabled={disabled} aria-haspopup="menu" aria-expanded={!!menu.anchor}
      onClick={event => { setQuery(""); setLimit(200); if (menu.anchor) menu.close(); else menu.open(event.currentTarget); }}>
      <span>{summary}</span><Ic name="down" size={16} />
    </button>
    {menu.anchor ? <Menu anchor={menu.anchor} onClose={menu.close} restore={menu.opener} label={label}>
      <div className="menu-search"><Ic name="search" size={16} /><input aria-label={L("선택 항목 검색", "Search options")} value={query} onChange={event => { setQuery(event.target.value); setLimit(200); }} /></div>
      <MenuItem disabled={selected.length === choices.length} onSelect={() => onChange(choices.map(option => option.id))}>{L("모두 선택", "Select all")}</MenuItem>
      <MenuItem disabled={!selected.length} onSelect={() => onChange([])}>{L("모두 해제", "Clear all")}</MenuItem>
      <MenuSep />
      {shown.slice(0, limit).map(option => <MenuItem key={option.id} checked={selected.includes(option.id)}
        onSelect={() => onChange(selected.includes(option.id) ? selected.filter(item => item !== option.id) : [...selected, option.id])}>{option.label}</MenuItem>)}
      {shown.length > limit ? <MenuItem onSelect={() => setLimit(n => n + 200)}>{L(`다음 200개 표시 (${shown.length}개 중 ${limit}개)`, `Show next 200 (${limit} of ${shown.length})`)}</MenuItem> : null}
      {!shown.length ? <MenuItem disabled>{L("검색 결과가 없습니다", "No matching options")}</MenuItem> : null}
    </Menu> : null}
  </Field>;
}

/* ---------- lists ---------- */

/** A filter chip: it opens its choices, and with some chosen a clear button sits beside it; clearing hands focus back to
 * the chip, so the keyboard stays where it was. */
export function FilterChip({ icon, label, count, onOpen, onClear }: {
  icon: IconName; label: string; count: number; onOpen: (anchor: HTMLElement) => void; onClear: () => void;
}) {
  const L = useL();
  const chip = useRef<HTMLButtonElement>(null);
  return <span className={cls("fchip fchip-set", count > 0 && "on")}>
    <button type="button" className="fchip-open" ref={chip} aria-haspopup="menu" onClick={event => onOpen(event.currentTarget)}>
      <Ic name={icon} size={15} /><span className="clip">{label}</span>
      {count ? <span className="filter-count">{count}</span> : <Ic name="down" size={14} />}
    </button>
    {count ? <button type="button" className="x" aria-label={L(`${label} 필터 지우기`, `Clear ${label} filter`)}
      onClick={() => { chip.current?.focus(); onClear(); }}><Ic name="close" size={10} /></button> : null}
  </span>;
}

export function SearchBox({ value, onChange, placeholder, label, id }: { value: string; onChange: (value: string) => void; placeholder: string; label: string; id?: string }) {
  return <label className="search"><Ic name="search" size={17} /><span className="sr">{label}</span>
    <input id={id} value={value} placeholder={placeholder} onChange={event => onChange(event.target.value)} />
  </label>;
}

export function EmptyRow({ colSpan, children }: { colSpan: number; children: ReactNode }) {
  return <tr><td colSpan={colSpan} className="empty-row">{children}</td></tr>;
}

export function Pager({ page, pages, size, onPage, onSize, total }: {
  page: number; pages: number; size: number; onPage: (page: number) => void; onSize: (size: number) => void; total: number;
}) {
  const L = useL();
  const first = total ? page * size + 1 : 0, last = Math.min(total, (page + 1) * size);
  return <div className="pager">
    <span className="num">{first}–{last} / {L(`${total}건`, String(total))}</span>
    <div className="pager-r">
      <label className="pager-size">{L("페이지당", "Per page")}
        <select value={size} onChange={event => onSize(Number(event.target.value))}>
          {[25, 50, 100].map(n => <option key={n} value={n}>{n}</option>)}
        </select>
      </label>
      <span className="pager-btns">
        <button type="button" className="icon-btn" onClick={() => onPage(page - 1)} disabled={page <= 0} aria-label={L("이전 페이지", "Previous page")}><Ic name="left" size={16} /></button>
        <button type="button" className="icon-btn" onClick={() => onPage(page + 1)} disabled={page >= pages - 1} aria-label={L("다음 페이지", "Next page")}><Ic name="right" size={16} /></button>
      </span>
    </div>
  </div>;
}

export function Fact({ label, children, tip }: { label: ReactNode; children: ReactNode; tip?: string }) {
  return <div className="fact"><dt>{label}{tip ? <> <InfoTip text={tip} /></> : null}</dt><dd>{children}</dd></div>;
}

export function Facts({ children }: { children: ReactNode }) {
  return <dl className="facts">{children}</dl>;
}

export function KV({ rows }: { rows: [ReactNode, ReactNode][] }) {
  return <dl className="kv">{rows.map(([key, value], index) => <div key={index} style={{ display: "contents" }}><dt>{key}</dt><dd>{value}</dd></div>)}</dl>;
}

/* ---------- states the design did not draw ---------- */

export function Loading({ label }: { label?: string }) {
  const L = useL();
  return <div className="loading-line" role="status"><span className="spinner" aria-hidden="true" />{label ?? L("불러오는 중", "Loading")}</div>;
}

export function ErrorLine({ children, onRetry }: { children: ReactNode; onRetry?: () => void }) {
  const L = useL();
  return <div className="err-line" role="alert"><Ic name="alert" size={16} /><span>{children}</span>
    {onRetry ? <button type="button" className="link-btn" onClick={onRetry}>{L("다시 시도", "Retry")}</button> : null}
  </div>;
}

export function Empty({ title, children, action }: { title: ReactNode; children?: ReactNode; action?: ReactNode }) {
  return <div className="empty-block"><h3>{title}</h3>{children ? <p>{children}</p> : null}{action}</div>;
}

/* ---------- charts ---------- */

export function Donut({ segments, size = 168, thick = 16, center }: { segments: { value: number; color: string }[]; size?: number; thick?: number; center: ReactNode }) {
  const r = (size - thick) / 2, cx = size / 2, C = 2 * Math.PI * r;
  const total = segments.reduce((sum, s) => sum + s.value, 0) || 1;
  const gap = segments.filter(s => s.value > 0).length > 1 ? 2 : 0;
  let offset = 0;
  return <div className="donut" style={{ width: size, height: size }}>
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden="true">
      <circle cx={cx} cy={cx} r={r} fill="none" stroke="var(--surface-3)" strokeWidth={thick} />
      {segments.map((segment, index) => {
        const length = segment.value / total * C, dash = Math.max(0, length - gap);
        const arc = <circle key={index} cx={cx} cy={cx} r={r} fill="none" stroke={segment.color} strokeWidth={thick}
          strokeDasharray={`${dash} ${C - dash}`} strokeDashoffset={-offset} transform={`rotate(-90 ${cx} ${cx})`} />;
        offset += length;
        return arc;
      })}
    </svg>
    <div className="donut-center">{center}</div>
  </div>;
}

export function Gauge({ percent }: { percent: number }) {
  const W = 210, R = 84, cx = W / 2, cy = 100, length = Math.PI * R;
  const d = `M ${cx - R} ${cy} A ${R} ${R} 0 0 1 ${cx + R} ${cy}`;
  const value = Math.max(0.001, percent / 100) * length;
  return <svg className="gauge-svg" width={W} height="112" viewBox={`0 0 ${W} 112`} aria-hidden="true">
    <path d={d} fill="none" stroke="var(--surface-3)" strokeWidth="16" strokeLinecap="round" />
    <path d={d} fill="none" stroke="var(--ok)" strokeWidth="16" strokeLinecap="round" strokeDasharray={`${value} ${length}`} />
  </svg>;
}

export function Sparkline({ values }: { values: number[] }) {
  const W = 250, H = 90, max = Math.max(...values, 0) + 1, step = values.length > 1 ? W / (values.length - 1) : W;
  const points = values.map((v, i) => [i * step, H - 8 - (v / max) * (H - 20)]);
  const line = points.map((p, i) => `${i ? "L" : "M"}${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join(" ");
  const last = points[points.length - 1] ?? [0, H];
  return <svg width="100%" height={H} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" aria-hidden="true">
    <path d={`${line} L ${W} ${H} L 0 ${H} Z`} fill="var(--primary-soft)" />
    <path d={line} fill="none" stroke="var(--primary)" strokeWidth="2" vectorEffect="non-scaling-stroke" />
    <circle cx={last[0]} cy={last[1]} r="4" fill="var(--primary)" />
  </svg>;
}

export function BarList({ rows, color }: { rows: { key: string; name: ReactNode; value: number }[]; color?: string }) {
  const max = Math.max(1, ...rows.map(row => row.value));
  return <div className="bar-list">
    {rows.map(row => <div className="bar-row" key={row.key}>
      <span className="name">{row.name}</span>
      <span className="bar-track"><span className="bar-fill" style={{ display: "block", width: `${row.value / max * 100}%`, background: color } as CSSProperties} /></span>
      <span className="num">{row.value}</span>
    </div>)}
  </div>;
}
