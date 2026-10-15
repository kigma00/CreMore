"use client";

/* What floats above the page: tooltips, toasts, menus, modals and the details drawer.
 * They keep the design's markup (#tip, #toasts .toast, .menu, .scrim .modal, .drawer) and add
 * keyboard handling: Escape closes, arrows move through a menu, focus stays inside a modal and
 * returns to what opened it. */

import { createContext, type ReactNode, type RefObject, useCallback, useContext, useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

import { Ic, type IconName, Tick } from "@/console/icons";

/* ---------- tooltips: any element with data-tip ---------- */

export function TooltipLayer() {
  const tip = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = tip.current;
    if (!el) return;
    let owner: Element | null = null;
    let leaveTimer: ReturnType<typeof setTimeout> | undefined;
    const cancelLeave = () => clearTimeout(leaveTimer);
    const hide = () => {
      cancelLeave();
      el.hidden = true;
      if (owner) {
        const otherIds = (owner.getAttribute("aria-describedby") ?? "").split(/\s+/).filter(id => id && id !== el.id);
        if (otherIds.length) owner.setAttribute("aria-describedby", otherIds.join(" "));
        else owner.removeAttribute("aria-describedby");
        owner = null;
      }
    };
    const show = (target: Element) => {
      const text = target.getAttribute("data-tip");
      if (!text) return;
      hide();
      owner = target;
      target.setAttribute("aria-describedby", [target.getAttribute("aria-describedby"), el.id].filter(Boolean).join(" "));
      el.textContent = text;
      // Dialog help belongs inside the visible dialog, not across its border or the viewport edge.
      const panel = target.closest(".modal, .drawer")?.getBoundingClientRect();
      const viewport = document.documentElement;
      const left = Math.max(8, panel ? panel.left + 12 : 8), right = Math.min(viewport.clientWidth - 8, panel ? panel.right - 12 : viewport.clientWidth - 8);
      const top = Math.max(8, panel ? panel.top + 12 : 8), bottom = Math.min(viewport.clientHeight - 8, panel ? panel.bottom - 12 : viewport.clientHeight - 8);
      el.style.maxWidth = `${Math.max(0, Math.min(320, right - left))}px`;
      el.style.maxHeight = `${Math.max(0, bottom - top)}px`;
      el.style.left = "0px";
      el.style.top = "0px";
      el.hidden = false;
      // Keep help clear of sibling toggle buttons, including when they wrap on a narrow screen.
      const r = (target.closest(".ig-toggles") ?? target).getBoundingClientRect(), t = el.getBoundingClientRect();
      let x = r.left + r.width / 2 - t.width / 2, y = r.top - t.height - 8;
      if (y < top) y = r.bottom + 8;
      x = Math.max(left, Math.min(x, right - t.width));
      y = Math.max(top, Math.min(y, bottom - t.height));
      el.style.left = `${x}px`;
      el.style.top = `${y}px`;
    };
    const leave = () => { cancelLeave(); leaveTimer = setTimeout(hide, 120); };
    const over = (event: Event) => {
      if (el.contains(event.target as Node)) { cancelLeave(); return; }
      const target = (event.target as Element | null)?.closest?.("[data-tip]");
      if (target) show(target); else leave();
    };
    const focus = (event: Event) => {
      const target = (event.target as Element | null)?.closest?.("[data-tip]");
      if (target) show(target);
    };
    const key = (event: KeyboardEvent) => {
      if (!el.hidden && event.key === "Escape" && !event.isComposing) {
        event.preventDefault(); event.stopPropagation();
      }
      hide();
    };
    const scroll = (event: Event) => { if (event.target !== el) hide(); };
    document.addEventListener("mouseover", over);
    document.addEventListener("mouseout", leave);
    document.addEventListener("focusin", focus);
    document.addEventListener("focusout", hide);
    document.addEventListener("keydown", key, true);
    document.addEventListener("pointerdown", hide);
    window.addEventListener("scroll", scroll, true);
    window.addEventListener("resize", hide);
    window.addEventListener("blur", hide);
    return () => {
      hide();
      document.removeEventListener("mouseover", over);
      document.removeEventListener("mouseout", leave);
      document.removeEventListener("focusin", focus);
      document.removeEventListener("focusout", hide);
      document.removeEventListener("keydown", key, true);
      document.removeEventListener("pointerdown", hide);
      window.removeEventListener("scroll", scroll, true);
      window.removeEventListener("resize", hide);
      window.removeEventListener("blur", hide);
    };
  }, []);
  return <div id="tip" ref={tip} role="tooltip" hidden />;
}

/* ---------- toasts ---------- */

type Toast = { id: number; text: string; tone: "ok" | "bad" };
const ToastContext = createContext<(text: string, tone?: "ok" | "bad") => void>(() => {});

export function useToast() {
  return useContext(ToastContext);
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([]);
  const next = useRef(0);
  const push = useCallback((text: string, tone: "ok" | "bad" = "ok") => {
    const id = ++next.current;
    setItems(list => [...list.slice(-3), { id, text, tone }]);
    window.setTimeout(() => setItems(list => list.filter(item => item.id !== id)), tone === "bad" ? 6000 : 3600);
  }, []);
  return <ToastContext.Provider value={push}>
    {children}
    <div id="toasts" role="status" aria-live="polite">
      {items.map(item => <div className="toast" key={item.id}>
        <Ic name={item.tone === "bad" ? "alert" : "checkCircle"} size={17} /><span>{item.text}</span>
      </div>)}
    </div>
  </ToastContext.Provider>;
}

/* ---------- menus ---------- */

export type MenuAnchor = { x: number; y: number; top: number; right: number; alignRight: boolean };

export function anchorOf(element: Element): MenuAnchor {
  const r = element.getBoundingClientRect();
  return { x: r.left, y: r.bottom + 6, top: r.top, right: r.right, alignRight: r.left > window.innerWidth * 0.55 };
}

type FloatingProps = {
  anchor: MenuAnchor; onClose: () => void; label: string; children: ReactNode; restore?: RefObject<HTMLElement | null>;
};

function FloatingPanel({ anchor, onClose, label, children, restore, kind, id }: FloatingProps & { kind: "menu" | "popover"; id: string }) {
  const menu = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => {
    const el = menu.current;
    if (!el) return;
    const position = () => {
      const W = Math.min(document.documentElement.clientWidth, window.visualViewport?.width ?? window.innerWidth);
      const H = Math.min(document.documentElement.clientHeight, window.visualViewport?.height ?? window.innerHeight);
      if (kind === "popover" && restore?.current) {
        const trigger = restore.current.getBoundingClientRect();
        const owner = restore.current.closest<HTMLElement>(".modal, .drawer");
        const bounds = owner?.getBoundingClientRect();
        const left = Math.max(8, bounds ? bounds.left + 12 : 8);
        const right = Math.min(W - 8, bounds && owner ? bounds.left + owner.clientWidth - 12 : W - 8);
        const bottom = Math.min(H - 8, bounds ? bounds.bottom - 8 : H - 8);
        const top = Math.max(8, bounds ? bounds.top + 8 : 8,
          owner?.querySelector(":scope > .drawer-head")?.getBoundingClientRect().bottom ?? 0);
        const y = trigger.bottom + 6;
        const x = Math.max(left, Math.min(trigger.left, right));
        const width = Math.max(0, Math.min(340, right - x));
        el.style.width = `${width}px`;
        el.style.minWidth = "0px";
        el.style.maxWidth = `${width}px`;
        el.style.maxHeight = `${Math.max(0, Math.min(H * 0.7, bottom - y))}px`;
        el.style.left = `${x}px`;
        el.style.top = `${y}px`;
        // Keep the open state when its trigger scrolls out of view, but never
        // paint its contents over the drawer header or outside the owner.
        el.style.clipPath = `inset(${Math.max(0, top - y)}px 0 0)`;
        el.style.visibility = y >= bottom - 28 || trigger.bottom <= top ? "hidden" : "visible";
        return;
      }
      el.style.maxWidth = `min(340px, ${Math.max(0, W - 16)}px)`;
      el.style.minWidth = `min(230px, ${Math.max(0, W - 16)}px)`;
      el.style.maxHeight = `min(70vh, ${Math.max(0, H - 16)}px)`;
      const r = el.getBoundingClientRect();
      let x = anchor.alignRight ? anchor.right - r.width : anchor.x;
      let y = anchor.y;
      if (x + r.width > W - 8) x = W - r.width - 8;
      if (y + r.height > H - 8) y = Math.max(8, Math.min(H - r.height - 8, anchor.top - r.height - 6));
      el.style.left = `${Math.max(8, x)}px`;
      el.style.top = `${Math.max(8, y)}px`;
    };
    position();
    const first = el.querySelector<HTMLElement>(".menu-search input, .menu-item:not([aria-disabled='true'])");
    (kind === "menu" ? first : el)?.focus({ preventScroll: true });
    const observer = new ResizeObserver(position);
    observer.observe(el);
    if (kind === "popover") {
      if (restore?.current) observer.observe(restore.current);
      const owner = restore?.current?.closest(".modal, .drawer");
      if (owner) observer.observe(owner);
      window.addEventListener("scroll", position, true);
      window.addEventListener("resize", position);
      window.visualViewport?.addEventListener("resize", position);
    }
    return () => {
      observer.disconnect();
      window.removeEventListener("scroll", position, true);
      window.removeEventListener("resize", position);
      window.visualViewport?.removeEventListener("resize", position);
    };
  }, [anchor, kind, restore]);
  useEffect(() => {
    const close = () => { onClose(); restore?.current?.focus({ preventScroll: true }); };
    const down = (event: MouseEvent) => {
      if (menu.current && !menu.current.contains(event.target as Node) && !restore?.current?.contains(event.target as Node)) onClose();
    };
    const key = (event: KeyboardEvent) => {
      // A key that ends or moves what an input method is composing (Korean being typed in the search box) is its own.
      if (event.isComposing) return;
      if (event.key === "Escape") { event.preventDefault(); close(); return; }
      if (kind !== "menu") return;
      if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
      const items = Array.from(menu.current?.querySelectorAll<HTMLElement>(".menu-item:not([aria-disabled='true'])") ?? []);
      if (!items.length) return;
      event.preventDefault();
      const at = items.indexOf(document.activeElement as HTMLElement);
      const next = event.key === "ArrowDown" ? (at + 1) % items.length : (at - 1 + items.length) % items.length;
      items[next].focus();
    };
    const scroll = (event: Event) => {
      if (!menu.current || menu.current.contains(event.target as Node)) return;
      onClose();
    };
    document.addEventListener("mousedown", down);
    document.addEventListener("keydown", key);
    if (kind === "menu") {
      window.addEventListener("scroll", scroll, true);
      window.addEventListener("resize", onClose);
      window.visualViewport?.addEventListener("resize", onClose);
    }
    return () => {
      document.removeEventListener("mousedown", down);
      document.removeEventListener("keydown", key);
      window.removeEventListener("scroll", scroll, true);
      window.removeEventListener("resize", onClose);
      window.visualViewport?.removeEventListener("resize", onClose);
    };
  }, [onClose, restore, kind]);
  return createPortal(<div className={kind === "menu" ? "menu" : "menu detail-popover"} id={id}
    role={kind === "menu" ? "menu" : "dialog"} tabIndex={kind === "popover" ? -1 : undefined} aria-label={label} ref={menu}>{children}</div>,
    restore?.current?.closest(kind === "popover" ? ".modal, .drawer" : ".modal") ?? document.body);
}

export function Menu(props: FloatingProps) {
  return <FloatingPanel {...props} kind="menu" id="menu" />;
}

/** Read-only details overlay directly below their trigger without moving surrounding fields. */
export function DetailPopover({ label, children }: { label: string; children: ReactNode }) {
  const popover = useMenu();
  const id = useId();
  const open = (element: HTMLButtonElement) => {
    const height = window.visualViewport?.height ?? document.documentElement.clientHeight;
    if (!popover.anchor) {
      const owner = element.closest<HTMLElement>(".modal, .drawer");
      const bounds = owner?.getBoundingClientRect(), trigger = element.getBoundingClientRect();
      const top = Math.max(8, bounds?.top ?? 0, owner?.querySelector(":scope > .drawer-head")?.getBoundingClientRect().bottom ?? 0);
      const bottom = Math.min(height - 8, bounds?.bottom ?? height);
      const room = Math.min(200, Math.max(0, bottom - top) / 2);
      // Keep mobile triggers below the sticky drawer header while making room.
      const offset = trigger.top < top ? trigger.top - top - 12
        : trigger.bottom > bottom - room ? trigger.bottom - bottom + room : 0;
      if (offset) (owner ?? window).scrollBy({ top: offset, behavior: "instant" });
    }
    popover.open(element);
  };
  return <>
    <button type="button" className="link-btn record-summary" aria-haspopup="dialog" aria-expanded={!!popover.anchor}
      aria-controls={popover.anchor ? id : undefined} onClick={event => open(event.currentTarget)}>
      {label}<Ic name="down" size={12} />
    </button>
    {popover.anchor ? <FloatingPanel kind="popover" id={id} anchor={popover.anchor} onClose={popover.close}
      restore={popover.opener} label={label}>{children}</FloatingPanel> : null}
  </>;
}

export function MenuItem({ icon, children, onSelect, disabled, tip, end, className, checked }: {
  icon?: IconName; children: ReactNode; onSelect?: () => void; disabled?: boolean; tip?: string; end?: ReactNode;
  className?: string; checked?: boolean;
}) {
  return <button type="button" role={checked === undefined ? "menuitem" : "menuitemcheckbox"} aria-checked={checked}
    className={className ? `menu-item ${className}` : "menu-item"} aria-disabled={disabled || undefined} data-tip={tip}
    onClick={() => { if (!disabled) onSelect?.(); }}>
    {checked !== undefined ? <span className={checked ? "check on" : "check"}>{checked ? <Tick /> : null}</span>
      : icon ? <Ic name={icon} size={17} /> : null}
    <span className="mi-text">{children}</span>
    {end ? <span className="end">{end}</span> : null}
  </button>;
}

export function MenuSep() { return <div className="menu-sep" role="separator" />; }
export function MenuLabel({ children }: { children: ReactNode }) { return <div className="menu-label">{children}</div>; }

/** Open/close state for one menu, remembering the button that opened it. */
export function useMenu() {
  const [anchor, setAnchor] = useState<MenuAnchor | null>(null);
  const opener = useRef<HTMLElement | null>(null);
  const open = useCallback((element: HTMLElement) => { opener.current = element; setAnchor(current => current ? null : anchorOf(element)); }, []);
  const close = useCallback(() => setAnchor(null), []);
  return { anchor, open, close, opener };
}

/* ---------- modals ---------- */

// A <details> heading (summary) takes focus too, so Tab moves on from it inside the dialog.
const FOCUSABLE = "button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), summary, [tabindex]:not([tabindex='-1'])";

export function Modal({ onClose, labelledBy, size, className, children, dismissable = true }: {
  onClose: () => void; labelledBy: string; size?: "wide" | "narrow"; className?: string; children: ReactNode; dismissable?: boolean;
}) {
  const box = useRef<HTMLDivElement>(null);
  // The latest close and dismissable, read when a key comes: a re-render (a list polling behind the modal) must
  // not run the effect below again and pull focus back to the first field.
  const latest = useRef({ onClose, dismissable });
  useEffect(() => { latest.current = { onClose, dismissable }; });
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    const el = box.current;
    const first = el?.querySelector<HTMLElement>("[data-autofocus]") ?? el?.querySelector<HTMLElement>(FOCUSABLE);
    first?.focus({ preventScroll: true });
    const key = (event: KeyboardEvent) => {
      // An Escape that ends what an input method is composing (Korean being typed in a field) leaves the dialog open.
      if (event.key === "Escape" && !event.defaultPrevented && !event.isComposing && !el?.querySelector(".menu") && latest.current.dismissable) { event.preventDefault(); latest.current.onClose(); return; }
      if (event.key !== "Tab" || !el) return;
      const items = Array.from(el.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(item => item.offsetParent !== null);
      if (!items.length) return;
      const at = items.indexOf(document.activeElement as HTMLElement), last = items.length - 1;
      // Focus on none of them (fallen out of the dialog, or on a control just disabled or removed): Tab comes back
      // in. Among them, only the ends wrap; the browser moves focus between the rest.
      const next = at < 0 ? (event.shiftKey ? last : 0) : event.shiftKey && at === 0 ? last : !event.shiftKey && at === last ? 0 : -1;
      if (next >= 0) { event.preventDefault(); items[next].focus(); }
    };
    document.addEventListener("keydown", key);
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", key);
      document.body.style.overflow = overflow;
      previous?.focus?.({ preventScroll: true });
    };
  }, []);
  const classes = ["modal", size, className].filter(Boolean).join(" ");
  return createPortal(<div className="scrim" onMouseDown={event => { if (dismissable && event.target === event.currentTarget) onClose(); }}>
    <div className={classes} role="dialog" aria-modal="true" aria-labelledby={labelledBy} ref={box}>{children}</div>
  </div>, document.body);
}

/* ---------- keyboard ---------- */

/** "/" opens search from anywhere outside a text field. */
export function useSlashKey(open: () => void) {
  const ref = useRef(open);
  ref.current = open;
  useEffect(() => {
    const key = (event: KeyboardEvent) => {
      if (event.key !== "/" || event.metaKey || event.ctrlKey || event.altKey) return;
      const target = event.target as HTMLElement | null;
      if (target && (target.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName))) return;
      event.preventDefault();
      ref.current();
    };
    document.addEventListener("keydown", key);
    return () => document.removeEventListener("keydown", key);
  }, []);
}

/* ---------- details drawer ---------- */

// Inputs that take no typing: a key on one is not text being written.
const UNTYPED = new Set(["button", "checkbox", "color", "file", "hidden", "image", "radio", "range", "reset", "submit"]);
/** A text field: a text input, a text area or editable content. */
const typedInto = (el: HTMLElement) => el.isContentEditable || el.tagName === "TEXTAREA" || (el instanceof HTMLInputElement && !UNTYPED.has(el.type));

export function Drawer({ label, children, onClose }: { label: string; children: ReactNode; onClose: () => void }) {
  const panel = useRef<HTMLElement>(null);
  const [host, setHost] = useState<HTMLElement | null>(null);
  useEffect(() => { setHost(document.body); }, []);
  // The latest close, read when a key comes: a parent's re-render (a list polling behind the panel) must not subscribe
  // the panel again, after a modal's own listener.
  const close = useRef(onClose);
  useEffect(() => { close.current = onClose; });
  useEffect(() => {
    if (!host) return;
    document.body.classList.add("drawer-open");
    // Opened with nothing focused (the control that opened it is gone, as a search result is): the panel takes focus,
    // so Tab and Escape start from it.
    if (!document.activeElement || document.activeElement === document.body) panel.current?.focus({ preventScroll: true });
    const key = (event: KeyboardEvent) => {
      // A modal or menu above it took this Escape (both prevent its default), or it ends what an input method was
      // composing (Korean being typed): the panel stays.
      if (event.key !== "Escape" || event.defaultPrevented || event.isComposing || document.querySelector(".scrim, .menu")) return;
      // Escape in a text field beside the panel is the field's (a search being typed): the panel stays. Anywhere else
      // -- in the panel, on the row that opened it, nowhere -- it closes the panel.
      const active = document.activeElement as HTMLElement | null;
      if (active && !panel.current?.contains(active) && typedInto(active)) return;
      event.preventDefault();
      close.current();
    };
    document.addEventListener("keydown", key);
    return () => { document.body.classList.remove("drawer-open"); document.removeEventListener("keydown", key); };
  }, [host]);
  return host ? createPortal(<aside className="drawer" id="drawer" aria-label={label} ref={panel} tabIndex={-1}>{children}</aside>, host) : null;
}
