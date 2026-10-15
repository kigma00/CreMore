/* The console's line icons (24px grid, 1.8 stroke), drawn once as path markup.
 * Only these constant strings are injected; nothing from the API reaches an icon. */

const ICONS = {
  grid: '<path d="M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="M11 12l8-8M16 7l2 2M14 9l2 2"/>',
  alert: '<path d="M12 4l9 16H3z"/><path d="M12 10v4M12 17.5v.01"/>',
  token: '<rect x="3.5" y="6.5" width="17" height="11" rx="2"/><path d="M7.5 10.5h9M7.5 13.5h5"/>',
  api: '<path d="M8 5c-2 0-2 1.5-2 3s0 3-2 4c2 1 2 2.5 2 4s0 3 2 3M16 5c2 0 2 1.5 2 3s0 3 2 4c-2 1-2 2.5-2 4s0 3-2 3"/>',
  cloud: '<path d="M7 18h10a4 4 0 0 0 .6-7.95A6 6 0 0 0 6.2 9.2 4.4 4.4 0 0 0 7 18z"/>',
  vault: '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3M12 15v2"/>',
  activity: '<path d="M3 12h4l3-7 4 14 3-7h4"/>',
  plug: '<path d="M9 7V3M15 7V3M6 7h12v4a6 6 0 0 1-12 0zM12 17v4"/>',
  search: '<circle cx="11" cy="11" r="6"/><path d="M20 20l-4.5-4.5"/>',
  book: '<path d="M5 4.5A1.5 1.5 0 0 1 6.5 3H19v15H6.5A1.5 1.5 0 0 0 5 19.5zM5 19.5A1.5 1.5 0 0 0 6.5 21H19"/>',
  bell: '<path d="M6 16v-5a6 6 0 0 1 12 0v5l1.5 2h-15zM10 20a2 2 0 0 0 4 0"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M4.6 4.6l1.4 1.4M18 18l1.4 1.4M2.5 12h2M19.5 12h2M4.6 19.4L6 18M18 6l1.4-1.4"/>',
  moon: '<path d="M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z"/>',
  monitor: '<rect x="3" y="4.5" width="18" height="11.5" rx="1.5"/><path d="M8.5 20h7M12 16v4"/>',
  dots: '<circle cx="12" cy="5" r="1.4" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r="1.4" fill="currentColor" stroke="none"/><circle cx="12" cy="19" r="1.4" fill="currentColor" stroke="none"/>',
  close: '<path d="M6 6l12 12M18 6L6 18"/>',
  panelClose: '<path d="M4 12h11M10.5 7.5L15 12l-4.5 4.5M20 5v14"/>',
  down: '<path d="M6 9l6 6 6-6"/>',
  up: '<path d="M6 15l6-6 6 6"/>',
  right: '<path d="M9 6l6 6-6 6"/>',
  left: '<path d="M15 6l-6 6 6 6"/>',
  first: '<path d="M17 6l-6 6 6 6M7 6v12"/>',
  last: '<path d="M7 6l6 6-6 6M17 6v12"/>',
  copy: '<rect x="9" y="9" width="11" height="11" rx="1.5"/><path d="M5.5 15H4.5A.5.5 0 0 1 4 14.5V4.5A.5.5 0 0 1 4.5 4h10a.5.5 0 0 1 .5.5v1"/>',
  filter: '<path d="M4 6h16M7 12h10M10 18h4"/>',
  star: '<path d="M12 3.5l2.6 5.3 5.9.9-4.3 4.1 1 5.8L12 16.9l-5.2 2.7 1-5.8-4.3-4.1 5.9-.9z"/>',
  columns: '<rect x="4" y="5" width="16" height="14" rx="1.5"/><path d="M10 5v14M15 5v14"/>',
  download: '<path d="M12 4v11M7 10l5 5 5-5M5 20h14"/>',
  send: '<path d="M4.5 11.5L20 4l-5.5 16-3-6.5z"/><path d="M11.5 13.5L20 4"/>',
  user: '<circle cx="12" cy="8" r="3.5"/><path d="M5 20a7 7 0 0 1 14 0"/>',
  users: '<circle cx="9" cy="8" r="3"/><path d="M3 19a6 6 0 0 1 12 0M16 5.5a3 3 0 0 1 0 5.8M17.5 14a5.5 5.5 0 0 1 3.5 5"/>',
  userPlus: '<circle cx="10" cy="8" r="3.5"/><path d="M3 20a7 7 0 0 1 12.5-4.3M18 14v6M15 17h6"/>',
  userMinus: '<circle cx="10" cy="8" r="3.5"/><path d="M3 20a7 7 0 0 1 12.5-4.3M15 17h6"/>',
  tag: '<path d="M3.5 12V4.5a1 1 0 0 1 1-1H12l8.5 8.5-8 8z"/><circle cx="8" cy="8" r="1.4"/>',
  comment: '<path d="M4 5h16v11H9l-5 4z"/>',
  webhook: '<circle cx="12" cy="6" r="2.5"/><circle cx="6" cy="17" r="2.5"/><circle cx="18" cy="17" r="2.5"/><path d="M11 8.5l-3.8 6.3M13 8.5l3.8 6.3M8.5 17h7"/>',
  checkCircle: '<circle cx="12" cy="12" r="9"/><path d="M8 12.5l2.7 2.7L16 10"/>',
  minusCircle: '<circle cx="12" cy="12" r="9"/><path d="M8 12h8"/>',
  halfCircle: '<circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 0 1 0 18z" fill="currentColor" stroke="none"/>',
  xCircle: '<circle cx="12" cy="12" r="9"/><path d="M9 9l6 6M15 9l-6 6"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  shield: '<path d="M12 2.4L20 5.4V12c0 4.9-3.4 7.5-8 9.4C7.4 19.5 4 16.9 4 12V5.4z"/><circle cx="12" cy="10.4" r="2.3" fill="currentColor" stroke="none"/><path d="M12 12.5v2.9"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 7.6v.01"/>',
  wand: '<path d="M4.5 19.5l10-10M14 3.5l.9 1.9 1.9.9-1.9.9-.9 1.9-.9-1.9-1.9-.9 1.9-.9zM19 11.5l.6 1.2 1.2.6-1.2.6-.6 1.2-.6-1.2-1.2-.6 1.2-.6z"/>',
  pencil: '<path d="M4 20l4-1 11-11-3-3L5 16zM14 6l3 3"/>',
  trash: '<path d="M4.5 7h15M9.5 7V4.5h5V7M6.5 7l1 13h9l1-13M10 11v5M14 11v5"/>',
  expand: '<path d="M14 4h6v6M20 4l-7 7M10 20H4v-6M4 20l7-7"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  minus: '<path d="M5 12h14"/>',
  fit: '<path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/><circle cx="12" cy="12" r="1.3" fill="currentColor" stroke="none"/>',
  ext: '<path d="M14 4h6v6M20 4l-9 9M18 14v6H4V6h6"/>',
  scan: '<path d="M4 8V5.5A1.5 1.5 0 0 1 5.5 4H8M16 4h2.5A1.5 1.5 0 0 1 20 5.5V8M20 16v2.5a1.5 1.5 0 0 1-1.5 1.5H16M8 20H5.5A1.5 1.5 0 0 1 4 18.5V16M4 12h16"/>',
  sliders: '<path d="M4 7h9M17 7h3M4 17h3M11 17h9M15 5v4M9 15v4"/>',
  list: '<path d="M9 6h11M9 12h11M9 18h11M4.5 6h.01M4.5 12h.01M4.5 18h.01"/>',
  bolt: '<path d="M13 3L5 14h6l-1 7 8-11h-6z"/>',
  git: '<circle cx="6" cy="6" r="2"/><circle cx="6" cy="18" r="2"/><circle cx="18" cy="8" r="2"/><path d="M6 8v8M18 10c0 4-6 3-10.2 6.6"/>',
  page: '<path d="M6 3h9l4 4v14H6zM14 3v5h5"/>',
  bucket: '<ellipse cx="12" cy="6.5" rx="8" ry="2.8"/><path d="M4 6.5l1.8 11.5c.3 1.8 3 3 6.2 3s5.9-1.2 6.2-3L20 6.5"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.8 3.5 5.8 3.5 9s-1 6.2-3.5 9c-2.5-2.8-3.5-5.8-3.5-9S9.5 5.8 12 3z"/>',
  lockOpen: '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 7.6-1.7"/>',
  hourglass: '<path d="M7 3h10M7 21h10M8 3c0 5 8 5 8 9s-8 4-8 9M16 3c0 5-8 5-8 9"/>',
  sleep: '<path d="M4 12a8 8 0 1 0 16 0M9 5h4l-4 5h4M15 3h3l-3 4h3"/>',
  userQ: '<circle cx="10" cy="8" r="3.5"/><path d="M3 20a7 7 0 0 1 11-5.7M17 15.5a2 2 0 1 1 2.6 1.9c-.4.1-.6.4-.6.8v.3M19 21v.01"/>',
  history: '<path d="M4 12a8 8 0 1 0 2.4-5.7M4 4v4h4M12 8v4l3 2"/>',
  refresh: '<path d="M20 12a8 8 0 0 1-13.7 5.7M4 12a8 8 0 0 1 13.7-5.7M18 3v4h-4M6 21v-4h4"/>',
  pause: '<rect x="6.5" y="5" width="3.5" height="14" rx="1"/><rect x="14" y="5" width="3.5" height="14" rx="1"/>',
  play: '<path d="M8 5l11 7-11 7z"/>',
  stop: '<rect x="6" y="6" width="12" height="12" rx="1.5"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="M12 2.5v3M12 18.5v3M2.5 12h3M18.5 12h3M5.3 5.3l2.1 2.1M16.6 16.6l2.1 2.1M5.3 18.7l2.1-2.1M16.6 7.4l2.1-2.1"/>',
  server: '<rect x="4" y="4" width="16" height="7" rx="1.5"/><rect x="4" y="13" width="16" height="7" rx="1.5"/><path d="M7.5 7.5h.01M7.5 16.5h.01"/>',
  checkList: '<path d="M10 6h10M10 12h10M10 18h10M4 6l1.5 1.5L8 5M4 12l1.5 1.5L8 11M4 18l1.5 1.5L8 17"/>',
  lock: '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
  building: '<path d="M4 20V5.5L12 3v17M12 8l8 2.5V20M3 20h18M7.5 8h1M7.5 11.5h1M7.5 15h1M15.5 13h1M15.5 16h1"/>',
  flag: '<path d="M5 21V4M5 4h11l-2 4 2 4H5"/>',
  logout: '<path d="M14 4h4.5A1.5 1.5 0 0 1 20 5.5v13a1.5 1.5 0 0 1-1.5 1.5H14M10 16l-4-4 4-4M6 12h10"/>',
} as const;

export type IconName = keyof typeof ICONS;

/** The design's check mark inside a .check box (heavier stroke than the line icons). */
export function Tick() {
  return <svg width="11" height="11" viewBox="0 0 24 24" className="ic" style={{ strokeWidth: 3 }} aria-hidden="true">
    <path d="M5 12.5l4.5 4.5L19 7.5" />
  </svg>;
}

export function Ic({ name, size = 18, className }: { name: IconName; size?: number; className?: string }) {
  return <svg className={className ? `ic ${className}` : "ic"} width={size} height={size} viewBox="0 0 24 24"
    aria-hidden="true" dangerouslySetInnerHTML={{ __html: ICONS[name] }} />;
}
