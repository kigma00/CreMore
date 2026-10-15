const test = require("node:test"), assert = require("node:assert/strict");
const { load, formatDisplayTimestamp: format } = require("./load-display-timezone.cjs");

test("display instants support UTC KST and local without rewriting provider facts", () => {
  const fact = Object.freeze({ at: "2026-09-10T18:30:00Z", observed_at: "2026-09-10T19:00:00Z" });
  assert.match(format(fact.at, "en", "short", "UTC"), /Sep 10, 2026, 6:30 PM UTC/);
  assert.match(format(fact.at, "en", "short", "Asia/Seoul"), /Sep 11, 2026, 3:30 AM KST/);
  const local = Intl.DateTimeFormat().resolvedOptions().timeZone;
  assert.ok(format(fact.at, "ko", "medium", "LOCAL").endsWith(local));
  assert.equal(fact.at, "2026-09-10T18:30:00Z"); assert.equal(fact.observed_at, "2026-09-10T19:00:00Z");
});

test("date-only evidence keeps provider precision in all display zones", () => {
  for (const zone of ["UTC", "Asia/Seoul", "LOCAL"]) for (const locale of ["ko", "en"]) {
    assert.equal(format("2026-09-10", locale, "short", zone), "2026-09-10");
    for (const value of [null, "", "invalid", "0001-01-01T00:00:00Z", "2026-02-30"]) assert.equal(format(value, locale, "short", zone), "—");
  }
});

function store(initial, blocked = false) {
  const values = new Map(initial == null ? [] : [["cremore.display-timezone.v1", initial]]), events = new Map(), subscriptions = [], notifications = [];
  const fakeWindow = { localStorage: { getItem: key => { if (blocked) throw Error("blocked"); return values.get(key) ?? null; }, setItem: (key, value) => { if (blocked) throw Error("blocked"); values.set(key, value); } }, addEventListener: (key, listener) => { events.set(key, listener); }, removeEventListener: (key, listener) => { if (events.get(key) === listener) events.delete(key); } };
  const ui = load({ window: fakeWindow, require: name => name === "react" ? { useSyncExternalStore: (subscribe, snapshot, serverSnapshot) => { subscriptions.push(subscribe); return { current: snapshot(), server: serverSnapshot() }; } } : require(name) });
  return { ui, values, events, subscriptions, notifications };
}

test("validated versioned preference hydrates deterministically and uses one storage listener", () => {
  const s = store("UTC");
  assert.deepEqual({ ...s.ui.useDisplayTimezone() }, { current: "Asia/Seoul", server: "Asia/Seoul" });
  const removeA = s.subscriptions[0](() => s.notifications.push(s.ui.getDisplayTimezone()));
  s.ui.useDisplayTimezone(); const removeB = s.subscriptions[1](() => {});
  assert.equal(s.ui.getDisplayTimezone(), "UTC"); assert.equal(s.events.size, 1);
  for (const zone of ["Asia/Seoul", "UTC", "LOCAL"]) { s.ui.setDisplayTimezone(zone); assert.equal(s.values.get(s.ui.displayTimezoneStorageKey), zone); assert.equal(s.ui.getDisplayTimezone(), zone); }
  s.ui.setDisplayTimezone("untrusted-zone"); assert.equal(s.ui.getDisplayTimezone(), "LOCAL");
  s.values.set(s.ui.displayTimezoneStorageKey, "UTC"); s.events.get("storage")({ key: s.ui.displayTimezoneStorageKey }); assert.equal(s.ui.getDisplayTimezone(), "UTC");
  s.values.delete(s.ui.displayTimezoneStorageKey); s.events.get("storage")({ key: null }); assert.equal(s.ui.getDisplayTimezone(), "Asia/Seoul");
  removeA(); assert.equal(s.events.size, 1); removeB(); assert.equal(s.events.size, 0);
});

test("invalid or blocked storage keeps a usable non-secret display preference", () => {
  for (const input of ["Mars", "{broken", "Asia/Tokyo"]) { const s = store(input); s.ui.useDisplayTimezone(); s.subscriptions[0](() => {}); assert.equal(s.ui.getDisplayTimezone(), "Asia/Seoul"); }
  const s = store(null, true); s.ui.useDisplayTimezone(); const cleanup = s.subscriptions[0](() => {}); s.ui.setDisplayTimezone("UTC"); assert.equal(s.ui.getDisplayTimezone(), "UTC"); cleanup();
});
