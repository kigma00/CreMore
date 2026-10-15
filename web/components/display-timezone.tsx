"use client";

import { useSyncExternalStore } from "react";

export type DisplayTimezone = "UTC" | "Asia/Seoul" | "LOCAL";
export const displayTimezoneStorageKey = "cremore.display-timezone.v1";
const defaultTimezone: DisplayTimezone = "Asia/Seoul";
let currentTimezone: DisplayTimezone = defaultTimezone;
const listeners = new Set<() => void>();

export function isDisplayTimezone(value: unknown): value is DisplayTimezone {
  return value === "UTC" || value === "Asia/Seoul" || value === "LOCAL";
}

function publish(value: DisplayTimezone) {
  if (currentTimezone === value) return;
  currentTimezone = value;
  listeners.forEach(listener => listener());
}

function readPreference() {
  try {
    const value = window.localStorage.getItem(displayTimezoneStorageKey);
    publish(isDisplayTimezone(value) ? value : defaultTimezone);
  } catch { /* Storage is optional; retain the in-memory preference. */ }
}

function storageChanged(event: StorageEvent) {
  if (event.key === displayTimezoneStorageKey || event.key === null) readPreference();
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  if (listeners.size === 1) {
    window.addEventListener("storage", storageChanged);
    // Read after hydration so server HTML and the first client render agree.
    readPreference();
  }
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0) window.removeEventListener("storage", storageChanged);
  };
}

export function getDisplayTimezone(): DisplayTimezone {
  return typeof window === "undefined" ? defaultTimezone : currentTimezone;
}

export function setDisplayTimezone(value: unknown) {
  if (!isDisplayTimezone(value) || typeof window === "undefined") return;
  publish(value);
  try { window.localStorage.setItem(displayTimezoneStorageKey, value); } catch { /* Device preference is optional. */ }
}

// The dashboard subscribes once at its existing root, preserving child identity,
// selected rows, open views and unsaved form state when all dates are redrawn.
export function useDisplayTimezone() {
  return useSyncExternalStore(subscribe, getDisplayTimezone, () => defaultTimezone);
}

export function formatDisplayTimestamp(value: string | undefined | null, locale: "ko" | "en", timeStyle: "short" | "medium" = "short", zone: DisplayTimezone = getDisplayTimezone()): string {
  if (!value || value.startsWith("0001-") || !Number.isFinite(Date.parse(value))) return "—";
  // A date-only provider fact has no instant or timezone: preserve its precision.
  if (/^\d{4}-\d{2}-\d{2}$/.test(value)) return new Date(value).toISOString().slice(0, 10) === value ? value : "—";
  const timeZone = zone === "LOCAL" ? Intl.DateTimeFormat().resolvedOptions().timeZone : zone;
  const label = zone === "Asia/Seoul" ? "KST" : zone === "LOCAL" ? timeZone || (locale === "ko" ? "기기 현지" : "Device local") : "UTC";
  return `${new Intl.DateTimeFormat(locale === "ko" ? "ko-KR" : "en-US", { dateStyle: "medium", timeStyle, timeZone }).format(new Date(value))} ${label}`;
}
