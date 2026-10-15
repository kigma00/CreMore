"use client";

import { useSyncExternalStore } from "react";
import { themeStorageKey } from "@/lib/theme-script";

// Display theme: follow the operating system, or a per-device choice. The
// choice is applied as `data-theme` on <html>; the console's stylesheet does the rest.
export type ThemePreference = "system" | "light" | "dark";
const listeners = new Set<() => void>();
let current: ThemePreference = "system";

export function isThemePreference(value: unknown): value is ThemePreference {
  return value === "system" || value === "light" || value === "dark";
}

function apply(value: ThemePreference) {
  const root = document.documentElement;
  if (value === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", value);
}

function publish(value: ThemePreference) {
  if (current === value) return;
  current = value;
  listeners.forEach(listener => listener());
}

function readPreference() {
  try {
    const value = window.localStorage.getItem(themeStorageKey);
    const next = value === "dark" || value === "light" ? value : "system";
    apply(next);
    publish(next);
  } catch { /* Storage is optional; the operating-system theme still applies. */ }
}

function storageChanged(event: StorageEvent) {
  if (event.key === themeStorageKey || event.key === null) readPreference();
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  if (listeners.size === 1) {
    window.addEventListener("storage", storageChanged);
    readPreference();
  }
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0) window.removeEventListener("storage", storageChanged);
  };
}

export function setThemePreference(value: unknown) {
  if (!isThemePreference(value) || typeof window === "undefined") return;
  apply(value);
  publish(value);
  try {
    if (value === "system") window.localStorage.removeItem(themeStorageKey);
    else window.localStorage.setItem(themeStorageKey, value);
  } catch { /* Device preference is optional. */ }
}

export function useThemePreference() {
  return useSyncExternalStore(subscribe, () => current, () => "system" as ThemePreference);
}
