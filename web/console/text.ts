"use client";

/* The console's words and dates.
 *
 * Every visible string is written where it is used, Korean first: L("한국어", "English").
 * Dates follow the display timezone preference (KST by default) and the chosen language.
 */

import { useCallback } from "react";

import { getDisplayTimezone, type DisplayTimezone } from "@/components/display-timezone";
import { type Locale, useLocale } from "@/components/locale";

export type Say = (ko: string, en: string) => string;

/** A word with the Korean particle it takes: 은/는, 이/가, 을/를 or 과/와 by whether it ends in a final
 * consonant; a word that does not end in Hangul keeps both forms, as "은(는)". */
export function josa(word: string, pair: "은/는" | "이/가" | "을/를" | "과/와"): string {
  const [withFinal, without] = pair.split("/");
  const code = word.charCodeAt(word.length - 1);
  if (!(code >= 0xac00 && code <= 0xd7a3)) return `${word}${withFinal}(${without})`;
  return word + ((code - 0xac00) % 28 ? withFinal : without);
}

/** Rows as CSV text. A cell that opens with = + - @ would run as a spreadsheet formula, so it is kept as text. */
export function csvText(rows: (string | number | null | undefined)[][]): string {
  const cell = (value: string | number | null | undefined) => {
    const text = String(value ?? "");
    const safe = /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
    return /[",\r\n]/.test(safe) ? `"${safe.replaceAll("\"", "\"\"")}"` : safe;
  };
  return rows.map(row => row.map(cell).join(",")).join("\r\n");
}

function save(filename: string, blob: Blob) {
  const link = document.createElement("a");
  const href = URL.createObjectURL(blob);
  link.href = href;
  link.download = filename;
  link.click();
  // Some browsers start the download after click() returns: the URL is released a while later.
  window.setTimeout(() => URL.revokeObjectURL(href), 30_000);
}

/** Save rows as a CSV file (with a byte order mark, so spreadsheets read Korean as UTF-8). */
export function downloadCsv(filename: string, rows: (string | number | null | undefined)[][]) {
  save(filename, new Blob(["\uFEFF" + csvText(rows)], { type: "text/csv;charset=utf-8" }));
}

/** Save a value the API served as an indented JSON file. */
export function downloadJson(filename: string, value: unknown) {
  save(filename, new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }));
}

export function sayIn(locale: Locale): Say {
  return (ko, en) => (locale === "en" ? en : ko);
}

export function useL(): Say {
  const locale = useLocale();
  return useCallback((ko: string, en: string) => (locale === "en" ? en : ko), [locale]);
}

export const DAY = 86_400_000;
const MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

export function time(value: string | null | undefined): number | null {
  if (!value || value.startsWith("0001-")) return null;
  const at = Date.parse(value);
  return Number.isFinite(at) ? at : null;
}

function parts(at: number, zone: DisplayTimezone) {
  const timeZone = zone === "LOCAL" ? undefined : zone;
  const values = Object.fromEntries(new Intl.DateTimeFormat("en-US", {
    timeZone, year: "numeric", month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit", hourCycle: "h23",
  }).formatToParts(new Date(at)).map(part => [part.type, part.value]));
  return { y: Number(values.year), m: Number(values.month), d: Number(values.day), hh: values.hour, mm: values.minute };
}

/** "9월 27일" / "Sep 27", with the year when it is not this year. */
export function fmtDay(value: string | null | undefined, locale: Locale, zone: DisplayTimezone = getDisplayTimezone(), now = Date.now()): string {
  const at = time(value);
  if (at === null) return "—";
  // A provider's date-only fact has no instant; keep it as the calendar day it names.
  const dateOnly = typeof value === "string" && /^\d{4}-\d{2}-\d{2}$/.test(value);
  const p = dateOnly ? { y: Number(value!.slice(0, 4)), m: Number(value!.slice(5, 7)), d: Number(value!.slice(8, 10)) } : parts(at, zone);
  const thisYear = parts(now, zone).y;
  if (locale === "en") return `${MON[p.m - 1]} ${p.d}${p.y !== thisYear ? `, ${p.y}` : ""}`;
  return `${p.y !== thisYear ? `${p.y}년 ` : ""}${p.m}월 ${p.d}일`;
}

/** "9월 27일 10:00". */
export function fmtDT(value: string | null | undefined, locale: Locale, zone: DisplayTimezone = getDisplayTimezone(), now = Date.now()): string {
  const at = time(value);
  if (at === null) return "—";
  const p = parts(at, zone);
  return `${fmtDay(value, locale, zone, now)} ${p.hh}:${p.mm}`;
}

/** "3시간 전" / "3h ago"; future times read "3일 후" / "in 3d". */
export function rel(value: string | null | undefined, locale: Locale, now = Date.now()): string {
  const at = time(value);
  if (at === null) return "—";
  const diff = now - at, ahead = diff < 0, span = Math.abs(diff);
  const L = sayIn(locale);
  if (span < 3_600_000) {
    const m = Math.max(1, Math.round(span / 60_000));
    return ahead ? L(`${m}분 후`, `in ${m}m`) : L(`${m}분 전`, `${m}m ago`);
  }
  if (span < DAY) {
    const h = Math.round(span / 3_600_000);
    return ahead ? L(`${h}시간 후`, `in ${h}h`) : L(`${h}시간 전`, `${h}h ago`);
  }
  const d = Math.round(span / DAY);
  return ahead ? L(`${d}일 후`, `in ${d}d`) : L(`${d}일 전`, `${d}d ago`);
}

export function daysLeft(value: string | null | undefined, now = Date.now()): number | null {
  const at = time(value);
  return at === null ? null : Math.ceil((at - now) / DAY);
}

/** "3건" / "3". */
export function cnt(n: number, locale: Locale): string {
  return locale === "en" ? String(n) : `${n}건`;
}

export function num(n: number, locale: Locale): string {
  return new Intl.NumberFormat(locale === "en" ? "en-US" : "ko-KR").format(n);
}

/** One word per enumeration code a screen shows, both languages, falling back to the code. */
export function codeText(code: string | null | undefined, table: Record<string, [string, string]>, locale: Locale): string {
  if (!code) return "—";
  const found = table[code];
  if (found) return locale === "en" ? found[1] : found[0];
  return code.toLowerCase().replaceAll("_", " ").replace(/^./, letter => letter.toUpperCase());
}
