/* Reading an RE2 pattern for people. The pattern splits into pieces (text, character sets, repeats,
 * groups) that each say what they mean, and into one line of plain words for the value it reports.
 * The same tree builds a synthetic value in the pattern's shape, and a browser RegExp approximates
 * the pattern so a sample is tried without leaving the browser. The server compiles the pattern
 * with RE2 and decides whether a rule is valid. */

import type { Say } from "@/console/text";

export type Quant = { raw: string; min: number; max: number; lazy?: boolean };
export type ClassItem = { t: "range"; a: string; b: string } | { t: "esc" | "char" | "posix"; c: string };
export type GroupKind = "cap" | "named" | "nc" | "ci" | "flags" | "look";
export type RxNode = { raw: string; q?: Quant } & (
  | { t: "lit"; s: string }
  | { t: "class"; neg: boolean; items: ClassItem[] }
  | { t: "esc"; c: string }
  | { t: "any" }
  | { t: "anchor"; c: string }
  | { t: "flag" }
  | { t: "group"; kind: GroupKind; name: string; alts: RxNode[][]; open: string; closed: boolean });
export type Alts = RxNode[][];

/** A boundary around a value: a line start or end, or one character outside a set -- (?:^|[^A-Za-z0-9_]). */
export function isBound(node: RxNode): boolean {
  return node.t === "group" && node.kind === "nc" && node.alts.length === 2
    && node.alts.some(alt => alt.length === 1 && alt[0].t === "anchor")
    && node.alts.some(alt => alt.length === 1 && alt[0].t === "class" && alt[0].neg);
}

const ESC: Record<string, [string, string]> = {
  d: ["숫자", "digit"], D: ["숫자가 아닌 글자", "non-digit"], w: ["영문·숫자·'_'", "letter, digit or '_'"],
  W: ["영문·숫자·'_'가 아닌 글자", "non-word character"], s: ["공백", "whitespace"], S: ["공백이 아닌 글자", "non-whitespace"],
  b: ["단어 경계", "word boundary"], B: ["단어 경계가 아닌 곳", "not a word boundary"], A: ["전체의 시작", "start of text"],
  z: ["전체의 끝", "end of text"], p: ["유니코드 글자 묶음", "Unicode class"], n: ["줄바꿈", "newline"], t: ["탭", "tab"],
  r: ["줄 되돌림", "carriage return"],
};
const POSIX: Record<string, string> = {
  alpha: "A-Za-z", digit: "0-9", alnum: "A-Za-z0-9", upper: "A-Z", lower: "a-z", space: "\\s", xdigit: "0-9A-Fa-f",
  word: "\\w", blank: " \\t", punct: "!-\\/:-@\\[-`{-~", print: " -~", graph: "!-~", cntrl: "\\x00-\\x1f",
};

export function parse(src: string): Alts {
  let i = 0;
  const n = src.length;
  const lit = (s: string, raw = s): RxNode => ({ t: "lit", s, raw });
  const push = (list: RxNode[], node: RxNode) => {
    const last = list[list.length - 1];
    if (node.t === "lit" && !node.q && last?.t === "lit" && !last.q) { last.s += node.s; last.raw += node.raw; return; }
    list.push(node);
  };
  const quant = (node: RxNode) => {
    if (node.t === "flag" || node.t === "anchor") return;
    const c = src[i];
    let m: RegExpExecArray | null;
    if (c === "*" || c === "+" || c === "?") { node.q = { raw: c, min: c === "+" ? 1 : 0, max: c === "?" ? 1 : Infinity }; i++; }
    else if (c === "{" && (m = /^\{(\d+)(,(\d*))?\}/.exec(src.slice(i)))) {
      const min = Number(m[1]);
      node.q = { raw: m[0], min, max: m[2] ? (m[3] === "" ? Infinity : Number(m[3])) : min };
      i += m[0].length;
    } else return;
    if (src[i] === "?") { node.q.raw += "?"; node.q.lazy = true; i++; }
  };
  const seq = (inGroup: boolean): Alts => {
    const alts: Alts = [[]];
    while (i < n) {
      const ch = src[i];
      if (ch === ")" && inGroup) break;
      if (ch === "|") { alts.push([]); i++; continue; }
      const node = atom();
      quant(node);
      push(alts[alts.length - 1], node);
    }
    return alts;
  };
  const atom = (): RxNode => {
    const ch = src[i], start = i;
    let m: RegExpExecArray | null;
    if (ch === "(") {
      const rest = src.slice(i);
      if ((m = /^\(\?[a-zA-Z-]+\)/.exec(rest))) { i += m[0].length; return { t: "flag", raw: m[0] }; }
      let kind: GroupKind = "cap", name = "";
      if (/^\(\?[=!]/.test(rest)) { kind = "look"; i += 3; }
      else if (/^\(\?<[=!]/.test(rest)) { kind = "look"; i += 4; }
      else if ((m = /^\(\?P?<([A-Za-z_]\w*)>/.exec(rest))) { kind = "named"; name = m[1]; i += m[0].length; }
      else if ((m = /^\(\?([a-zA-Z-]+):/.exec(rest))) { kind = m[1].split("-")[0].includes("i") ? "ci" : "flags"; i += m[0].length; }
      else if (rest.startsWith("(?:")) { kind = "nc"; i += 3; }
      else i += 1;
      const open = src.slice(start, i), alts = seq(true), closed = src[i] === ")";
      if (closed) i++;
      return { t: "group", kind, name, alts, open, closed, raw: src.slice(start, i) };
    }
    if (ch === "[") {
      i++;
      let neg = false, first = true;
      const items: ClassItem[] = [];
      if (src[i] === "^") { neg = true; i++; }
      while (i < n && (src[i] !== "]" || first)) {
        first = false;
        const c = src[i];
        if (c === "[" && src.startsWith("[:", i)) {
          const end = src.indexOf(":]", i);
          if (end > 0) { items.push({ t: "posix", c: src.slice(i + 2, end) }); i = end + 2; continue; }
        }
        let item: ClassItem;
        if (c === "\\") { item = { t: "esc", c: src[i + 1] ?? "" }; i += 2; } else { item = { t: "char", c }; i++; }
        if (item.t === "char" && src[i] === "-" && src[i + 1] && src[i + 1] !== "]") {
          const escaped = src[i + 1] === "\\", b = escaped ? src[i + 2] ?? "" : src[i + 1];
          i += escaped ? 3 : 2;
          items.push({ t: "range", a: item.c, b });
        } else items.push(item);
      }
      if (i < n) i++;
      return { t: "class", neg, items, raw: src.slice(start, i) };
    }
    if (ch === "\\") {
      const c = src[i + 1] ?? "";
      if (c && "dDwWsSbBAzntr".includes(c)) { i += 2; return { t: "esc", c, raw: "\\" + c }; }
      if (c === "x") {
        const braced = /^\\x\{([0-9A-Fa-f]+)\}/.exec(src.slice(i)), hex = braced ? braced[1] : src.substr(i + 2, 2);
        const raw = braced ? braced[0] : "\\x" + hex;
        i += raw.length;
        return lit(String.fromCodePoint(parseInt(hex, 16) || 63), raw);
      }
      if (c === "p" || c === "P") {
        let end = src[i + 2] === "{" ? src.indexOf("}", i) + 1 : i + 3;
        if (end <= i) end = n;
        const raw = src.slice(i, end);
        i = end;
        return { t: "esc", c: "p", raw };
      }
      i += 2;
      return lit(c, "\\" + c);
    }
    i++;
    if (ch === ".") return { t: "any", raw: "." };
    if (ch === "^" || ch === "$") return { t: "anchor", c: ch, raw: ch };
    return lit(ch);
  };
  return seq(false);
}

/* ---------- plain words ---------- */

function classParts(items: ClassItem[], L: Say): string[] {
  const has: Record<string, boolean> = {}, extra: string[] = [];
  for (const item of items) {
    if (item.t === "range") {
      const key = `${item.a}-${item.b}`;
      has[key] = true;
      if (!["A-Z", "a-z", "0-9", "a-f", "A-F"].includes(key)) extra.push(`'${item.a}'~'${item.b}'`);
    } else if (item.t === "esc") {
      if (item.c === "d") has["0-9"] = true;
      else if (item.c === "w") { has["A-Z"] = has["a-z"] = has["0-9"] = true; extra.push("'_'"); }
      else if (ESC[item.c] && "sntr".includes(item.c)) extra.push(L(...ESC[item.c]));
      else extra.push(`'${item.c}'`);
    } else if (item.t === "posix") extra.push(`[:${item.c}:]`);
    else extra.push(item.c === " " ? L("공백", "space") : `'${item.c}'`);
  }
  const parts: string[] = [];
  const hexLower = has["a-f"] && has["0-9"] && !has["a-z"], hexUpper = has["A-F"] && has["0-9"] && !has["A-Z"];
  if (hexLower || hexUpper) parts.push(hexLower && hexUpper ? L("16진수", "hex digit") : hexLower ? L("16진수(0~9·a~f)", "hex (0–9, a–f)") : L("16진수(0~9·A~F)", "hex (0–9, A–F)"));
  else {
    if (has["A-Z"] && has["a-z"]) parts.push(L("영문", "letter"));
    else { if (has["A-Z"]) parts.push(L("영문 대문자", "uppercase letter")); if (has["a-z"]) parts.push(L("영문 소문자", "lowercase letter")); }
    if (has["a-f"] && !has["a-z"]) parts.push("a~f");
    if (has["A-F"] && !has["A-Z"]) parts.push("A~F");
    if (has["0-9"]) parts.push(L("숫자", "digit"));
  }
  return [...parts, ...extra];
}

function classShort(node: Extract<RxNode, { t: "class" }>, L: Say) {
  const p = classParts(node.items, L).join(L("·", "/"));
  return node.neg ? L(`${p} 외 글자`, `not ${p}`) : p;
}

function classTip(node: Extract<RxNode, { t: "class" }>, L: Say) {
  const p = classParts(node.items, L).join(L("·", ", "));
  return node.neg ? L(`${p} 이외의 글자 한 개`, `any one character except ${p}`) : L(`${p} 중 한 글자`, `one character: ${p}`);
}

export function quantTip(q: Quant, L: Say) {
  const lazy = q.lazy ? L(" (가능한 짧게)", " (as few as possible)") : "";
  if (q.min === q.max) return L(`바로 앞이 정확히 ${q.min}번`, `exactly ${q.min} of the previous`) + lazy;
  if (q.min === 0 && q.max === 1) return L("바로 앞은 있어도 되고 없어도 됨", "the previous part is optional") + lazy;
  if (q.max === Infinity) return (q.min === 0 ? L("바로 앞이 없거나 여러 번", "zero or more of the previous") : L(`바로 앞이 ${q.min}번 이상`, `${q.min} or more of the previous`)) + lazy;
  return L(`바로 앞이 ${q.min}~${q.max}번`, `${q.min} to ${q.max} of the previous`) + lazy;
}

function quantShort(q: Quant, chars: boolean, L: Say) {
  if (q.min === 0 && q.max === 1) return L("(생략 가능)", "(optional)");
  const unit = chars ? L("자", "") : L("번", "");
  if (q.min === q.max) return L(`${q.min}${unit}`, `×${q.min}`);
  if (q.max === Infinity) return L(`${q.min}${unit} 이상`, `×${q.min}+`);
  return L(`${q.min}~${q.max}${unit}`, `×${q.min}–${q.max}`);
}

export function flagTip(raw: string, L: Say) {
  const on = (/^\(\?([a-zA-Z]*)/.exec(raw)?.[1] ?? "").split("");
  const words = on.map(flag => flag === "i" ? L("대소문자를 가리지 않습니다", "case-insensitive") : flag === "s" ? L("'.'이 줄바꿈에도 맞습니다", "'.' also matches newlines")
    : flag === "m" ? L("^·$가 줄마다 맞습니다", "^ and $ match at each line") : flag === "U" ? L("반복을 가능한 짧게 잡습니다", "repeats are lazy") : flag);
  return L(`이 뒤로는 ${words.join(", ")}`, `from here on: ${words.join(", ")}`);
}

export function groupTip(node: Extract<RxNode, { t: "group" }>, L: Say): string {
  if (isBound(node)) {
    const set = node.alts.flat().find((item): item is Extract<RxNode, { t: "class" }> => item.t === "class")!;
    const chars = classParts(set.items, L).join(L("·", ", "));
    return L(`경계: 바로 앞뒤에 ${chars} 글자가 붙어 있으면 안 됩니다. 줄의 처음과 끝도 됩니다.`, `Boundary: no ${chars} right before or after. Line start and end also count.`);
  }
  let base = { nc: L("묶음", "Group"), cap: L("번호 붙은 묶음", "Numbered group"), ci: L("대소문자를 가리지 않는 묶음", "Case-insensitive group"),
    flags: L("옵션이 붙은 묶음", "Group with flags"), look: L("앞뒤 살피기 — RE2에서는 쓸 수 없습니다", "Lookaround — not allowed in RE2"), named: "" }[node.kind];
  if (node.kind === "named") base = node.name === "secret" ? L("찾아서 보고할 값(비밀값). 이 부분만 지문으로 남깁니다", "The value to report (the secret). Only this part is fingerprinted")
    : L(`'${node.name}' 이름 붙은 부분`, `Named part '${node.name}'`);
  const sum = node.alts.map(list => summary(list, L)).filter(Boolean).join(L(" 또는 ", " or "));
  return base + (sum ? ` · ${sum}` : "");
}

export function nodeTip(node: RxNode, L: Say): string {
  switch (node.t) {
    case "lit": return L(`'${node.s}' 글자 그대로`, `the literal text '${node.s}'`);
    case "class": return classTip(node, L);
    case "esc": return ESC[node.c] ? L(...ESC[node.c]) : node.raw;
    case "any": return L("아무 글자 한 개(줄바꿈 제외)", "any one character except newline");
    case "anchor": return node.c === "^" ? L("줄의 시작", "start of line") : L("줄의 끝", "end of line");
    case "flag": return flagTip(node.raw, L);
    case "group": return groupTip(node, L);
  }
}

function phrase(node: RxNode, L: Say): string | null {
  let base: string, chars = true;
  if (node.t === "lit") { base = `'${node.s}'`; if (node.s.length > 1) chars = false; }
  else if (node.t === "class") base = classShort(node, L);
  else if (node.t === "esc") { if ("bBAz".includes(node.c)) return null; base = ESC[node.c] ? L(...ESC[node.c]) : node.raw; }
  else if (node.t === "any") base = L("아무 글자", "any character");
  else if (node.t === "group") {
    if (isBound(node) || node.kind === "look") return null;
    chars = false;
    const alts = node.alts.map(list => summary(list, L)).filter(Boolean);
    if (!alts.length) return null;
    base = alts.length > 1 ? `(${alts.join(L(" 또는 ", " or "))})` : node.q && node.alts[0].length > 1 ? `(${alts[0]})` : alts[0];
  } else return null;
  return node.q ? `${base} ${quantShort(node.q, chars, L)}` : base;
}

function summary(list: RxNode[], L: Say) {
  return list.map(node => phrase(node, L)).filter(Boolean).join(" → ");
}

function findSecret(list: RxNode[]): Extract<RxNode, { t: "group" }> | null {
  for (const node of list) {
    if (node.t !== "group") continue;
    if (node.kind === "named" && node.name === "secret") return node;
    for (const alt of node.alts) { const found = findSecret(alt); if (found) return found; }
  }
  return null;
}

/** The value the pattern reports, in plain words, and the name that must come before it. */
export function parts(alts: Alts, L: Say): { value: string; label: string } {
  let secret: Extract<RxNode, { t: "group" }> | null = null;
  for (const alt of alts) secret = secret ?? findSecret(alt);
  const value = (secret ? secret.alts : alts).map(list => summary(list, L)).filter(Boolean).join(L(" 또는 ", " or "));
  let label = "";
  if (secret && alts.length === 1) {
    const at = alts[0].indexOf(secret);
    if (at > 0) label = summary(alts[0].slice(0, at), L);
  }
  return { value, label };
}

/* ---------- trying samples in the browser ---------- */

/** The pattern as a browser RegExp: RE2's (?P<name>), leading flags, \A, \z, POSIX classes and \pL
 * become their JavaScript forms. Null when the browser cannot compile it. */
export function toJsRe(expr: string): RegExp | null {
  let src = String(expr || ""), flags = "g";
  const lead = /^\(\?([imsU]+)\)/.exec(src);
  if (lead) {
    for (const flag of lead[1]) if ("ims".includes(flag) && !flags.includes(flag)) flags += flag;
    src = src.slice(lead[0].length);
  }
  src = src.replace(/\(\?P<(\w+)>/g, "(?<$1>")
    .replace(/\\(.)/g, (match, c: string) => c === "z" ? "$" : c === "A" ? "^" : match)
    .replace(/\[:(\w+):\]/g, (match, name: string) => POSIX[name] ?? match);
  if (/\\[pP][A-Z{]/.test(src)) { src = src.replace(/\\([pP])([A-Z])/g, "\\$1{$2}"); flags += "u"; }
  try { return new RegExp(src, flags); } catch { /* retry below without scoped case flags */ }
  try { return new RegExp(src.replace(/\(\?i:/g, "(?:"), flags.includes("i") ? flags : flags + "i"); } catch { return null; }
}

export type Hit = { start: number; end: number; skip: boolean };

/** Where the pattern matches a sample (the secret group when it has one); a match on a line with an
 * excluded word is marked skipped, as a scan ignores it. */
export function hits(expr: string, sample: string, excluded: string[]): Hit[] | null {
  const re = toJsRe(expr);
  if (!re || !sample) return null;
  const out: [number, number][] = [];
  let m: RegExpExecArray | null, guard = 0;
  re.lastIndex = 0;
  while ((m = re.exec(sample)) && guard++ < 50) {
    if (!m[0].length) { re.lastIndex++; continue; }
    const secret = m.groups?.secret, value = secret ?? m[0];
    const start = m.index + (secret != null ? Math.max(0, m[0].indexOf(secret)) : 0);
    out.push([start, start + value.length]);
  }
  const words = excluded.map(word => word.toLowerCase()).filter(Boolean);
  return out.map(([start, end]) => {
    const from = sample.lastIndexOf("\n", start - 1) + 1;
    let to = sample.indexOf("\n", end);
    if (to < 0) to = sample.length;
    const line = sample.slice(from, to).toLowerCase();
    return { start, end, skip: words.some(word => line.includes(word)) };
  });
}

/* ---------- synthetic values ---------- */

const POOL = ["=", "_", "a", "A", "0", " ", "#", "x"];

function classChar(node: Extract<RxNode, { t: "class" }>) {
  const inClass = (ch: string) => node.items.some(item => {
    if (item.t === "range") return ch >= item.a && ch <= item.b;
    if (item.t === "esc") return item.c === "d" ? /\d/.test(ch) : item.c === "w" ? /\w/.test(ch) : item.c === "s" ? /\s/.test(ch) : ch === item.c;
    if (item.t === "posix") return POSIX[item.c] ? new RegExp(`[${POSIX[item.c]}]`).test(ch) : false;
    return item.c === ch;
  });
  const found = POOL.find(ch => inClass(ch) !== node.neg);
  if (found) return found;
  const first = node.items[0];
  return first ? (first.t === "range" ? first.a : first.c) : "x";
}

function synthNode(node: RxNode): string {
  let one: string;
  if (node.t === "lit") one = node.s;
  else if (node.t === "class") one = classChar(node);
  else if (node.t === "esc") one = ({ d: "0", w: "a", s: " ", D: "x", W: "-", S: "x", n: "\n", t: "\t" } as Record<string, string>)[node.c] ?? "";
  else if (node.t === "any") one = "x";
  else if (node.t === "group") { if (node.kind === "look") return ""; one = synthList(node.alts[0] ?? []); }
  else return "";
  const times = node.q ? (node.q.min === 0 ? (node.t === "group" ? 0 : 1) : node.q.min) : 1;
  return one.repeat(Math.min(times, 400));
}

function synthList(list: RxNode[]) {
  return list.map(synthNode).join("");
}

/** A fake value in the pattern's shape: fewest repeats, and '=', '_', 'a', 'A', '0' first from a set. */
export function synth(expr: string): string {
  return synthList(parse(expr)[0] ?? []);
}

/* ---------- checks the rule form shows ---------- */

export const UNSAFE = /\(\?[=!<]|\(\?P=|\\[1-9]/;

export function splitList(value: string): string[] {
  return value.split(",").map(item => item.trim()).filter(Boolean);
}

/** What the server said about the pattern alone: still asking, or the refusal code it gave. */
export type PatternVerdict = { state: "idle" | "pending" | "done"; error?: string | null };

export type RuleCheck = { ok: boolean | null; label: string; why?: string };

export function ruleChecks(form: { name: string; expr: string; kw: string }, taken: boolean, verdict: PatternVerdict, L: Say): RuleCheck[] {
  const name = form.name.trim(), expr = form.expr, has = Boolean(expr.trim());
  const keywords = splitList(form.kw);
  const safe = has ? !UNSAFE.test(expr) : null;
  const judged = has && safe && expr.length <= 1000 && verdict.state === "done";
  const error = verdict.error ?? "";
  const compiles = judged ? !/does not compile|regex engine/.test(error) : null;
  const broad = compiles ? /trivial input|empty string/.test(error) : null;
  return [
    { ok: Boolean(name) && name.length <= 128 && !taken, label: L("룰 이름 1~128자, 다른 룰과 겹치지 않음", "Name has 1–128 characters and is unique"),
      why: taken ? L("같은 이름의 룰이 이미 있습니다.", "A rule with this name already exists.") : "" },
    { ok: has ? expr.length <= 1000 : null, label: L("정규식 1000자 이하", "Pattern is at most 1000 characters") },
    { ok: safe, label: L("RE2에서 쓸 수 있는 문법(앞뒤 살피기·역참조 없음)", "RE2-safe (no lookaround or backreferences)"),
      why: /\(\?<[A-Za-z_]/.test(expr) ? L("이름 붙은 묶음은 (?P<이름>…) 형식으로 쓰세요.", "Write named groups as (?P<name>…).") : "" },
    { ok: compiles, label: L("문법 오류 없음", "No syntax errors"),
      why: /regex engine/.test(error) ? L("서버에서 정규식 엔진을 쓸 수 없어 룰을 받지 않습니다.", "The server's regex engine is unavailable, so rules are refused.") : "" },
    { ok: broad === null ? null : !broad, label: L("너무 넓지 않음(빈 값·흔한 문장에 걸리지 않음)", "Not too broad (no match on empty or everyday text)") },
    { ok: keywords.length <= 32 && keywords.every(word => word.length <= 64), label: L("키워드 32개 이하, 각 64자 이하", "Up to 32 keywords of 64 characters") },
  ];
}
