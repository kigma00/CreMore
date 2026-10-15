"use client";

import { useState } from "react";

import { useL } from "@/console/text";

/** Keep only visited positions, never accumulate rows or fetch unrequested pages. */
export function usePageHistory<T extends string | number | null>(key: string | null, initial: T) {
  const [state, setState] = useState<{ key: string | null; positions: T[] }>({ key, positions: [initial] });
  const positions = state.key === key ? state.positions : [initial];
  const reset = () => setState({ key, positions: [initial] });
  return {
    position: positions[positions.length - 1], page: positions.length,
    previous: () => setState({ key, positions: positions.length > 1 ? positions.slice(0, -1) : positions }),
    next: (position: T) => setState({ key, positions: [...positions, position] }), reset,
  };
}

export function PageNavigation({ label, page, hasNext, loading, previous, next, reset }: {
  label: string; page: number; hasNext: boolean; loading: boolean; previous: () => void; next: () => void; reset: () => void;
}) {
  const L = useL();
  return <nav className="list-foot" aria-label={label} style={{ flexWrap: "wrap", gap: 8 }}>
    <span>{label} · {L(`${page}페이지`, `Page ${page}`)}</span>
    <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
      <button type="button" className="ghost-btn" disabled={page <= 1 || loading} onClick={reset}>{L("처음", "First")}</button>
      <button type="button" className="ghost-btn" disabled={page <= 1 || loading} onClick={previous}>{L("이전", "Previous")}</button>
      <button type="button" className="ghost-btn" disabled={!hasNext || loading} onClick={next}>{L("다음", "Next")}</button>
    </div>
  </nav>;
}
