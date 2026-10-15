"use client";

import { useEffect, useRef, useState } from "react";
import { api } from "@/lib/dashboard-api";
import { reasonText } from "@/console/data";
import { downloadJson, useL } from "@/console/text";
import { Banner } from "@/console/ui";

export type SignedApproval = { claims: Record<string, unknown>; signature: string };

/** The private signing key stays with the independent approver. Only their artifact is uploaded. */
export function IndependentAuthorization({ planId, planHash, mode, onChange }: {
  planId: string; planHash: string; mode: "execute" | "emergency" | "recheck"; onChange: (value: SignedApproval | undefined) => void;
}) {
  const L = useL();
  const [error, setError] = useState("");
  const [fileName, setFileName] = useState("");
  const selection = useRef(0);
  useEffect(() => () => { selection.current++; }, [planId, planHash, mode]);
  async function request() {
    setError("");
    try {
      downloadJson(`cremore-authorization-${planId}-${mode}.json`,
        await api(`action-plans/${planId}/authorization-request?mode=${mode}`));
    } catch (reason) { setError(reasonText(reason, L)); }
  }
  async function read(file: File | undefined) {
    const current = ++selection.current;
    onChange(undefined); setFileName(""); setError("");
    if (!file) return;
    try {
      if (file.size > 4096) throw new Error("size");
      const value = JSON.parse(await file.text());
      if (!value || Object.keys(value).sort().join() !== "claims,signature" || typeof value.signature !== "string" || !value.signature
        || !value.claims || Array.isArray(value.claims) || typeof value.claims !== "object" || value.claims.plan_id !== planId
        || value.claims.plan_hash !== planHash || value.claims.mode !== mode) throw new Error("shape");
      if (selection.current !== current) return;
      onChange(value); setFileName(file.name);
    } catch { if (selection.current !== current) return;
      setError(L("이 계획·작업에 대한 서명 승인 JSON 파일을 선택하세요. 개인키 파일은 올리지 마세요.",
      "Select the signed approval JSON for this plan and operation. Do not upload a private key.")); }
  }
  return <div className="ig-section">
    <h3>{L("독립 실행 승인", "Independent execution approval")}</h3>
    <p className="meta">{L("요청 파일의 대상·조치를 별도 승인 환경에서 검토하고 서명한 후 승인 파일만 첨부하세요. 서버가 서명·만료·재사용 여부를 확인합니다.",
      "Review the target and action in the request on the independent approval system, sign it, then attach only the approval file. The server checks its signature, expiry and reuse.")}</p>
    <button type="button" className="ghost-btn" onClick={() => void request()}>{L("승인 요청 파일 받기", "Download approval request")}</button>
    <label className="field"><span>{L("서명 승인 파일", "Signed approval file")}</span>
      <input type="file" accept="application/json,.json" onChange={event => void read(event.target.files?.[0])} /></label>
    {fileName ? <p className="meta">{L("첨부됨", "Attached")}: {fileName}</p> : null}
    {error ? <Banner tone="bad" icon="alert">{error}</Banner> : null}
  </div>;
}
