"use client";

/* Where an AWS access key is kept, as an Admin declares it: one of the installation's allowlisted Secrets Manager secrets
 * (GET/PUT/DELETE /api/v1/credentials/{id}/management). A declaration, not a value match -- nothing is created, rotated
 * or read from the secret. With the Secrets Manager inventory on, an Admin can read the secret's storage metadata
 * (rotation, the current version; never the value), and a rotation plan starts from the declared secret. */

import { useState } from "react";

import { useLocale } from "@/components/locale";
import { isConflict, reasonText, send, useApi, useSaved } from "@/console/data";
import { useToast } from "@/console/layer";
import { fmtDay, fmtDT, type Say, useL } from "@/console/text";
import { Card, CardBody, ErrorLine, Fact, Facts, Loading, SelectField } from "@/console/ui";
import { DashboardAPIError } from "@/lib/dashboard-api";

/** GET /api/v1/credentials/{id}/management (cremore/api/routes/findings.py _management_public). */
export type Management = {
  revision: number; status: "NO_MANAGER_CONNECTED" | "MANAGED_MATCHED" | "UNKNOWN" | string; reference?: string;
  updated_at: string | null; can_read_metadata: boolean;
};
type Managers = { items: { provider: string; allowed_references: string[] }[] };
/** GET .../management/metadata (aws/.../investigation/secret_metadata.py describe), for the declaration of reference_revision. */
export type SecretMetadata = { reference_revision: number; observed_at: string; metadata: {
  arn: string; current_version_id: string; rotation_enabled: boolean; last_rotated_date: string | null; next_rotation_date: string | null;
  last_accessed_date: string | null; last_changed_date: string | null; deleted_date: string | null;
} };

/** A secret's short name from its ARN (the name after ':secret:'). */
export function secretName(arn: string): string {
  return arn.includes(":secret:") ? arn.split(":secret:")[1] : arn;
}

/** Why the storage details could not be read, in words; the secret's own account is what CreMore could not open. */
export function metadataError(error: unknown, L: Say): string {
  const code = error instanceof DashboardAPIError ? error.message.split(":", 1)[0].trim() : "";
  return code === "ACCOUNT_NOT_CONNECTED" ? L("이 Secret이 있는 AWS 계정이 AWS 연동에 없습니다.", "The AWS account this secret is in is not in an AWS integration.")
    : reasonText(error, L);
}

function Metadata({ credentialId, revision, onStale }: { credentialId: string; revision: number; onStale: () => void }) {
  const L = useL();
  const locale = useLocale();
  const view = useApi<SecretMetadata>(`credentials/${credentialId}/management/metadata`, { every: 0 });
  if (view.error) return <ErrorLine onRetry={view.reload}>{metadataError(view.error, L)}</ErrorLine>;
  if (!view.data) return <Loading />;
  // Read for another declaration than the one shown (an Admin changed it meanwhile): the card is read again first.
  if (view.data.reference_revision !== revision) return <ErrorLine onRetry={onStale}>{L("보관 위치가 그사이 바뀌었습니다.", "Where the key is kept changed meanwhile.")}</ErrorLine>;
  const m = view.data.metadata;
  return <Facts>
    <Fact label={L("로테이션", "Rotation")}>{m.rotation_enabled ? L("켜짐", "On") : L("꺼짐", "Off")}</Fact>
    <Fact label={L("마지막 로테이션", "Last rotated")}>{m.last_rotated_date ? fmtDT(m.last_rotated_date, locale) : <span className="subtle">—</span>}</Fact>
    <Fact label={L("다음 로테이션", "Next rotation")}>{m.next_rotation_date ? fmtDT(m.next_rotation_date, locale) : <span className="subtle">—</span>}</Fact>
    <Fact label={L("현재 버전", "Current version")}><span className="mono small">{m.current_version_id || "—"}</span></Fact>
    {/* Reading the secret is not using the key: Secrets Manager's own last-accessed date, kept to the day. */}
    <Fact label={L("저장소에서 마지막으로 읽힘", "Last read from the store")}>
      {m.last_accessed_date ? fmtDay(m.last_accessed_date, locale) : <span className="subtle">—</span>}</Fact>
    {m.deleted_date ? <Fact label={L("삭제 예정", "Scheduled deletion")}>{fmtDT(m.deleted_date, locale)}</Fact> : null}
  </Facts>;
}

export function SecretBinding({ credentialId, admin }: { credentialId: string; admin: boolean }) {
  const L = useL();
  const locale = useLocale();
  const toast = useToast();
  const saved = useSaved();
  const view = useApi<Management>(`credentials/${credentialId}/management`);
  const managers = useApi<Managers>(admin ? "secret-managers" : null);
  const [choice, setChoice] = useState<{ value: string; revision: number } | null>(null);
  const [busy, setBusy] = useState(false);
  // The declaration whose storage details were asked for: another declaration asks again.
  const [detailsFor, setDetailsFor] = useState<string | null>(null);
  const m = view.data;
  // No allowlisted secret on this installation: nothing to declare.
  if (!m || m.status === "NO_MANAGER_CONNECTED") return view.error ? <Card level={3} title={L("Secrets Manager 보관 위치", "Secrets Manager location")}>
    <CardBody><ErrorLine onRetry={view.reload}>{reasonText(view.error, L)}</ErrorLine></CardBody></Card> : null;
  const allowed = managers.data?.items.flatMap(item => item.allowed_references) ?? [];
  const value = choice?.value ?? m.reference ?? "";
  const write = async (method: "PUT" | "DELETE") => {
    setBusy(true);
    try {
      // The answer is the declaration now, with its revision: a second change right after carries it.
      const revision = choice?.revision ?? m.revision;
      view.replace(await send<Management>(`credentials/${credentialId}/management`, method, method === "PUT" ? { reference: value, revision } : { revision }));
      toast(method === "PUT" ? L("보관 위치를 지정했습니다", "Set where the key is kept") : L("보관 위치 지정을 지웠습니다", "Cleared where the key is kept"));
      setChoice(null);
      saved();
    } catch (reason) {
      toast(reasonText(reason, L), "bad");
      // Changed by another Admin since it was read: read it again, so the next try carries its revision.
      if (isConflict(reason)) view.reload();
    } finally { setBusy(false); }
  };
  return <Card level={3} headClass="wrap" title={L("Secrets Manager 보관 위치", "Secrets Manager location")}
    meta={m.reference && m.updated_at ? L(`${fmtDT(m.updated_at, locale)} 지정`, `Set ${fmtDT(m.updated_at, locale)}`) : undefined}>
    <CardBody>
      <p className="ig-sub">{m.reference ? L(`관리자가 이 키를 ${secretName(m.reference)}에 보관한다고 지정했습니다.`,
        `An Admin declared this key is kept in ${secretName(m.reference)}.`)
        : L("이 키를 보관하는 Secret을 아직 지정하지 않았습니다.", "No secret is declared to hold this key yet.")}</p>
      {admin ? (managers.error && !managers.data ? <ErrorLine onRetry={managers.reload}>{reasonText(managers.error, L)}</ErrorLine>
        : !managers.data ? <Loading />
          : <div className="aws-set-inline">
            <SelectField label={L("허용된 Secret", "Allowed secret")} value={value} onChange={value => setChoice({ value, revision: choice?.revision ?? m.revision })}
              options={[{ id: "", label: L("Secret 선택", "Choose a secret") }, ...allowed.map(arn => ({ id: arn, label: secretName(arn) }))]} />
            <button type="button" className="primary-btn" disabled={busy || !value || value === m.reference} onClick={() => void write("PUT")}>{L("지정", "Set")}</button>
            {m.reference ? <button type="button" className="ghost-btn" disabled={busy} onClick={() => void write("DELETE")}>{L("지정 지우기", "Clear")}</button> : null}
          </div>) : null}
      {choice && choice.revision !== m.revision ? <p className="meta tone-warn">{L("보관 위치가 변경됐습니다. 선택을 지운 뒤 최신 내용에서 다시 지정하세요.", "The storage location changed. Clear your selection and choose again from the latest version.")} <button type="button" className="link-btn" onClick={() => setChoice(null)}>{L("선택 지우기", "Clear selection")}</button></p> : null}
      {admin && m.reference && m.can_read_metadata ? (detailsFor === `${m.reference}:${m.revision}`
        ? <Metadata key={`${m.reference}:${m.revision}`} credentialId={credentialId} revision={m.revision} onStale={view.reload} />
        : <button type="button" className="link-btn" onClick={() => setDetailsFor(`${m.reference}:${m.revision}`)}>{L("Secret 저장 정보 읽기", "Read the secret's storage details")}</button>) : null}
    </CardBody>
  </Card>;
}
