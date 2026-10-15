"use client";

/* Table cells the credential list and its panel share. */

import { useLocale } from "@/components/locale";
import { DetailPopover } from "@/console/layer";
import { type CredentialRecord, creatorLabel, daysTo, ended, revoked, sourceLabel } from "@/console/records";
import { fmtDay, fmtDT, num, useL } from "@/console/text";
import { Fact } from "@/console/ui";

export function CreatorSummary({ c }: { c: CredentialRecord }) {
  const L = useL();
  const creator = c.issued?.provider === "aws_iam" ? c.issued.creator : null;
  if (!creator) return <span>{creatorLabel(c, L)}</span>;
  return <DetailPopover label={creatorLabel(c, L) ?? ""}>
    <ul><li>{creator.arn}</li><li className="subtle">CloudTrail · {creator.region}</li></ul>
  </DetailPopover>;
}

/** Where the key was recently used from (the saved CloudTrail lookup); nothing when there is no such lookup. */
export function RecentSources({ c }: { c: CredentialRecord }) {
  const L = useL();
  const locale = useLocale();
  if (!c.recent_sources?.length) return null;
  // The total counts every distinct address the lookup read; "more": it saw addresses past what it could count.
  // A lower bound with none known past those listed says so without a number.
  const rest = Math.max((c.recent_sources_total ?? 0) - c.recent_sources.length, 0), more = c.recent_sources_more === true;
  return <Fact label={L("최근 사용 출처", "Recently used from")} tip={L("저장된 CloudTrail 이벤트 기록의 출발 주소입니다. 키 소유 계정에서 조회한 기록만 씁니다.", "Source addresses in the saved CloudTrail event history, from lookups in the key's own account only.")}>
    <ul className="pill-wrap">{c.recent_sources.map(source => <li className="tag" key={source.address}>
      <span className="mono">{sourceLabel(source.address, source.kind, L)}</span>
      <span className="subtle num"> · {source.last_seen_at ? fmtDT(source.last_seen_at, locale) : "—"} · {L(`${source.count}건`, `${source.count} ${source.count === 1 ? "call" : "calls"}`)}</span></li>)}
      {rest ? <li className="tag num">{more ? L(`+${num(rest, locale)}곳 이상`, `+${num(rest, locale)} or more`) : L(`+${num(rest, locale)}곳`, `+${num(rest, locale)} more`)}</li>
        : more ? <li className="tag">{L("더 있을 수 있음", "possibly more")}</li> : null}</ul>
  </Fact>;
}

export function Expiry({ c }: { c: CredentialRecord }) {
  const L = useL();
  const locale = useLocale();
  if (revoked(c) || (ended(c) && c.expiry !== "date")) return <span className="subtle">—</span>;
  if (c.expiry === "unknown") return <span className="subtle" data-tip={L("발급 정보가 없어 만료일을 알 수 없습니다.", "No issuance info, so the expiry is unknown.")}>{L("미확인", "Unknown")}</span>;
  if (c.expiry === "none") return <span className="exp-none" data-tip={L("만료일 없이 발급됐습니다.", "Issued without an expiry date.")}>{L("없음", "None")}</span>;
  const days = daysTo(c.expires_at);
  if (days !== null && days < 0) return <span className="subtle num" data-tip={fmtDay(c.expires_at, locale)}>{L("만료됨", "Expired")}</span>;
  if (days !== null && days <= 30) return <span className="exp-soon num" data-tip={fmtDay(c.expires_at, locale) + L(" 만료", " expiry")}>D-{days}</span>;
  return <span className="num">{fmtDay(c.expires_at, locale)}</span>;
}
