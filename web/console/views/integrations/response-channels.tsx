"use client";

/* The Slack channels an exposure-response request may also be posted in (cremore phase 2 "response channels"): an Admin
 * picks them from the channels the bot can see, or enters a channel ID. CreMore checks each one with Slack when it is
 * saved and again before every post: private channels only unless the Admin allows a public one, never a channel
 * shared with another company, never an archived one. */

import { useState } from "react";

import { reasonText, send, useApi, useSaved } from "@/console/data";
import { Ic } from "@/console/icons";
import { Modal, useToast } from "@/console/layer";
import { type Say, useL } from "@/console/text";
import { Banner, Loading, SelectField, StateChip, TextField } from "@/console/ui";

export const RESPONSE_CHANNELS_PATH = "settings/response-channels";
/** One approved channel as the Admin setting holds it: name and privacy are what Slack said at the last save. */
export type ApprovedChannel = { channel_id: string; name: string; is_private: boolean; allow_public: boolean; checked_at: string | null };
export type ResponseChannelsView = { version: number; channels: ApprovedChannel[] };
/** A channel the bot can post to (conversations.list). */
export type ChannelCandidate = { channel_id: string; name: string; is_private: boolean; is_ext_shared: boolean };
/** What any analyst reads for the request form (GET response-channels). */
export type ResponseChannelOption = { channel_id: string; name: string; is_private: boolean };

/** A row being edited: a channel typed by ID has no name or privacy until the server checks it on save. */
type Row = { channel_id: string; name?: string; is_private?: boolean; allow_public: boolean };

/** The integrations card's state: how many channels requests may go to. */
export function responseChannelsState(view: { channels: unknown[] } | undefined, L: Say): string {
  return view?.channels.length ? L(`${view.channels.length}개 채널`, `${view.channels.length} channel${view.channels.length === 1 ? "" : "s"}`) : L("설정 안 됨", "Not set up");
}

/** A Slack channel ID as the server takes one (RESPONSE_CHANNELS_INVALID otherwise). */
export const CHANNEL_ID = /^[CG][A-Z0-9]{8,12}$/;

export function ResponseChannelsModal({ onClose }: { onClose: () => void }) {
  const L = useL();
  const toast = useToast();
  const saved = useSaved();
  const view = useApi<ResponseChannelsView>(RESPONSE_CHANNELS_PATH, { every: 0 });
  // Listing asks Slack: only when the window opens, never again behind the Admin's back.
  const candidates = useApi<{ channels: ChannelCandidate[]; truncated?: boolean }>(`${RESPONSE_CHANNELS_PATH}/candidates`, { every: 0 });
  const [edited, setEdited] = useState<Row[] | null>(null);
  const [picked, setPicked] = useState("");
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const head = <h2 id="rc-title"><span className="ig-cm"><Ic name="send" size={18} /></span>{L("대응 알림 채널", "Response channels")} <small>Slack</small></h2>;
  if (!view.data) {
    return <Modal onClose={onClose} labelledBy="rc-title" className="integ mi">
      {head}{view.error ? <Banner tone="bad" icon="alert">{reasonText(view.error, L)}</Banner> : <Loading />}
      <div className="modal-foot"><button type="button" className="ghost-btn" onClick={onClose}>{L("닫기", "Close")}</button></div>
    </Modal>;
  }
  const rows: Row[] = edited ?? view.data.channels;
  const listed = candidates.data?.channels ?? [];
  const refused = listed.filter(candidate => candidate.is_ext_shared);
  const open = listed.filter(candidate => !candidate.is_ext_shared && !rows.some(row => row.channel_id === candidate.channel_id));
  const add = (row: Row) => { setEdited([...rows, row]); setError(null); };
  const typedId = typed.trim().toUpperCase();
  const typedKnown = listed.find(candidate => candidate.channel_id === typedId);
  const typedProblem = !typedId ? "" : !CHANNEL_ID.test(typedId) ? L("채널 ID는 C 또는 G로 시작하는 대문자·숫자입니다.", "A channel ID starts with C or G and has capital letters and digits.")
    : rows.some(row => row.channel_id === typedId) ? L("이미 목록에 있습니다.", "Already in the list.")
      : typedKnown?.is_ext_shared ? L("외부 회사와 공유된 채널은 쓸 수 없습니다.", "A channel shared with another company cannot be used.") : "";

  async function save() {
    setBusy(true); setError(null);
    try {
      const next = await send<ResponseChannelsView>(RESPONSE_CHANNELS_PATH, "PUT", { expected_version: view.data!.version,
        channels: rows.map(row => ({ channel_id: row.channel_id, allow_public: row.allow_public })) });
      view.replace(next); setEdited(null); saved();
      toast(L("대응 알림 채널을 저장했습니다.", "Response channels saved."));
    } catch (reason) { setError(reasonText(reason, L)); }
    finally { setBusy(false); }
  }

  return <Modal onClose={onClose} labelledBy="rc-title" className="integ mi" dismissable={!busy}>
    {head}
    <p className="ig-sub mi-intro">{L("대응 요청을 담당 팀의 Slack 채널에도 올리고, 진행 상황을 그 글의 스레드에 기록합니다. 저장할 때와 올릴 때마다 Slack에서 채널을 다시 확인합니다. 기본은 비공개 채널만 쓰며, 외부 회사와 공유된 채널과 보관된 채널은 쓸 수 없습니다. 회신은 언제나 CreMore 링크로만 받습니다.",
      "Response requests can also be posted in the responsible team's Slack channel, with progress in that post's thread. CreMore checks the channel with Slack on save and before every post. Private channels only by default; channels shared with another company and archived channels are never used. Answers always come only through the CreMore link.")}</p>
    {error ? <Banner tone="bad" icon="alert" onClose={() => setError(null)}>{error}</Banner> : null}

    <div className="ig-section">
      <div className="ig-section-head"><h3>{L("채널 추가", "Add a channel")}</h3></div>
      {candidates.loading ? <Loading /> : candidates.error ? <p className="meta tone-warn">{reasonText(candidates.error, L)}</p> : <>
        <div className="row2">
          <SelectField label={L("봇이 볼 수 있는 채널", "Channels the bot can see")} value={picked} onChange={setPicked} disabled={busy}
            options={[{ id: "", label: L("선택하세요", "Select") }, ...open.map(candidate => ({ id: candidate.channel_id,
              label: `#${candidate.name} · ${candidate.is_private ? L("비공개", "Private") : L("공개", "Public")}` }))]} />
          <div className="field"><span className="lbl" aria-hidden="true">&nbsp;</span>
            <button type="button" className="ghost-btn" disabled={busy || !picked} onClick={() => {
              const candidate = open.find(item => item.channel_id === picked);
              if (candidate) add({ channel_id: candidate.channel_id, name: candidate.name, is_private: candidate.is_private, allow_public: false });
              setPicked("");
            }}><Ic name="plus" size={15} />{L("추가", "Add")}</button></div>
        </div>
        {candidates.data?.truncated ? <p className="meta">{L("채널이 많아 일부만 보입니다. 없는 채널은 ID로 추가하세요.", "Only some channels are listed. Add a missing one by its ID.")}</p> : null}
        {refused.length ? <div>
          <p className="meta">{L("외부 회사와 공유된 채널은 쓸 수 없습니다:", "Channels shared with another company cannot be used:")}</p>
          {refused.map(candidate => <p className="meta md-actions" key={candidate.channel_id}><span className="cell-wrap">#{candidate.name}</span><StateChip tone="warn">{L("외부 공유 · 거절됨", "Externally shared · refused")}</StateChip></p>)}
        </div> : null}
      </>}
      <div className="row2">
        <TextField label={L("또는 채널 ID", "Or a channel ID")} value={typed} onChange={setTyped} placeholder="C0123ABCD9" maxLength={24}
          hint={typedProblem || L("채널 정보 > 하단의 채널 ID(C… 또는 G…)입니다.", "The channel ID (C… or G…) at the bottom of the channel's details.")} />
        <div className="field"><span className="lbl" aria-hidden="true">&nbsp;</span>
          <button type="button" className="ghost-btn" disabled={busy || !typedId || Boolean(typedProblem)} onClick={() => {
            add(typedKnown ? { channel_id: typedKnown.channel_id, name: typedKnown.name, is_private: typedKnown.is_private, allow_public: false } : { channel_id: typedId, allow_public: false });
            setTyped("");
          }}><Ic name="plus" size={15} />{L("ID로 추가", "Add by ID")}</button></div>
      </div>
    </div>

    <div className="ig-section">
      <div className="ig-section-head"><h3>{L("승인한 채널", "Approved channels")}</h3></div>
      {!rows.length ? <p className="meta">{L("아직 없습니다. 채널이 없으면 대응 요청은 개인 DM이나 메일로만 갑니다.", "None yet. Without a channel, requests go only by DM or mail.")}</p> : null}
      <div className="check-list">{rows.map(row => <div key={row.channel_id} className="card">
        <div className="md-actions">
          <strong className="cell-wrap">{row.name ? `#${row.name}` : row.channel_id}</strong>
          {row.is_private === undefined ? <StateChip>{L("저장할 때 확인", "Checked on save")}</StateChip>
            : <StateChip tone={row.is_private ? "ok" : "warn"}>{row.is_private ? L("비공개", "Private") : L("공개", "Public")}</StateChip>}
          <button type="button" className="ghost-btn" disabled={busy} aria-label={L(`${row.name ? `#${row.name}` : row.channel_id} 빼기`, `Remove ${row.name ? `#${row.name}` : row.channel_id}`)}
            onClick={() => setEdited(rows.filter(item => item.channel_id !== row.channel_id))}><Ic name="close" size={14} />{L("빼기", "Remove")}</button>
        </div>
        {/* Only a channel Slack said is public needs (and takes) the Admin's allow. */}
        <label className="check-line"><input type="checkbox" checked={row.allow_public} disabled={busy || row.is_private !== false}
          onChange={event => setEdited(rows.map(item => item.channel_id === row.channel_id ? { ...item, allow_public: event.target.checked } : item))} />
          {L("공개 채널 허용", "Allow this public channel")}</label>
        {row.is_private === false ? <p className="meta tone-warn">{L("공개 채널은 워크스페이스의 누구나 읽을 수 있습니다. 알림에는 비밀값·경로·이메일을 넣지 않지만, 어떤 자격증명이 노출됐고 누가 맡았는지는 보입니다.",
          "Anyone in the workspace can read a public channel. Posts carry no secret, path or email, but they show which credential was exposed and who is assigned.")}</p> : null}
      </div>)}</div>
    </div>

    <div className="modal-foot">
      <button type="button" className="ghost-btn" style={{ marginLeft: "auto" }} onClick={onClose} disabled={busy}>{L("닫기", "Close")}</button>
      <button type="button" className="primary-btn" disabled={busy || edited === null} onClick={() => void save()}>{busy ? L("저장 중", "Saving") : L("저장", "Save")}</button>
    </div>
  </Modal>;
}
