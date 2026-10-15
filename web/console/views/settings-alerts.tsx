"use client";

/* Slack alerts for new detections (cremore/alerts), an Admin's card in Settings: on or off, where they go (an Incoming
 * Webhook, or a channel the contact setup's Slack bot may post to), what they carry and in which language, the
 * console's address their links start with (kept once, in the contact setup), a test message and how delivery stands.
 * The webhook address is write-only: the API says whether one is saved and never returns it. Switching how alerts are
 * sent shows the new way's field first and saves both together, so it works while alerts are on. */

import { useEffect, useState } from "react";

import { type Locale, useLocale } from "@/components/locale";
import { DashboardAPIError } from "@/lib/dashboard-api";
import { reasonCodeText, reasonText, send, useApi, useSaved } from "@/console/data";
import { actorLabel } from "@/console/labels";
import { useToast } from "@/console/layer";
import { fmtDT, type Say, useL } from "@/console/text";
import { Banner, Card, CardBody, ErrorLine, Loading, Seg, Switch, TextField } from "@/console/ui";

export const ALERTS_PATH = "settings/detection-alerts";

type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
type Transport = "webhook" | "bot";
export type AlertStatus = { pending: number; oldest_pending_at: string | null; last_seen_at: string | null; last_success_at: string | null;
  last_failure_at: string | null; last_error_code: string | null; consecutive_failures: number };
export type AlertsView = {
  enabled: boolean; transport: Transport; webhook_saved: boolean; channel: string | null; channels: string[]; bot_ready: boolean;
  min_severity: Severity; detail: "standard" | "minimal"; language: "ko" | "en"; events: string[]; console_url: string | null;
  enabled_at: string | null; updated_by: string | null; updated_at: string | null; status: AlertStatus;
};
type Tested = { delivered: boolean; error_code: string | null };

export const SEVERITY_CHOICES: [Severity, [string, string]][] = [
  ["INFO", ["모든 탐지", "Every detection"]], ["LOW", ["낮음 이상", "Low and above"]], ["MEDIUM", ["보통 이상", "Medium and above"]],
  ["HIGH", ["높음 이상", "High and above"]], ["CRITICAL", ["심각만", "Critical only"]],
];
// How often the card reads delivery again; a save answers with the new view at once.
export const STATUS_EVERY = 60_000;

const REFUSED: [string, string] = ["Slack이 이 메시지의 내용을 받지 않았습니다. 짧은 형태로 다시 보내고, 그래도 안 되면 이 알림만 나중에 다시 보냅니다. 다른 알림은 계속 나갑니다.",
  "Slack refused this message's content. It is resent in the short form; failing that, only this alert is retried later. Other alerts keep going."];
const DOWN: [string, string] = ["Slack이 잠시 응답하지 못했습니다. 곧 다시 보냅니다.", "Slack was briefly unavailable. Sending resumes shortly."];
// The setup's refusals and delivery's codes, in words; any other code reads as the console's other reasons do.
const CODES: Record<string, [string, string]> = {
  ALERTS_WEBHOOK_INVALID: ["Slack Incoming Webhook 주소(https://hooks.slack.com/services/…)를 그대로 붙여 넣습니다.", "Paste the Slack Incoming Webhook URL (https://hooks.slack.com/services/…) as it is."],
  ALERTS_WEBHOOK_REQUIRED: ["Incoming Webhook 주소를 먼저 저장합니다.", "Save an Incoming Webhook URL first."],
  ALERTS_CHANNEL_REQUIRED: ["보낼 채널을 먼저 고릅니다.", "Choose the channel to post to first."],
  ALERTS_CHANNEL_NOT_ALLOWED: ["연락 발송에서 허용한 채널만 고를 수 있습니다.", "Only a channel allowed under Contact delivery can be chosen."],
  ALERTS_BOT_NOT_SET_UP: ["연동 서비스 > 연락 발송에서 Slack 봇을 먼저 설정합니다.", "Set up the Slack bot under Integrations > Contact delivery first."],
  ALERTS_NOT_CONFIGURED: ["보낼 곳이 아직 정해지지 않았습니다.", "No destination is set up yet."],
  ALERTS_SECRET_UNAVAILABLE: ["저장한 주소를 열 수 없습니다. 주소를 다시 저장합니다.", "The saved URL cannot be opened. Save it again."],
  DELIVERY_RATE_LIMITED: ["Slack 요청 한도에 걸렸습니다. Slack이 알려 준 시간 뒤에 모든 알림을 다시 보냅니다.", "Slack's rate limit was reached. Every alert resumes after the time Slack gave."],
  AUTH_FAILED: ["Slack이 Webhook 주소를 거절했습니다. 새 주소를 만들어 저장합니다.", "Slack refused the webhook URL. Create a new one and save it."],
  HTTP_STATUS_REJECTED: ["Slack이 이 Webhook으로 받지 않습니다. Webhook이 지워졌거나 채널이 보관되었는지 확인합니다.", "Slack does not take messages on this webhook. Check whether it was removed or its channel archived."],
  SINK_UNAVAILABLE: DOWN, SLACK_UNAVAILABLE: DOWN, SLACK_INTERNAL_ERROR: DOWN, SLACK_FATAL_ERROR: DOWN, SLACK_SERVICE_UNAVAILABLE: DOWN,
  DELIVERY_REJECTED: REFUSED, SLACK_INVALID_BLOCKS: REFUSED, SLACK_INVALID_BLOCKS_FORMAT: REFUSED, SLACK_MSG_TOO_LONG: REFUSED,
  SLACK_MSG_BLOCKS_TOO_LONG: REFUSED, SLACK_NO_TEXT: REFUSED, SLACK_TOO_MANY_ATTACHMENTS: REFUSED, SLACK_INVALID_ARGUMENTS: REFUSED,
  SLACK_IS_ARCHIVED: ["채널이 보관되었습니다. 다른 채널을 고릅니다.", "The channel is archived. Choose another channel."],
  INVALID_RESPONSE: ["Slack이 메시지를 받았다고 답하지 않았습니다.", "Slack did not answer that it took the message."],
  RESPONSE_TOO_LARGE: ["Slack의 응답이 예상보다 커서 읽지 않았습니다.", "Slack's answer was larger than expected and was not read."],
  DELIVERY_TIMEOUT: ["Slack이 제시간에 답하지 않았습니다.", "Slack did not answer in time."],
  HTTP_DELIVERY_FAILED: ["Slack에 연결하지 못했습니다.", "Could not reach Slack."],
  DELIVERY_FAILED: ["보내지 못했습니다.", "It was not sent."],
  CONTACT_RECIPIENT_NOT_ALLOWED: ["고른 채널이 연락 발송의 허용 채널에 없습니다.", "The chosen channel is not allowed under Contact delivery."],
  CONTACT_CHANNEL_NOT_SET_UP: ["연락 발송의 Slack 봇 설정이 없습니다.", "Contact delivery has no Slack bot set up."],
};

/** A code from the setup or from delivery, in words. */
export function alertCodeText(code: string, L: Say): string {
  const known = CODES[code];
  return known ? L(known[0], known[1]) : reasonCodeText(code, L);
}

/** A test's code in words: a test is sent once more without its button, and nothing of it is resent later. */
export function testCodeText(code: string, L: Say): string {
  if (CODES[code] === REFUSED) return L("Slack이 시험 메시지의 내용을 버튼을 뺀 형태로도 받지 않았습니다.",
    "Slack refused the test message's content, also without its button.");
  if (CODES[code] === DOWN) return L("Slack이 잠시 응답하지 못했습니다. 잠시 뒤 다시 시험합니다.", "Slack was briefly unavailable. Test again shortly.");
  return alertCodeText(code, L);
}

const EVENT_WORDS: [string, [string, string]][] = [
  ["finding.created", ["새 자격증명 노출", "new credential exposures"]], ["finding.location_added", ["새 위치에서 발견", "new locations"]],
  ["finding.reappeared", ["제거 후 다시 노출", "reappearances"]],
];

/** What the saved event types announce (a subset is chosen through the API). */
export function announced(events: string[], L: Say): string {
  const shown = EVENT_WORDS.filter(([kind]) => events.includes(kind)).map(([, words]) => words);
  if (!shown.length) return L("알릴 이벤트 종류가 없습니다.", "No event type is chosen.");
  const english = shown.map(words => words[1]);
  return L(`${shown.map(words => words[0]).join(", ")}을 알립니다.`,
    `Announces ${english.length > 1 ? `${english.slice(0, -1).join(", ")} and ${english[english.length - 1]}` : english[0]}.`);
}

/** What a refused save says. */
export function alertReason(error: unknown, L: Say): string {
  const code = error instanceof DashboardAPIError ? error.message.split(":", 1)[0].trim() : "";
  return CODES[code] ? alertCodeText(code, L) : reasonText(error, L);
}

/** The shape Slack gives an Incoming Webhook; the API checks it again. */
export function webhookShape(value: string): boolean {
  return /^https:\/\/hooks\.slack(-gov)?\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[A-Za-z0-9_-]+$/i.test(value.trim());
}

/** What saving the "where to send" part sends: the way, and the new way's webhook or channel with it. */
export function destinationBody(view: AlertsView, transport: Transport, webhook: string, channel: string): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  if (transport !== view.transport) body.transport = transport;
  if (transport === "webhook" && webhook.trim()) body.webhook_url = webhook.trim();
  if (transport === "bot" && (transport !== view.transport || channel !== (view.channel ?? ""))) body.channel = channel;
  return body;
}

/** How delivery stands, in one line; ``warn`` when something needs a look. */
export function deliveryState(view: AlertsView, L: Say, locale: Locale, now = Date.now()): { text: string; warn: boolean } {
  const s = view.status;
  if (!view.enabled) return { text: L("꺼짐 · 켜면 그때부터의 탐지를 보냅니다.", "Off · once on, detections from then on are sent."), warn: false };
  const seen = s.last_seen_at ? Date.parse(s.last_seen_at) : NaN;
  if (Number.isNaN(seen)) return { text: L("워커가 아직 알림을 확인하지 않았습니다.", "The worker has not picked the alerts up yet."), warn: true };
  if (now - seen > 120_000) {
    return { text: L(`워커가 ${fmtDT(s.last_seen_at, locale)} 이후 알림을 확인하지 않았습니다.`, `The worker has not checked the alerts since ${fmtDT(s.last_seen_at, locale)}.`), warn: true };
  }
  const waiting = s.pending ? L(` · 대기 ${s.pending}건`, ` · ${s.pending} waiting`) : "";
  if (s.consecutive_failures) {
    const why = alertCodeText(s.last_error_code ?? "DELIVERY_FAILED", L);
    return { text: L(`보내지 못해 다시 보냅니다(연속 ${s.consecutive_failures}회): ${why}${waiting}`,
      `Not sent; retrying (${s.consecutive_failures} in a row): ${why}${waiting}`), warn: true };
  }
  return { text: s.last_success_at ? L(`정상 · 마지막 전송 ${fmtDT(s.last_success_at, locale)}${waiting}`, `Working · last sent ${fmtDT(s.last_success_at, locale)}${waiting}`)
    : L(`정상 · 아직 보낸 알림이 없습니다${waiting}`, `Working · no alert sent yet${waiting}`), warn: false };
}

export function DetectionAlerts() {
  const L = useL();
  const locale = useLocale();
  const toast = useToast();
  const saved = useSaved();
  // Read once and then every STATUS_EVERY: delivery status is a bounded read, but it need not run every 10 s.
  const view = useApi<AlertsView>(ALERTS_PATH, { every: 0 });
  const { reload } = view;
  useEffect(() => {
    const timer = window.setInterval(() => { if (document.visibilityState === "visible") reload(); }, STATUS_EVERY);
    return () => window.clearInterval(timer);
  }, [reload]);
  const [busy, setBusy] = useState<"" | "save" | "test">("");
  const [picked, setPicked] = useState<Transport | null>(null);
  const [webhook, setWebhook] = useState("");
  const [channel, setChannel] = useState<string | null>(null);
  const [consoleUrl, setConsoleUrl] = useState<string | null>(null);
  const [tested, setTested] = useState<Tested | null>(null);
  const title = L("Slack 탐지 알림", "Slack detection alerts");
  if (view.error) return <Card title={title} className="list-card"><CardBody><ErrorLine onRetry={view.reload}>{reasonText(view.error, L)}</ErrorLine></CardBody></Card>;
  if (!view.data) return <Card title={title} className="list-card"><CardBody><Loading /></CardBody></Card>;
  const v = view.data;
  const state = deliveryState(v, L, locale);
  const by = v.updated_by === "local operator" ? L("로컬 관리자", "Local admin") : actorLabel(v.updated_by, L);
  const transport = picked ?? v.transport;
  const switching = transport !== v.transport;
  const chosen = channel ?? v.channel ?? "";
  const typed = webhook.trim();
  const typedWrong = typed !== "" && !webhookShape(typed);
  const body = destinationBody(v, transport, webhook, chosen);
  const destinationReady = transport === "webhook" ? (typed ? !typedWrong : v.webhook_saved) : Boolean(chosen);
  const savedReady = v.transport === "webhook" ? v.webhook_saved : Boolean(v.channel);
  const unlisted = chosen && !v.channels.includes(chosen) ? chosen : null;

  const put = async (change: Record<string, unknown>, done?: string) => {
    setBusy("save");
    try {
      view.replace(await send<AlertsView>(ALERTS_PATH, "PUT", change));
      saved();
      toast(done ?? L("저장했습니다", "Saved"));
      return true;
    } catch (reason) {
      toast(alertReason(reason, L), "bad");
      return false;
    } finally { setBusy(""); }
  };
  const resetDestination = () => { setPicked(null); setWebhook(""); setChannel(null); };
  const saveDestination = async () => {
    if (await put(body, switching ? L("보내는 방법을 바꿨습니다", "Sending method changed") : L("저장했습니다", "Saved"))) resetDestination();
  };
  const commitConsole = async () => {
    if (consoleUrl === null || consoleUrl.trim() === (v.console_url ?? "")) { setConsoleUrl(null); return; }
    if (await put({ console_url: consoleUrl.trim() })) setConsoleUrl(null);
  };
  const test = async () => {
    setBusy("test"); setTested(null);
    try { setTested(await send<Tested>(`${ALERTS_PATH}/test`, "POST")); }
    catch (reason) { setTested({ delivered: false, error_code: null }); toast(alertReason(reason, L), "bad"); }
    finally { setBusy(""); }
  };

  return <Card title={title} id="set-alerts" className="list-card"
    meta={v.updated_by ? L(`마지막 변경: ${by}${v.updated_at ? ` · ${fmtDT(v.updated_at, locale)}` : ""}`, `Last changed by ${by}${v.updated_at ? ` · ${fmtDT(v.updated_at, locale)}` : ""}`) : undefined}
    info={L("새 탐지는 결과와 같은 저장 단계에서 발신 대기열에 기록되고, 워커가 Slack이 받았다고 답할 때까지 다시 보냅니다. 메시지에는 비밀값·가린 값·지문이 들어가지 않습니다.",
      "Each new detection is queued in the same step that stores it, and the worker resends until Slack answers that it took the message. Messages never carry a secret value, a masked value or a fingerprint.")}>
    <CardBody>
      <div className="set-row">
        <div className="set-text"><b>{L("새 탐지를 Slack으로 보내기", "Send new detections to Slack")}</b>
          <p>{announced(v.events, L)} {L("처음 켜기 전 기록과 꺼 둔 동안의 탐지는 보내지 않고, 끄기 전에 보내지 못한 알림은 다시 켜면 보냅니다. 오탐으로 닫힌 탐지는 보내지 않습니다.",
            "Records from before alerts were first on and detections made while they are off are not sent; alerts still owed when they were turned off go out once they are on again. None closed as a false positive is sent.")}</p>
          <div className="set-state">{state.warn ? <span className="set-warn">{state.text}</span> : state.text}</div>
        </div>
        <Switch checked={v.enabled} label={L("Slack 탐지 알림", "Slack detection alerts")} disabled={Boolean(busy) || (!v.enabled && !savedReady)}
          tip={!v.enabled && !savedReady ? L("보낼 곳을 먼저 저장합니다.", "Save where to send first.") : undefined}
          onChange={enabled => void put({ enabled }, enabled ? L("알림을 켰습니다", "Alerts on") : L("알림을 껐습니다", "Alerts off"))} />
      </div>

      <div className="set-row">
        <div className="set-text"><b>{L("보낼 곳", "Where to send")}</b>
          <p>{L("Slack 앱에서 만든 Incoming Webhook 주소, 또는 연락 발송에 설정한 Slack 봇이 보낼 수 있는 채널입니다.",
            "An Incoming Webhook URL made in a Slack app, or a channel the Slack bot set up under Contact delivery may post to.")}</p>
          {transport === "webhook" ? <div className="set-grid wide">
            <TextField label={L("Incoming Webhook 주소", "Incoming Webhook URL")} value={webhook} onChange={setWebhook} masked maxLength={512}
              disabled={Boolean(busy)} placeholder={v.webhook_saved ? L("저장된 주소 유지 · 바꿀 때만 입력", "Keep the saved URL · enter only to replace") : "https://hooks.slack.com/services/…"}
              hint={typedWrong ? <span className="set-warn">{alertCodeText("ALERTS_WEBHOOK_INVALID", L)}</span>
                : v.webhook_saved ? L("주소가 저장되어 있습니다. 저장한 주소는 다시 보여 주지 않습니다.", "A URL is saved. A saved URL is never shown again.")
                  : L("Slack 앱의 Incoming Webhooks에서 채널을 골라 만든 주소입니다.", "Made under Incoming Webhooks in a Slack app, for one channel.")} />
          </div> : v.bot_ready ? <div className="set-grid">
            <div className="field">
              <label htmlFor="alerts-channel">{L("채널", "Channel")}</label>
              <select id="alerts-channel" value={chosen} disabled={Boolean(busy)} onChange={event => setChannel(event.target.value)}>
                <option value="">{L("채널 고르기", "Choose a channel")}</option>
                {unlisted ? <option value={unlisted}>{L(`${unlisted} (허용 목록에 없음)`, `${unlisted} (not allowed any more)`)}</option> : null}
                {v.channels.map(name => <option key={name} value={name}>{name}</option>)}
              </select>
              <span className="meta">{L("연락 발송에서 허용한 채널입니다. 봇을 그 채널에 초대해야 보낼 수 있습니다.", "The channels allowed under Contact delivery. Invite the bot to the channel so it can post there.")}</span>
            </div>
          </div> : <p className="set-note">{alertCodeText("ALERTS_BOT_NOT_SET_UP", L)}</p>}
          {switching ? <p className="set-note">{L("아직 바꾸지 않았습니다. 저장하면 이 방법으로 보냅니다.", "Not changed yet: once saved, alerts go this way.")}</p> : null}
          {Object.keys(body).length ? <div className="dm-acts">
            <button type="button" className="primary-btn" disabled={Boolean(busy) || !destinationReady} onClick={() => void saveDestination()}>
              {switching ? L("이 방법으로 보내기", "Send this way") : L("저장", "Save")}</button>
            <button type="button" className="ghost-btn" disabled={Boolean(busy)} onClick={resetDestination}>{L("취소", "Cancel")}</button>
          </div> : null}
        </div>
        <Seg value={transport} label={L("보내는 방법", "How to send")} onChange={next => { setPicked(next === v.transport ? null : next); setChannel(null); }}
          options={[{ id: "webhook" as const, label: "Incoming Webhook" }, { id: "bot" as const, label: L("Slack 봇", "Slack bot") }]} />
      </div>

      <div className="set-grid">
        <div className="field">
          <label htmlFor="alerts-severity">{L("보낼 심각도", "Severity to send")}</label>
          <select id="alerts-severity" value={v.min_severity} disabled={Boolean(busy)} onChange={event => void put({ min_severity: event.target.value })}>
            {SEVERITY_CHOICES.map(([id, words]) => <option key={id} value={id}>{L(...words)}</option>)}
          </select>
          <span className="meta">{L("위치의 점수를 최대 1분 기다리고, 그래도 없으면 기준과 관계없이 보냅니다. 기준보다 낮던 탐지가 기준 이상으로 오르면 심각도 상승으로 알립니다.",
            "An alert waits up to a minute for its location's score, then goes out whatever the minimum. A detection that rises from below the minimum to meet it is announced as a severity rise.")}</span>
        </div>
        <div className="field">
          <label htmlFor="alerts-detail">{L("내용", "Content")}</label>
          <select id="alerts-detail" value={v.detail} disabled={Boolean(busy)} onChange={event => void put({ detail: event.target.value })}>
            <option value="standard">{L("자세히", "Standard")}</option>
            <option value="minimal">{L("간단히", "Minimal")}</option>
          </select>
          <span className="meta">{v.detail === "minimal" ? L("심각도·유형·발견 위치와 콘솔 링크만 보냅니다.", "Severity, type, where it was found and the console link only.")
            : L("유형·발급처·검증 상태·연결·리소스·경로와 줄·처음 발견·검사 시작·다른 위치 수와 콘솔 링크, AWS 키는 최근 사용 출처 IP 주소도 보냅니다. 채널을 보는 사람은 이 주소를 봅니다. 자격증명처럼 보이는 이름은 넣지 않습니다.",
              "Type, issuer, verification, connection, resource, path and line, first seen, what started the scan, other locations and the console link, and for an AWS key the IP addresses it was recently used from, which anyone who sees the channel sees. A name shaped like a credential is left out.")}</span>
        </div>
        <div className="field">
          <label htmlFor="alerts-language">{L("메시지 언어", "Message language")}</label>
          <select id="alerts-language" value={v.language} disabled={Boolean(busy)} onChange={event => void put({ language: event.target.value })}>
            <option value="ko">한국어</option>
            <option value="en">English</option>
          </select>
          <span className="meta">{L("시각은 한국어면 KST, 영어면 UTC로 적습니다.", "Times are in KST for Korean and in UTC for English.")}</span>
        </div>
        <div className="field">
          <label htmlFor="alerts-console">{L("콘솔 주소", "Console address")}</label>
          <input id="alerts-console" value={consoleUrl ?? v.console_url ?? ""} inputMode="url" autoComplete="off" spellCheck={false} maxLength={200} disabled={Boolean(busy)}
            placeholder={typeof window === "undefined" ? "https://cremore.example.com" : window.location.origin}
            onChange={event => setConsoleUrl(event.target.value)} onBlur={() => void commitConsole()}
            onKeyDown={event => { if (event.key === "Enter") event.currentTarget.blur(); }} />
          <span className="meta">{v.console_url ? L("알림의 콘솔 링크가 이 주소로 시작합니다. 연락 발송의 승인 링크와 같은 설정입니다.", "The alerts' console links start with this address; approval links under Contact delivery use it too.")
            : L("비워 두면 알림에 링크 대신 Credential ID가 들어갑니다. 연락 발송의 승인 링크와 같은 설정입니다.", "Left empty, alerts carry the credential ID instead of a link; approval links under Contact delivery use the same address.")}</span>
        </div>
      </div>

      <div className="set-row">
        <div className="set-text"><b>{L("시험 메시지", "Test message")}</b>
          <p>{L("저장한 설정으로 지금 한 번 보냅니다. 시험 메시지는 알림 대기열을 거치지 않고, 알림과 같은 간격과 Slack의 한도를 지킵니다.",
            "Sends one message now with the saved setup. A test does not go through the alert queue; it keeps the alerts' pace and Slack's limits.")}</p>
          {tested ? tested.delivered ? <Banner tone="ok" icon="info">{L("시험 메시지를 보냈습니다. Slack 채널에서 확인합니다.", "Test message sent. Look for it in the Slack channel.")}</Banner>
            : tested.error_code ? <Banner tone="bad" icon="alert">{testCodeText(tested.error_code, L)}</Banner> : null : null}
        </div>
        <button type="button" className="ghost-btn" disabled={Boolean(busy) || !savedReady} onClick={() => void test()}>
          {busy === "test" ? L("보내는 중", "Sending") : L("시험 메시지 보내기", "Send a test message")}</button>
      </div>
    </CardBody>
  </Card>;
}
