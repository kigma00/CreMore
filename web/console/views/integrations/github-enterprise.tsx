"use client";

/* CreMore's GitHub App on the other organizations of the enterprise (recommendation O-C2). GitHub does the
 * installing once three steps are done there: the App moves to the enterprise, gets "Enterprise organization
 * installations: read and write", and is installed on the enterprise account. Then the admin picks organizations
 * (or turns on auto for organizations that appear later); one worker installs the App on each, connects it with
 * the same key and activates it with this connection's plans once its permission check grants everything. */

import { useState } from "react";

import { useLocale } from "@/components/locale";
import { reasonText as apiReasonText, send, useApi, useSaved } from "@/console/data";
import { Ic } from "@/console/icons";
import { Modal, useToast } from "@/console/layer";
import { Logo } from "@/console/logos";
import { fmtDT, type Say, useL } from "@/console/text";
import { Banner, Check, EmptyRow, Loading, StateChip, Switch } from "@/console/ui";
import { CONNECTIONS_PATH, onboardingText, type ProviderConnection } from "@/console/views/integrations/model";

type Result = { state: string; code?: string; connection_id?: string; by?: string; at?: string };
type Row = { organization: string; installed: boolean; connection: { id: string; status: string; name: string } | null;
  requested: boolean; result: Result | null };
type Made = { organization: string; connection_id: string; status: string; same_app: boolean; changed: boolean };
export type EnterpriseStatus = {
  enterprise: string; host: string | null; organization: string; source_status: string; auto: boolean; reason?: string;
  state: "READY" | "REFRESHING" | "TRANSFER_REQUIRED" | "ENTERPRISE_INSTALL_REQUIRED" | "GITHUB_ENTERPRISE_PERMISSION_REQUIRED" | "GITHUB_UNAVAILABLE";
  app: { slug: string; owner: string; owner_type: string } | null; organizations: Row[]; made: Made[];
  paused_until: string | null; paused_code: string | null; refresh_pending?: boolean;
};

export const enterprisePath = (id: string) => `${CONNECTIONS_PATH}/${id}/github-enterprise`;

/** A GitHub connection that signs in with CreMore's App and names its enterprise can put the App elsewhere in it. */
export function enterpriseReady(c: ProviderConnection) {
  const auth = c.target.auth as Record<string, unknown> | undefined;
  return c.provider === "github" && c.auth_method === "github_app" && Boolean(c.target.enterprise || auth?.github_enterprise)
    && !c.purposes.includes("remediation") && c.status !== "DISABLED" && !c.credential.reference;
}

/** GitHub's pages for the three steps: the App's settings under its owner, the enterprise's Apps, the install page. */
export function githubPages(status: Pick<EnterpriseStatus, "host" | "organization" | "enterprise" | "app">) {
  const host = status.host?.replace(/^https?:\/\//, "").replace(/\/+$/, "");
  const web = host ? `https://${host}` : "https://github.com";
  const slug = status.app?.slug ?? "";
  // The App is transferred from the organization that owns it, which need not be this connection's.
  const owner = status.app?.owner_type === "Organization" && status.app.owner ? status.app.owner : status.organization;
  // GitHub Enterprise Server names its Apps github-apps; GitHub.com and GHE.com name them apps.
  const apps = host && !host.endsWith(".ghe.com") ? "github-apps" : "apps";
  return {
    transfer: slug ? `${web}/organizations/${encodeURIComponent(owner)}/settings/apps/${encodeURIComponent(slug)}/advanced` : undefined,
    permissions: `${web}/enterprises/${encodeURIComponent(status.enterprise)}/settings/apps`,
    install: slug ? `${web}/${apps}/${encodeURIComponent(slug)}/installations/new` : undefined,
  };
}

const STATES: Record<string, [[string, string], "ok" | "warn" | "running" | "bad" | undefined]> = {
  REQUESTED: [["설치 대기", "Waiting to install"], "running"], INSTALLING: [["설치 중", "Installing"], "running"],
  CHECKING: [["권한 확인 중", "Checking access"], "running"], ACTIVE: [["연결됨", "Connected"], "ok"],
  CONNECTED: [["이미 연결됨", "Already connected"], "ok"], NEEDS_REVIEW: [["확인 필요", "Needs review"], "warn"],
  FAILED: [["실패", "Failed"], "bad"],
};
/** Results the worker is still moving on: the window follows them. */
const MOVING = ["REQUESTED", "INSTALLING", "CHECKING"];

const CODES: Record<string, [string, string]> = {
  GITHUB_ENTERPRISE_INSTALL_REFUSED: ["GitHub가 설치를 거절했습니다. App이 이 엔터프라이즈 소유인지 확인하세요.", "GitHub refused the installation. Check that the App belongs to this enterprise."],
  GITHUB_ENTERPRISE_PERMISSION_REQUIRED: ["App에 엔터프라이즈 조직 설치 권한이 없거나 아직 승인되지 않았습니다.", "The App lacks the enterprise organization installations permission, or it is not approved yet."],
  GITHUB_ENTERPRISE_NOT_FOUND: ["이 서버에서 엔터프라이즈를 찾지 못했습니다. 엔터프라이즈 이름과, GitHub Enterprise Server라면 3.19 이상인지 확인하세요.", "The enterprise was not found here. Check its name and, on GitHub Enterprise Server, version 3.19 or later."],
  GITHUB_ORGANIZATION_NOT_IN_ENTERPRISE: ["엔터프라이즈가 설치할 수 있는 조직으로 알려 주지 않은 조직입니다.", "The enterprise does not list this organization as installable."],
  GITHUB_LIST_TRUNCATED: ["GitHub 목록이 1,000개를 넘어 끝까지 읽지 못했습니다.", "GitHub's list has more than 1,000 entries and could not be read to the end."],
  PERMISSIONS_NOT_GRANTED: ["권한 확인에서 허용되지 않은 권한이 있습니다. 연동에서 확인하세요.", "The access check found permissions not granted. Review the integration."],
  SOURCE_NOT_ACTIVE: ["이 연동에 수집 계획이 없어 켜지 않았습니다.", "Not turned on: this integration has no collection plan."],
  GITHUB_ENTERPRISE_SOURCE_NOT_ACTIVE: ["이 연동이 수집 중일 때 다른 조직에 설치할 수 있습니다. 먼저 수집을 시작하세요.", "Organizations can be added while this integration collects. Start collecting first."],
  GITHUB_ENTERPRISE_QUEUE_FULL: ["설치 대기가 1,000곳을 넘었습니다. 처리된 뒤 다시 요청하세요.", "More than 1,000 organizations are waiting. Ask again once they are done."],
  GITHUB_APP_REJECTED: ["GitHub가 App의 키를 받아들이지 않았습니다.", "GitHub did not accept the App's key."],
  GITHUB_APP_UNAVAILABLE: ["GitHub에 연결하지 못했습니다. 잠시 후 다시 확인하세요.", "Could not reach GitHub. Check again shortly."],
  GITHUB_TOO_SLOW: ["GitHub 응답이 느려 이 연동에 주어진 시간 안에 끝내지 못했습니다.", "GitHub answered too slowly to finish within this integration's time."],
  PROVIDER_CONNECTION_NOT_FOUND: ["만들었던 연동이 없습니다.", "The integration it made is gone."],
};

export function codeText(code: string | undefined, L: Say) {
  const known = code ? CODES[code] : undefined;
  return known ? L(...known) : code ?? "";
}

function reasonText(reason: unknown, L: Say) {
  const code = reason instanceof Error ? reason.message : "";
  return CODES[code] ? codeText(code, L) : onboardingText(code, [], L) ?? apiReasonText(reason, L);
}

export function GitHubEnterpriseModal({ conn, onClose }: { conn: ProviderConnection; onClose: () => void }) {
  const L = useL();
  const locale = useLocale();
  const toast = useToast();
  const saved = useSaved();
  // useApi follows worker snapshots with its default visible-window polling.
  const status = useApi<EnterpriseStatus>(enterprisePath(conn.id));
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const s = status.data;
  const open = (s?.organizations ?? []).filter(row => !row.connection && !(row.result && MOVING.includes(row.result.state)));
  const allOpen = open.length > 0 && open.every(row => picked.has(row.organization));
  const active = s?.source_status === "ACTIVE";
  const paused = s?.paused_until && Date.parse(s.paused_until) > Date.now() ? s.paused_until : null;
  const toggle = (names: string[], on: boolean) => setPicked(current => {
    const next = new Set(current);
    for (const name of names) if (on) next.add(name); else next.delete(name);
    return next;
  });

  async function install() {
    setBusy(true);
    const names = [...picked];
    let queued = 0;
    try {
      for (let start = 0; start < names.length; start += 100) {
        const answer = await send<{ requested: string[] }>(`${enterprisePath(conn.id)}/install`, "POST", { organizations: names.slice(start, start + 100) });
        queued += answer.requested.length;
      }
      toast(L(`${queued}개 조직에 설치를 시작했습니다. worker가 1분마다 몇 곳씩 설치하고 연결합니다.`, `Installing on ${queued} organizations. The worker installs and connects a few each minute.`));
      setPicked(new Set());
    } catch (reason) { toast(reasonText(reason, L), "bad"); }
    finally { setBusy(false); status.reload(); saved(); }
  }

  async function cancel(login: string) {
    setBusy(true);
    try {
      await send(`${enterprisePath(conn.id)}/cancel`, "POST", { organizations: [login] });
      toast(L(`${login} 설치 대기를 취소했습니다. 자동 설치도 이 조직은 건너뜁니다.`, `Cancelled ${login}. Auto-install leaves it out as well.`));
      status.reload();
    } catch (reason) { toast(reasonText(reason, L), "bad"); }
    finally { setBusy(false); }
  }

  async function setAuto(enabled: boolean) {
    setBusy(true);
    try {
      await send(`${enterprisePath(conn.id)}/auto`, "PUT", { enabled });
      toast(enabled ? L("지금부터 새로 생기는 조직에 한 시간마다 설치합니다.", "Organizations that appear from now on are installed on every hour.")
        : L("자동 설치를 껐습니다. 자동으로 대기에 넣은 조직도 뺐습니다.", "Automatic installation is off, and what it queued is dropped."));
      status.reload();
    } catch (reason) { toast(reasonText(reason, L), "bad"); }
    finally { setBusy(false); }
  }

  const pages = s ? githubPages(s) : null;
  const done = (step: 1 | 2 | 3) => s ? (step === 1 ? s.state !== "TRANSFER_REQUIRED" : s.state === "READY") : false;
  // Copies the source's next key does not reach: made with another App, or given another credential by an admin.
  const kept = (s?.made ?? []).filter(made => !made.same_app || made.changed).length;
  return <Modal onClose={onClose} labelledBy="ge-title" className="integ ge">
    <h2 id="ge-title"><Logo id="github" size={26} />{L("엔터프라이즈 조직에 설치", "Install on enterprise organizations")} <small>{conn.name}</small></h2>
    {status.error ? <Banner tone="bad" icon="alert">{reasonText(status.error, L)}</Banner> : !s ? <Loading />
      : s.state === "REFRESHING" ? <p role="status">{L("worker가 엔터프라이즈 설치 상태를 확인하고 있습니다. 자동으로 갱신됩니다.", "The worker is checking enterprise installation status. This view updates automatically.")}</p> : <>
      {s.refresh_pending ? <Banner icon="info">{L("이전 조회 결과입니다. worker가 최신 상태를 확인하고 있으며 자동으로 갱신됩니다.", "Showing the previous result while the worker checks the latest status. This view updates automatically.")}</Banner> : null}
      <p className="ig-sub">{L(`엔터프라이즈 ${s.enterprise}의 다른 조직에 같은 GitHub App을 설치하고 조직마다 연동을 만듭니다. GitHub에서 아래 세 단계를 한 번 마치면 CreMore가 나머지를 합니다.`,
        `Install the same GitHub App on the other organizations of ${s.enterprise} and connect each of them. Once the three steps below are done in GitHub, CreMore does the rest.`)}</p>
      <ol className="ge-steps">
        <Step n={1} done={done(1)} current={s.state === "TRANSFER_REQUIRED"} title={L("App을 엔터프라이즈로 이전", "Transfer the App to the enterprise")}
          text={L(`App 설정의 Advanced에서 Transfer ownership을 누르고 ${s.enterprise}를 고릅니다. 이전하면 엔터프라이즈의 모든 조직에 설치할 수 있습니다.`,
            `In the App's Advanced settings, choose Transfer ownership and pick ${s.enterprise}. Then it can be installed in every organization of the enterprise.`)}
          href={pages?.transfer} link={L("App 설정 열기", "Open App settings")} />
        <Step n={2} done={done(2)} current={s.state === "ENTERPRISE_INSTALL_REQUIRED" || s.state === "GITHUB_ENTERPRISE_PERMISSION_REQUIRED"}
          title={L("엔터프라이즈 권한 추가", "Add the enterprise permission")}
          text={L("App의 Permissions에서 Enterprise permissions의 'Enterprise organization installations'를 Read and write로 바꿉니다. 이미 엔터프라이즈에 설치했다면 새 권한을 승인하세요.",
            "In the App's Permissions, set Enterprise permissions → 'Enterprise organization installations' to Read and write. If it is already installed on the enterprise, approve the new permission there.")}
          href={pages?.permissions} link={L("엔터프라이즈 App 열기", "Open enterprise Apps")} />
        <Step n={3} done={done(3)} current={s.state === "ENTERPRISE_INSTALL_REQUIRED"} title={L("엔터프라이즈 계정에 설치", "Install it on the enterprise account")}
          text={L("설치할 위치에서 엔터프라이즈를 고릅니다. 엔터프라이즈 설치는 조직 설치만 관리합니다.", "Pick the enterprise as where to install. The enterprise installation only manages organization installations.")}
          href={pages?.install} link={L("설치 페이지 열기", "Open the install page")} />
      </ol>
      {s.state === "GITHUB_UNAVAILABLE" ? <Banner tone="bad" icon="alert">{codeText(s.reason ?? "GITHUB_APP_UNAVAILABLE", L)}</Banner> : null}
      {s.state === "GITHUB_ENTERPRISE_PERMISSION_REQUIRED" ? <Banner tone="warn" icon="alert">{codeText(s.state, L)}</Banner> : null}
      {!active ? <Banner tone="warn" icon="alert">{codeText("GITHUB_ENTERPRISE_SOURCE_NOT_ACTIVE", L)}</Banner> : null}
      {paused ? <Banner tone="warn" icon="alert">{L(`${codeText(s.paused_code ?? "", L)} ${fmtDT(paused, locale)}에 다시 시도합니다.`,
        `${codeText(s.paused_code ?? "", L)} The worker tries again at ${fmtDT(paused, locale)}.`)}</Banner> : null}
      {s.state === "READY" ? <>
        <div className="table-wrap ge-orgs"><table className="tbl">
          <thead><tr>
            <th className="sel-cell"><button type="button" className="sel-btn" role="checkbox" aria-checked={allOpen} disabled={!open.length || !active}
              aria-label={L("설치할 수 있는 조직 모두 선택", "Select every organization to install on")} onClick={() => toggle(open.map(row => row.organization), !allOpen)}><Check on={allOpen} /></button></th>
            <th>{L("조직", "Organization")}</th><th className="ge-more">{L("App 설치", "App installed")}</th><th className="ge-more">{L("CreMore 연동", "CreMore integration")}</th><th>{L("진행", "Progress")}</th>
          </tr></thead>
          <tbody>
            {s.organizations.length ? s.organizations.map(row => {
              const selectable = active && open.includes(row);
              const source = row.organization.toLowerCase() === s.organization.toLowerCase();
              // Organizations connected some other way count as done, as the worker treats them.
              const state = row.result ? STATES[row.result.state] : row.connection && !source ? STATES.CONNECTED : undefined;
              return <tr key={row.organization}>
                <td className="sel-cell">{selectable ? <button type="button" className="sel-btn" role="checkbox" aria-checked={picked.has(row.organization)}
                  aria-label={L(`${row.organization} 선택`, `Select ${row.organization}`)} onClick={() => toggle([row.organization], !picked.has(row.organization))}><Check on={picked.has(row.organization)} /></button> : null}</td>
                <td><span className="cred-name">{row.organization}</span>{source ? <span className="tag" style={{ marginLeft: 6 }}>{L("이 연동", "This integration")}</span> : null}</td>
                <td className="ge-more">{row.installed ? <span className="tone-ok">{L("설치됨", "Installed")}</span> : <span className="subtle">{L("없음", "No")}</span>}</td>
                <td className="ge-more">{row.connection ? row.connection.name : <span className="subtle">—</span>}</td>
                <td>{state ? <StateChip tone={state[1]}>{L(...state[0])}</StateChip> : <span className="subtle">—</span>}
                  {row.result?.state === "REQUESTED" ? <button type="button" className="link-btn ge-cancel" disabled={busy}
                    aria-label={L(`${row.organization} 설치 대기 취소`, `Cancel ${row.organization}`)} onClick={() => void cancel(row.organization)}>{L("취소", "Cancel")}</button> : null}
                  {row.result?.code ? <div className="subtle small">{codeText(row.result.code, L)}</div> : null}</td>
              </tr>;
            }) : <EmptyRow colSpan={5}>{L("설치할 수 있는 조직이 없습니다.", "No organization can be installed on.")}</EmptyRow>}
          </tbody>
        </table></div>
        <p className="meta">{L("조직마다 저장소 전체에 설치하고, 이 연동과 같은 목적·주기로 연동을 만듭니다. 저장소 내용 검사는 조직마다 검사 대상을 정한 뒤 시작합니다. 자동 설치는 켠 뒤에 새로 생긴 조직에만 적용합니다.",
          "Each organization gets the App on all its repositories and an integration with this one's purposes and schedule. Repository content scans start once each organization's scan targets are set. Auto-install applies only to organizations that appear after it is turned on.")}</p>
        {s.made.length ? <p className="meta">{L(`이 App 키로 만든 조직 연동 ${s.made.length}개가 키 사본을 가집니다. 이 연동의 키를 바꾸면 worker가 같은 App의 연동에도 새 키를 넣습니다.`,
          `${s.made.length} organization integrations made here hold a copy of the App key. When this integration's key is replaced, the worker puts the new one into those of the same App.`)}
          {kept ? L(` 다른 App으로 만들었거나 관리자가 자격증명을 바꾼 ${kept}개는 각 연동에서 바꿉니다.`,
            ` ${kept} made with another App or given another credential by an admin are changed in each integration.`) : ""}</p> : null}
      </> : null}
    </>}
    <div className="modal-foot">
      {s?.state === "READY" ? <span className="ge-auto"><Switch checked={s.auto} disabled={busy || (!s.auto && !active)} onChange={enabled => void setAuto(enabled)}
        label={L("새로 생기는 조직에도 자동 설치", "Also install on new organizations")} />
        <span>{L("새로 생기는 조직에도 자동 설치", "Also install on new organizations")}</span></span> : null}
      <button type="button" className="ghost-btn" style={{ marginLeft: "auto" }} onClick={onClose}>{L("닫기", "Close")}</button>
      {s?.state === "READY" ? <button type="button" className="primary-btn" disabled={busy || !picked.size || !active} onClick={() => void install()}>
        <Ic name="plus" size={15} />{L(`선택한 ${picked.size}개 조직에 설치하고 연동`, `Install and connect ${picked.size} selected`)}</button> : null}
    </div>
  </Modal>;
}

function Step({ n, done, current, title, text, href, link }: { n: number; done: boolean; current: boolean; title: string; text: string; href?: string; link: string }) {
  return <li className={done ? "ge-step is-done" : current ? "ge-step is-current" : "ge-step"}>
    <span className="ge-n" aria-hidden="true">{done ? <Ic name="checkCircle" size={18} /> : n}</span>
    {/* A finished step keeps its title only. */}
    <div><b>{title}</b>{done ? null : <><div className="meta">{text}</div>
      {href ? <a className="link-btn" href={href} target="_blank" rel="noopener noreferrer"><Ic name="ext" size={14} />{link}</a> : null}</>}</div>
  </li>;
}
