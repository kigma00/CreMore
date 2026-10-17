"use client";

/* 연결 대상 현황 (connected targets): what an integration reaches, one target at a time, with that target's own checks.
 * One menu item for every provider whose integration reaches targets of its own; an AWS integration's are its accounts
 * (whether scanning and key actions can reach each, and the role checks and changes behind them). */

import { type ReactNode, useEffect, useRef, useState } from "react";

import { failureCodeLabel } from "@/components/labels";
import { type Locale, useLocale } from "@/components/locale";
import { codeText, reasonText, send, useApi, useSaved } from "@/console/data";
import { Ic } from "@/console/icons";
import { Modal, useToast } from "@/console/layer";
import { Logo, serviceName } from "@/console/logos";
import { fmtDT, rel, type Say, useL } from "@/console/text";
import { Banner, ErrorLine, Loading, StateChip } from "@/console/ui";
import { runText } from "@/console/views/credentials/issued";
import { AccountRole } from "@/console/views/integrations/guide";
import { GitHubCollections } from "@/console/views/integrations/github-export";
import type { Child, ProviderConnection } from "@/console/views/integrations/model";
import { DashboardAPIError } from "@/lib/dashboard-api";

/** An AWS account as GET /api/v1/aws/accounts serves it (cremore/api/aws_support.py present_aws_account). */
export type AwsAccount = {
  id: string; account_id: string; name: string; access: string; enabled: boolean; source: string; org_blocks: string[];
  scanner_role_arn: string | null; remediation_role_arn: string | null; sso_role_name: string | null;
  validation_status: string; validation_detail: string | null; validated_at: string | null;
  remediation_validation_status: string; remediation_validation_detail: string | null; remediation_validated_at: string | null;
};
type KeyIdentity = { approved: object | null; remediation_role_name: string };
type Tone = "ok" | "partial" | "bad" | "running" | undefined;
type Purpose = "scanner" | "remediation";

/** The integrations whose targets this view lists: AWS accounts and GitHub organizations. */
export function reachKind(c: ProviderConnection): "aws" | "github" | null {
  if (c.provider === "aws" && c.children.some(child => child.kind === "aws_account")) return "aws";
  if (c.provider === "github" && inventories(c).length) return "github";
  return null;
}

/** The collections an integration's targets are read from: GitHub organization and enterprise inventories. */
export function inventories(c: ProviderConnection) {
  return c.children.filter(child => child.kind === "metadata" && child.purpose === "inventory");
}

const STATUS: Record<string, [string, string, Tone]> = {
  VALID: ["확인됨", "Confirmed", "ok"], INVALID: ["확인 실패", "Failed", "bad"], PENDING: ["확인 전", "Not checked", "partial"],
  NOT_CONFIGURED: ["설정 안 됨", "Not set up", undefined],
};
// The way in, in the words of the integration's sign-in methods (cremore_aws_provider/onboarding.py auth_methods).
const ACCESS: Record<string, [string, string]> = {
  ROLE: ["멤버 역할(CloudFormation)", "Member role (CloudFormation)"], RUNTIME_IDENTITY: ["이 설치의 AWS 신원", "This installation's AWS identity"],
  SSO_PERMISSION_SET: ["IAM Identity Center 권한 세트", "IAM Identity Center permission set"],
};
const KEY_IDENTITY_FIRST: [string, string] = ["키 조치 신원을 먼저 승인합니다(연동 설정의 로그인 단계).",
  "Approve the key-action identity first (the sign-in step of the integration's settings)."];
const WAIT_LIMIT = 120_000;

/** One purpose's access to an account in words: its state, and why where it is not confirmed. A key action waiting
 * for an approved identity waits for the key-action identity, not the one scanning runs as. */
export function accessText(status: string, detail: string | null, L: Say, purpose: Purpose = "scanner"): { text: string; tone: Tone; why: string | null } {
  const known = STATUS[status];
  const why = status === "VALID" || !detail ? null
    : purpose === "remediation" && detail === "IDENTITY_NOT_APPROVED" ? L(...KEY_IDENTITY_FIRST) : codeText(detail, L) ?? detail;
  return { text: known ? L(known[0], known[1]) : status, tone: known?.[2], why };
}

/** Why CreMore will not use an account for anything now, whatever its role checks say (aws_access.use_refusal): turned
 * off, or a discovery fact such as an account that left the organization. */
export function blocksOf(account: AwsAccount): string[] {
  return [...(account.enabled ? [] : ["ACCOUNT_DISABLED"]), ...(account.org_blocks ?? [])];
}

/** Whether an account's member stack is deployed from here: a member-role account in use that CreMore cannot reach yet
 * for scanning or for its key actions. An Organizations account's stack comes from the StackSet. */
export function deployable(account: AwsAccount): boolean {
  return account.access === "ROLE" && account.source !== "ORGANIZATION" && !blocksOf(account).length && (account.validation_status !== "VALID"
    || (Boolean(account.remediation_role_arn) && account.remediation_validation_status !== "VALID"));
}

/** Whether the worker has answered every scanning check asked for: each account's check time has moved since. */
export function answered(asked: Record<string, string | null>, accounts: AwsAccount[]): boolean {
  return Object.entries(asked).every(([id, at]) => {
    const account = accounts.find(item => item.id === id);
    return !account || account.validated_at !== at;
  });
}

/** The role a key-action role takes in an account: the account's partition and the installation's role name. */
export function keyActionRoleArn(account: AwsAccount, roleName: string): string {
  const part = (account.scanner_role_arn ?? "").split(":")[1];
  return `arn:${part?.startsWith("aws") ? part : "aws"}:iam::${account.account_id}:role/${roleName}`;
}

/** The inline policy an IAM Identity Center sign-in needs to assume the member roles (GET aws/scanner-identity policy):
 * a permission set made to read accounts directly assumes nothing. Before the identity is approved, the account
 * deployments say so themselves. */
export function HubPolicy() {
  const L = useL();
  const toast = useToast();
  const view = useApi<{ approved: object | null; policy: unknown }>("aws/scanner-identity", { every: 0 });
  if (!view.data?.approved) return null;
  const policy = JSON.stringify(view.data.policy, null, 2);
  const copy = () => navigator.clipboard ? navigator.clipboard.writeText(policy).then(() => toast(L("복사했습니다", "Copied")), () => toast(L("복사하지 못했습니다", "Could not copy"), "bad"))
    : toast(L("이 브라우저에서는 복사할 수 없습니다", "This browser cannot copy"), "bad");
  return <div className="reach-hub">
    <p className="ig-sub">{L("멤버 역할로 바꾼 계정은 CreMore가 로그인하는 권한 세트가 그 역할을 맡아 읽습니다. 권한 세트에 이 인라인 정책을 넣습니다.",
      "An account moved to a member role is read by the permission set CreMore signs in with assuming that role. Add this inline policy to the permission set.")}</p>
    <pre className="aws-set-code">{policy}</pre>
    <div className="aws-set-acts"><button type="button" className="ghost-btn" onClick={() => void copy()}><Ic name="copy" size={15} />{L("역할 맡기 정책 복사", "Copy the assume-role policy")}</button></div>
  </div>;
}

export function AwsAccounts({ conn }: { conn: ProviderConnection }) {
  const L = useL();
  const toast = useToast();
  const saved = useSaved();
  // Scanning checks the worker has not answered: each asked account's check time then, and when the last was asked. The
  // list is read again every few seconds until each time has moved, for two minutes at most (a result the worker could
  // not store never moves it).
  const [waiting, setWaiting] = useState<{ since: number; at: Record<string, string | null> } | null>(null);
  const accounts = useApi<AwsAccount[]>("aws/accounts", waiting ? { every: 5_000 } : {});
  // Each answer to a re-read checks again, a failed one too: the limit holds while the list cannot be read.
  useEffect(() => {
    if (waiting && (Date.now() - waiting.since > WAIT_LIMIT || answered(waiting.at, accounts.data ?? []))) setWaiting(null);
  }, [waiting, accounts.data, accounts.error]);
  const identity = useApi<KeyIdentity>("aws/remediation-identity", { every: 0 });
  const [busy, setBusy] = useState<string | null>(null);
  // Accounts whose member stack deployment is open: asked for, or opened after a key-action role was added or the account was moved.
  const [deploy, setDeploy] = useState<string[]>([]);
  const [confirm, setConfirm] = useState<string | null>(null);
  // A read that fails after one that worked keeps the table, its open deployments and an open question.
  if (accounts.error && !accounts.data) return <ErrorLine onRetry={accounts.reload}>{reasonText(accounts.error, L)}</ErrorLine>;
  if (!accounts.data) return <Loading />;
  const ids = new Set(conn.children.filter(child => child.kind === "aws_account").map(child => child.id));
  const rows = accounts.data.filter(account => ids.has(account.id)).sort((a, b) => a.account_id.localeCompare(b.account_id));
  const open = (id: string) => setDeploy(current => current.includes(id) ? current : [...current, id]);
  const act = async (key: string, work: () => Promise<string>, refused: (reason: unknown) => string = reason => reasonText(reason, L)) => {
    setBusy(key);
    try { toast(await work()); saved(); accounts.reload(); } catch (reason) { toast(refused(reason), "bad"); } finally { setBusy(null); }
  };
  // Scanning access is usually checked by the worker (queued); key-action access by the API at once, which answers with
  // the state. A key action refused for want of an approved identity waits for the key-action identity.
  const check = (account: AwsAccount, purpose: Purpose) => act(`${purpose}:${account.id}`, async () => {
    const result = await send<{ status: string; detail: string | null; check: string }>(`aws/accounts/${account.id}/validate?purpose=${purpose}`, "POST", {});
    if (result.check === "QUEUED") {
      setWaiting(current => ({ since: Date.now(), at: { ...current?.at, [account.id]: account.validated_at } }));
      return L("스캔 접근 확인을 요청했습니다. 작업자가 확인하면 상태가 바뀝니다.", "Asked to check scanning access; the state changes once the worker has checked it.");
    }
    const state = accessText(result.status, result.detail, L, purpose);
    const what = purpose === "scanner" ? L("스캔 접근", "Scanning access") : L("키 조치 접근", "Key-action access");
    return `${what}: ${state.text}${state.why ? ` · ${state.why}` : ""}`;
  }, reason => purpose === "remediation" && reason instanceof DashboardAPIError && reason.message.split(":", 1)[0].trim() === "IDENTITY_NOT_APPROVED"
    ? L(...KEY_IDENTITY_FIRST) : reasonText(reason, L));
  const addRole = (account: AwsAccount, roleName: string) => act(`role:${account.id}`, async () => {
    await send(`aws/accounts/${account.id}`, "PATCH", { remediation_role_arn: keyActionRoleArn(account, roleName) });
    open(account.id);
    return L("키 조치 역할을 정했습니다. 아래 CLI 명령으로 계정의 스택을 다시 배포합니다.", "The key-action role is set. Deploy the account's stack again with the CLI command below.");
  });
  const promote = (account: AwsAccount) => act(`promote:${account.id}`, async () => {
    await send(`aws/accounts/${account.id}/promote`, "POST", {});
    setConfirm(null);
    open(account.id);
    return L("멤버 역할로 바꿨습니다. 아래 배포로 역할을 만든 뒤 스캔 접근을 확인합니다.", "Moved to a member role. Create it with the deployment below, then check scanning access.");
  });
  // A key-action role can be added once the key-action identity is approved (its trust goes into the account's stack).
  const roleName = identity.data?.approved ? identity.data.remediation_role_name : null;
  const roleWhy = identity.error ? reasonText(identity.error, L) : identity.data && !identity.data.approved ? L(...KEY_IDENTITY_FIRST) : null;
  // An IAM Identity Center sign-in reaches a member role only with the assume-role policy: shown once, above the table.
  const hub = conn.auth_method === "sso" && rows.some(account => account.access === "ROLE" && deploy.includes(account.id));
  if (!rows.length) return <p className="ig-sub">{L("이 연동이 닿는 AWS 계정이 아직 없습니다.", "This integration reaches no AWS account yet.")}</p>;
  return <>
    {hub ? <HubPolicy /> : null}
    <div className="sub-scroll"><table className="sub-tbl reach-tbl">
      <thead><tr><th>{L("계정", "Account")}</th><th>{L("스캔 접근", "Scanning access")}</th><th>{L("키 조치 접근", "Key-action access")}</th></tr></thead>
      <tbody>{rows.map(account => <AwsAccountRow key={account.id} account={account} busy={busy !== null} roleName={roleName} roleWhy={roleWhy}
        confirming={confirm === account.id} opened={deploy.includes(account.id)}
        deployment={deploy.includes(account.id) ? <AccountRole id={account.id} update={account.validation_status === "VALID"}
          vault={conn.plans?.vault} /> : null}
        onCheck={purpose => void check(account, purpose)} onAddRole={name => void addRole(account, name)}
        onPromote={() => confirm === account.id ? void promote(account) : setConfirm(account.id)} onCancel={() => setConfirm(null)}
        onDeploy={() => setDeploy(current => current.includes(account.id) ? current.filter(id => id !== account.id) : [...current, account.id])} />)}</tbody>
    </table></div>
  </>;
}

/** One account: how it is reached, whether scanning and key actions can reach it and why not, and what to do next. */
export function AwsAccountRow({ account, busy, roleName, roleWhy, confirming, opened, deployment, onCheck, onAddRole, onPromote, onCancel, onDeploy }: {
  account: AwsAccount; busy: boolean; roleName: string | null; roleWhy: string | null; confirming: boolean; opened: boolean; deployment: ReactNode;
  onCheck: (purpose: Purpose) => void; onAddRole: (roleName: string) => void; onPromote: () => void; onCancel: () => void; onDeploy: () => void;
}) {
  const L = useL();
  const locale = useLocale();
  // The question to move takes focus (Cancel) and hands it back to the move button when answered with Cancel; a
  // deployment that opens (the account moved, a role added) takes focus, as what comes next.
  const promoteButton = useRef<HTMLButtonElement>(null);
  const toggleButton = useRef<HTMLButtonElement>(null);
  const cancelled = useRef(false);
  const wasOpened = useRef(opened);
  useEffect(() => {
    if (!confirming && cancelled.current) { cancelled.current = false; promoteButton.current?.focus(); }
  }, [confirming]);
  useEffect(() => {
    if (opened && !wasOpened.current) toggleButton.current?.focus();
    wasOpened.current = opened;
  }, [opened]);
  const scan = accessText(account.validation_status, account.validation_detail, L);
  const keys = accessText(account.remediation_validation_status, account.remediation_validation_detail, L, "remediation");
  const blocks = blocksOf(account);
  const sso = account.access === "SSO_PERMISSION_SET";
  const noRole = account.access === "ROLE" && !account.remediation_role_arn;
  // Turned off or blocked by discovery, an account is used for nothing, whatever its last check said.
  const notUsed = <StateChip tone="bad">{L("쓰지 않음", "Not used")}</StateChip>;
  return <>
    <tr>
      <td data-label={L("계정", "Account")}><b className="mono">{account.account_id}</b>{account.name && account.name !== account.account_id ? <div className="cell-wrap">{account.name}</div> : null}
        <div className="subtle small">{ACCESS[account.access] ? L(...ACCESS[account.access]) : account.access}{account.source === "ORGANIZATION" ? " · Organizations StackSet" : ""}</div>
        {blocks.length ? <div className="ig-sub">{blocks.map(code => code === "ACCOUNT_DISABLED" ? L("이 계정은 꺼져 있습니다.", "This account is turned off.") : codeText(code, L) ?? code).join(" ")}</div> : null}
        {opened || deployable(account) ? <div><button type="button" className="link-btn small" ref={toggleButton} aria-expanded={opened} onClick={onDeploy}>{opened ? L("배포 닫기", "Hide the deployment") : L("배포 보기", "Show the deployment")}</button></div> : null}</td>
      <td data-label={L("스캔 접근", "Scanning access")}>{blocks.length ? notUsed : <StateChip tone={scan.tone}>{scan.text}</StateChip>}
        {scan.why ? <div className="ig-sub">{scan.why}</div> : null}
        {account.validated_at ? <div className="subtle small">{rel(account.validated_at, locale)}</div> : null}
        <div><button type="button" className="link-btn small" disabled={busy} onClick={() => onCheck("scanner")}>{L("스캔 접근 확인", "Check scanning access")}</button></div></td>
      <td data-label={L("키 조치 접근", "Key-action access")}>{sso ? <>
        <div role="status">{confirming ? <Banner tone="warn" icon="alert">{L("멤버 역할로 바꾸면 계정에 역할을 배포하고 확인할 때까지 이 계정을 스캔하지 않습니다. 권한 세트 방식으로 되돌릴 수 없습니다.",
          "Once moved, this account is not scanned until its role is deployed and checked. It cannot be moved back to the permission set.")}</Banner> : null}</div>
        {confirming ? <div className="aws-set-acts">
          <button type="button" className="primary-btn" disabled={busy} onClick={onPromote}>{L("멤버 역할로 바꾸기", "Move to a member role")}</button>
          <button type="button" className="ghost-btn" disabled={busy} autoFocus onClick={() => { cancelled.current = true; onCancel(); }}>{L("취소", "Cancel")}</button>
        </div> : <>
          <div className="ig-sub">{L("권한 세트로는 스캔만 합니다. 키 조치는 멤버 역할로 바꾼 계정에서 합니다.", "A permission set only scans. Key actions run in an account moved to a member role.")}</div>
          <button type="button" className="link-btn small" ref={promoteButton} disabled={busy} onClick={onPromote}>{L("멤버 역할로 바꾸기", "Move to a member role")}</button></>}</>
        : noRole ? (account.source === "ORGANIZATION"
          ? <div className="ig-sub">{L("Organizations StackSet으로 닿는 계정에는 여기서 키 조치 역할을 더하지 않습니다.", "A key-action role is not added here to an account reached through the Organizations StackSet.")}</div>
          : roleName ? <button type="button" className="link-btn small" disabled={busy} onClick={() => onAddRole(roleName)}>{L("키 조치 역할 추가", "Add the key-action role")}</button>
            : roleWhy ? <div className="ig-sub">{roleWhy}</div> : null)
          : <>{blocks.length ? notUsed : <StateChip tone={keys.tone}>{keys.text}</StateChip>}
            {keys.why ? <div className="ig-sub">{keys.why}</div> : null}
            {account.remediation_validated_at ? <div className="subtle small">{rel(account.remediation_validated_at, locale)}</div> : null}
            {/* Without an approved key-action identity the API refuses the check: the reason above says what to do. */}
            {account.remediation_validation_detail !== "IDENTITY_NOT_APPROVED"
              ? <div><button type="button" className="link-btn small" disabled={busy} onClick={() => onCheck("remediation")}>{L("키 조치 접근 확인", "Check key-action access")}</button></div> : null}</>}</td>
    </tr>
    {deployment ? <tr className="reach-deploy"><td colSpan={3}>{deployment}</td></tr> : null}
  </>;
}
/* ---------- GitHub: the organizations an inventory reads and this App's installation on each ---------- */

/** An organization as GET .../github-organizations serves it (cremore_github_provider metadata snapshot.organization_roster,
 * permissions.organization_health). */
export type GitHubOrg = {
  org: string; status: string; reasons: string[];
  health: { status: string; reason: string; checked_at: string | null; repository_selection: string; sources: { kind: string; missing: string[]; status: string }[] };
};
type GitHubRoster = { run: { id: string; status: string; finished_at: string | null } | null; current_revision: boolean; items: GitHubOrg[]; total: number;
  discovery: { status: string; reasons: string[] } };
type AuditLinks = { counts: { events: number; linked: number; unmatched: number };
  sources?: { connection_id: string; current_revision: boolean; inventory: boolean; audit: boolean;
    run: { status: string; finished_at: string | null; reasons: string[] } | null }[] };

export function GitHubAuditSources({ sources }: { sources: AuditLinks["sources"] }) {
  const L = useL(), locale = useLocale();
  if (!sources?.length) return null;
  return <section className="ig-section"><b>{L("감사 연결에 사용한 수집 근거", "Collection evidence used for audit links")}</b>
    <dl className="md-kv">{sources.map(source => <div key={source.connection_id}>
      <dt>{source.inventory && source.audit ? L("인벤토리·감사 로그", "Inventory and audit")
        : source.audit ? L("감사 로그", "Audit") : L("인벤토리", "Inventory")}</dt>
      <dd className="cell-wrap">{source.run ? <>
        {source.run.status === "COMPLETE" ? L("수집 완료", "Complete collection") : L("부분 수집", "Partial collection")}
        {source.run.finished_at ? ` · ${fmtDT(source.run.finished_at, locale)}` : ""}
        {!source.current_revision ? ` · ${L("설정 변경 전 근거", "Evidence from an earlier configuration")}` : ""}
        {source.run.reasons.length ? <div className="ig-sub">{source.run.reasons.map(code => codeText(code, L)).join(" · ")}</div> : null}
      </> : L("사용 가능한 수집 근거 없음", "No eligible collection evidence")}</dd>
    </div>)}</dl>
    <p className="ig-sub">{L("서로 다른 시점의 관측을 식별자로 연결한 결과입니다. 실시간 유효성이나 실제 열람을 입증하지 않습니다.",
      "Observations from different times are linked by identifiers. They do not prove current validity or actual viewing.")}</p>
  </section>;
}

const HEALTH: Record<string, [string, string, Tone]> = {
  permissions_present: ["권한 있음", "Permissions present", "ok"], limited: ["권한 부족", "Missing permissions", "partial"],
  suspended: ["설치 정지됨", "Installation suspended", "bad"], not_installed: ["설치 안 됨", "Not installed", "bad"],
  unknown: ["확인 안 됨", "Not confirmed", undefined],
};
const HEALTH_REASONS: Record<string, [string, string]> = {
  installation_not_checked: ["아직 설치를 확인하지 않았습니다", "The installation is not checked yet"],
  installation_permissions_unavailable: ["설치의 권한 정보를 받지 못했습니다", "The installation's permissions were not returned"],
};

/** This App's installation on an organization in words: its state and, where it falls short, what is missing or why. */
export function healthText(health: GitHubOrg["health"], L: Say, locale: Locale): { text: string; tone: Tone; why: string | null } {
  const known = HEALTH[health.status];
  const missing = [...new Set(health.sources.flatMap(source => source.missing))];
  const why = health.status === "limited" ? L(`없는 권한: ${missing.join(", ")}`, `Missing: ${missing.join(", ")}`)
    : health.status === "not_installed" ? L("App의 전체 설치 목록에 없습니다", "Not in the App's complete installation list")
      : health.status === "unknown" ? (HEALTH_REASONS[health.reason] ? L(...HEALTH_REASONS[health.reason]) : failureCodeLabel(health.reason, locale))
        : null;
  return { text: known ? L(known[0], known[1]) : health.status, tone: known?.[2], why };
}

/** The organizations: this App's installation on each, what its reads last did, and a check where one can run. */
export function GitHubOrgTable({ items, ready, busy, onCheck }: { items: GitHubOrg[]; ready: boolean; busy: boolean; onCheck: (org: string) => void }) {
  const L = useL();
  const locale = useLocale();
  return <div className="sub-scroll"><table className="sub-tbl reach-tbl">
    <thead><tr><th>{L("조직", "Organization")}</th><th>{L("App 설치", "App installation")}</th><th>{L("마지막 수집", "Last collection")}</th></tr></thead>
    <tbody>{items.map(org => {
      const health = healthText(org.health, L, locale);
      const [run, tone] = runText(org.status, L);
      return <tr key={org.org}>
        <td data-label={L("조직", "Organization")}><b>{org.org}</b></td>
        <td data-label={L("App 설치", "App installation")}><StateChip tone={health.tone}>{health.text}</StateChip>
          {health.why ? <div className="ig-sub">{health.why}</div> : null}
          {org.health.checked_at ? <div className="subtle small">{rel(org.health.checked_at, locale)}</div> : null}
          {ready ? <div><button type="button" className="link-btn small" disabled={busy} onClick={() => onCheck(org.org)}>{L("설치 다시 확인", "Check the installation again")}</button></div> : null}</td>
        <td data-label={L("마지막 수집", "Last collection")}><StateChip tone={tone}>{run}</StateChip>
          {org.reasons.length ? <div className="ig-sub">{org.reasons.map(code => failureCodeLabel(code, locale)).join(" · ")}</div> : null}</td>
      </tr>;
    })}</tbody>
  </table></div>;
}

/** One inventory collection's organizations (an organization's, or an enterprise's). */
export function GitHubOrgs({ child }: { child: Child }) {
  const L = useL();
  const locale = useLocale();
  const toast = useToast();
  const saved = useSaved();
  const base = `v2/coverage/connections/${child.id}`;
  const roster = useApi<GitHubRoster>(`${base}/github-organizations?limit=100`);
  const audit = useApi<AuditLinks>(`${base}/github-audit-links?limit=1`, { every: 30_000 });
  const [busy, setBusy] = useState(false);
  if (roster.error && !roster.data) return <ErrorLine onRetry={roster.reload}>{reasonText(roster.error, L)}</ErrorLine>;
  if (!roster.data) return <Loading />;
  const r = roster.data;
  // An installation check re-reads only this App's installation (one organization, or its installation list).
  const check = async (org?: string) => {
    setBusy(true);
    try {
      await send(`${base}/github-installation-check`, "POST", org ? { org } : {});
      toast(org ? L(`${org}의 설치 확인을 요청했습니다`, `Asked to check the installation on ${org}`) : L("App의 설치 목록 확인을 요청했습니다", "Asked to check the App's installation list"));
      saved();
    } catch (reason) { toast(reasonText(reason, L), "bad"); } finally { setBusy(false); }
  };
  const ready = Boolean(r.run && r.run.status !== "RUNNING" && r.current_revision);
  const counts = audit.data?.counts;
  return <>
    <GitHubCollections connections={[child]} />
    {audit.error ? <ErrorLine onRetry={audit.reload}>{reasonText(audit.error, L)}</ErrorLine> : <GitHubAuditSources sources={audit.data?.sources} />}
    {!r.run ? <p className="ig-sub">{L("아직 수집하지 않았습니다. 첫 수집이 끝나면 조직과 설치가 보입니다.", "Not collected yet. The organizations and installations show after the first collection.")}</p>
      : !r.current_revision ? <p className="ig-sub">{L("설정을 바꾼 뒤 아직 수집하지 않았습니다. 설치 확인은 다음 수집이 끝난 뒤에 합니다.", "Not collected since the settings changed. Installations can be checked once the next collection finishes.")}</p> : null}
    {/* An enterprise's organization list that stopped short (an organization collection lists none: NOT_COLLECTED). */}
    {r.run && (r.discovery.status === "PARTIAL" || r.discovery.status === "FAILED") ? <p className="ig-sub">{L("조직 목록을 다 읽지 못했습니다", "The organization list was not read in full")} ({runText(r.discovery.status, L)[0]}){r.discovery.reasons.length ? ` · ${r.discovery.reasons.map(code => failureCodeLabel(code, locale)).join(" · ")}` : ""}</p> : null}
    {r.items.length ? <GitHubOrgTable items={r.items} ready={ready} busy={busy} onCheck={org => void check(org)} />
      : r.run ? <p className="ig-sub">{L("이 수집이 읽은 조직이 없습니다", "This collection read no organization")}{r.run.status !== "COMPLETE" ? ` (${runText(r.run.status, L)[0]})` : ""}.</p> : null}
    {r.total > r.items.length ? <p className="ig-sub">{L(`조직 ${r.total}개 중 ${r.items.length}개를 보여 줍니다.`, `Showing ${r.items.length} of ${r.total} organizations.`)}</p> : null}
    <div className="aws-set-acts">
      {ready ? <button type="button" className="ghost-btn" disabled={busy} onClick={() => void check()}>{L("App 설치 목록 다시 확인", "Check the App's installation list again")}</button> : null}
      {counts && counts.events ? <span className="ig-sub">{L(`감사 로그 이벤트 ${counts.events}건 중 Credential에 연결 ${counts.linked}건 · 연결 안 됨 ${counts.unmatched}건`,
        `Audit log: ${counts.linked} of ${counts.events} events linked to a credential · ${counts.unmatched} not linked`)}</span> : null}
    </div>
  </>;
}

/* ---------- Google Cloud: what a project's collections observed, and what changed ---------- */

export function ReachModal({ conn, onClose }: { conn: ProviderConnection; onClose: () => void }) {
  const L = useL();
  const kind = reachKind(conn);
  return <Modal onClose={onClose} labelledBy="reach-title" className="integ">
    <h2 id="reach-title"><Logo id={conn.provider} size={26} />{L("연결 대상 현황", "Connected targets")} <small>{conn.name || serviceName(conn.provider)}</small></h2>
    {kind === "aws" ? <AwsAccounts conn={conn} />
      // An enterprise's inventory is a collection of its own: each collection's organizations, under its name.
      : kind === "github" ? inventories(conn).map((child, index, all) => all.length > 1
        ? <div className="ig-section" key={child.id}><div className="ig-section-head"><h3>{child.name ?? child.id}</h3></div><GitHubOrgs child={child} /></div>
        : <GitHubOrgs key={child.id} child={child} />)
        : null}
    <div className="modal-foot"><button type="button" className="ghost-btn" onClick={onClose}>{L("닫기", "Close")}</button></div>
  </Modal>;
}
