"use client";

/* Setup steps: what an admin does at the provider so the chosen sign-in works, in one list every provider
 * shares -- a policy to copy, a template to download, a link that opens the provider's own screen with the
 * settings filled in. A provider adds steps here; the wizard shows them the same way for all. */

import { type ReactNode, useState } from "react";

import { reasonText, useApi } from "@/console/data";
import { Ic, type IconName } from "@/console/icons";
import type { Say } from "@/console/text";
import { useL } from "@/console/text";
import { SelectField } from "@/console/ui";
import type { AwsIdentityView } from "@/console/views/integrations/aws-identity";
import {
  type Descriptor, listValue, type Method, permissionsFor, type ProviderConnection, type Purpose, type Values,
} from "@/console/views/integrations/model";

export type GuideAction =
  | { kind: "copy"; label: string; text: string; icon?: IconName }
  | { kind: "link"; label: string; href: string; download?: string; external?: boolean; icon?: IconName }
  | { kind: "open"; label: string; onOpen: () => void; icon?: IconName };
export type GuideStep = { key: string; title: string; text?: string; actions?: GuideAction[]; body?: ReactNode };
/** A connection to guide; ``roots`` are the targets an onboarding chose, each with the features it serves. */
type GuideConnection = Pick<ProviderConnection, "target" | "children" | "purposes"> & { roots?: Root[] };
type Root = { purposes: string[]; target: Record<string, unknown> };

/** What the providers need from the admin before a sign-in method works; ``target`` and ``plans`` are step 1's
 * choices and ``stored`` whether the connection already holds a credential of this method. */
export type GuideContext = {
  aws?: AwsIdentityView | null; openMachine?: () => void; target?: Record<string, unknown>;
  plans?: Partial<Record<Purpose, Values>>; stored?: boolean;
};

// Methods that reach a cloud or Vault as this installation's own identity, which can be the company IdP's.
const AMBIENT: Record<string, string[]> = {
  aws: ["role", "runtime"],
};

export function guideSteps(d: Descriptor, method: Method, conn: GuideConnection | null, context: GuideContext, L: Say): GuideStep[] {
  const steps = d.provider === "aws" ? awsSteps(method, conn, context.aws ?? null, L, context.openMachine, context.plans?.vault)
    : d.provider === "slack" && method.id === "token" ? slackSteps(context.plans?.inventory?.audit_events === true, Boolean(context.stored), L) : [];
  if (context.openMachine && AMBIENT[d.provider]?.includes(method.id) && !steps.some(step => step.key === "aws-bootstrap")) steps.push(machineStep(d.provider, context.openMachine, L));
  return steps;
}

function machineStep(provider: string, open: () => void, L: Say): GuideStep {
  return { key: "machine", title: L("회사 IdP 신원으로 접근 (선택)", "Reach it as the company IdP identity (optional)"),
    text: L("회사 IdP의 기계 토큰으로 AWS에 접근하려면 기계 신원을 설정하세요.", "Set the machine identity to reach AWS with a token from your company IdP."),
    actions: [{ kind: "open", label: L("기계 신원 설정", "Set the machine identity"), onOpen: open, icon: "shield" }] };
}

function json(value: unknown) {
  return JSON.stringify(value, null, 2);
}

function AwsIdentitySetup({ openMachine }: { openMachine?: () => void }) {
  const L = useL();
  const [host, setHost] = useState("");
  return <>
    <SelectField label={L("CreMore 서버 실행 위치", "Where the CreMore server runs")} value={host} onChange={setHost} options={[
      { id: "", label: L("실행 위치 선택", "Choose the hosting environment") }, { id: "ec2", label: "Amazon EC2" },
      { id: "kubernetes", label: L("EKS·쿠버네티스", "EKS / Kubernetes") }, { id: "external", label: L("사내 서버·다른 클라우드", "On-premises / another cloud") },
    ]} />
    {host === "ec2" ? <>
      <p>{L("인프라 관리자가 EC2용 IAM 역할을 만들거나 기존 역할을 선택해 CreMore 인스턴스에 연결합니다. 역할에는 자기 역할을 읽는 iam:GetRole 권한을 포함합니다.",
        "An infrastructure administrator creates or selects an EC2 IAM role and attaches it to the CreMore instance. Include iam:GetRole for the role itself.")}</p>
      <p>{L("API와 워커가 같은 인스턴스 역할을 쓰도록 배포하고 IMDSv2 접근을 허용하세요. 컨테이너에서 실행하면 응답 홉 제한을 2로 둡니다(aws ec2 modify-instance-metadata-options --instance-id <ID> --http-put-response-hop-limit 2). 설정 후 ‘AWS 신원 다시 확인’을 누르면 역할을 자동으로 읽습니다.",
        "Configure the API and worker to use the same instance role with access to IMDSv2. In containers, set the response hop limit to 2 (aws ec2 modify-instance-metadata-options --instance-id <ID> --http-put-response-hop-limit 2). Then refresh the AWS identity to detect the role automatically.")}</p>
      <a className="ghost-btn" href="https://console.aws.amazon.com/ec2/home#Instances:" target="_blank" rel="noopener noreferrer">{L("EC2 콘솔 열기", "Open the EC2 console")}</a>
    </> : host === "kubernetes" ? <>
      <p>{L("EKS는 API·워커 ServiceAccount에 같은 IAM 역할을 IRSA 또는 Pod Identity로 연결합니다. 다른 쿠버네티스는 클러스터 OIDC 토큰을 신뢰하는 AWS 역할과 갱신되는 토큰 파일을 연결합니다.",
        "On EKS, bind the API and worker ServiceAccounts to the same IAM role using IRSA or Pod Identity. On other Kubernetes clusters, configure an AWS role trusting the cluster OIDC token and mount the rotating token file.")}</p>
      <p>{L("역할에는 자기 역할을 읽는 iam:GetRole을 포함하고, API와 워커가 모두 새 신원으로 실행된 후 다시 확인하세요.",
        "Include iam:GetRole for the role itself, then refresh after both the API and worker are running with that identity.")}</p>
    </> : host === "external" ? <>
      <p>{L("회사 인증서를 쓰는 서버는 IAM Roles Anywhere로도 연결할 수 있습니다. 서버 관리자가 인증서·개인키와 검증된 AWS signing helper를 배포하면 SDK가 임시 자격증명을 자동 갱신합니다. 인증서 자체는 회사 PKI에서 만료 전에 교체해야 합니다.",
        "Servers with a company certificate can also use IAM Roles Anywhere. An administrator deploys the certificate, private key and verified AWS signing helper; the SDK renews temporary credentials automatically. The company PKI must replace the certificate before it expires.")}</p>
      <a href="https://github.com/y4rvin/CreMore/blob/integration/saas-structure/docs/UNATTENDED_DEPLOYMENT.md" target="_blank" rel="noopener noreferrer">{L("Roles Anywhere·온프레미스 설정 안내", "Roles Anywhere and on-premises setup")}</a>
      <p>{L("서버에 AWS 신원이 없어도 회사 IdP의 서버용 앱과 AWS OIDC 신뢰 역할을 한 번 설정하면 됩니다. 기존 기계 신원 설정에서 안내 명령을 받고, API와 워커가 이후 토큰을 자동으로 갱신합니다.",
        "A server without an AWS identity can use a company IdP service app and an AWS role trusting its OIDC tokens. The machine identity setup provides the trust commands; the API and worker then renew the tokens automatically.")}</p>
      {openMachine ? <button type="button" className="ghost-btn" onClick={openMachine}>{L("회사 IdP로 서버 신원 설정", "Set up the server identity with the company IdP")}</button>
        : <p>{L("관리자가 회사 IdP 기계 신원을 설정해야 합니다.", "An administrator must configure the company IdP machine identity.")}</p>}
    </> : null}
    {host ? <p><a href="https://github.com/y4rvin/CreMore/blob/integration/saas-structure/docs/MACHINE_IDENTITY.md" target="_blank" rel="noopener noreferrer">{L("배포·신뢰 설정 안내", "Deployment and trust setup guide")}</a></p> : null}
  </>;
}

/** The hub policy (cremore_aws_provider.aws_identity.hub_policy) with the accounts being connected added to its account
 * condition, which names only registered ones; an organization condition covers them, and a policy naming none yet
 * gets them as its first. */
export function withAccounts(policy: unknown, accounts: string[]): unknown {
  const statement = (policy as { Statement?: Record<string, unknown>[] } | null)?.Statement?.[0];
  const condition = statement?.Condition as { StringEquals?: Record<string, string[]> } | undefined;
  if (!statement || !accounts.length || condition?.StringEquals?.["aws:ResourceOrgID"]) return policy;
  const listed = condition?.StringEquals?.["aws:ResourceAccount"] ?? [];
  return { ...(policy as object), Statement: [{ ...statement,
    Condition: { StringEquals: { "aws:ResourceAccount": [...new Set([...listed, ...accounts])].sort() } } }] };
}

const READER_ROLE = "CredentialVaultValueReaderRole";
// The server's rules (cremore/coverage/models.py and secret_inventory._ARN; cremore_aws_provider/onboarding.py _KMS_KEY,
// and _SSM_PATH with its "."/".." segment refusal for a Parameter Store path).
const SECRET_ARN = /^arn:(aws|aws-us-gov|aws-cn|aws-eusc):secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}$/;
const KMS_KEY = /^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key\/[A-Za-z0-9-]{1,128}$/;
const SSM_PATH = /^[A-Za-z0-9_.-]+(\/[A-Za-z0-9_.-]+)*$/;
const ssmPath = (path: string) => SSM_PATH.test(path) && !path.split("/").some(segment => segment === "." || segment === "..");

/** The member-role stack parameters (deploy/cloudformation/member-account-role.yaml) that also make the value-reader
 * role, when the vault comparison reads values with it (the vault plan's ``value_reader``, as the form holds it or as
 * saved): the account's own secrets and KMS keys, and each Parameter Store path in each chosen region with what lies
 * below it (IAM authorizes the requested path). A value the server would refuse is left out; it checks the plan again. */
export function valueReaderParameters(plan: Record<string, unknown> | undefined, partition: string, account: string): Record<string, string> {
  if (plan?.value_reader !== true) return {};
  const role = String(plan.value_reader_role ?? "").trim();
  const own = (arn: string) => arn.split(":")[4] === account;
  const paths = listValue(plan.ssm_prefixes).map(prefix => prefix.replace(/^\/+|\/+$/g, "")).filter(ssmPath)
    .flatMap(path => listValue(plan.regions).filter(region => /^[a-z0-9-]+$/.test(region))
      .flatMap(region => [`arn:${partition}:ssm:${region}:${account}:parameter/${path}`, `arn:${partition}:ssm:${region}:${account}:parameter/${path}/*`]));
  return {
    EnableVaultValueRead: "true",
    VaultValueReaderRoleName: /^[A-Za-z0-9+=,.@_-]{1,64}$/.test(role) ? role : READER_ROLE,
    VaultSecretArns: listValue(plan.secret_arns).filter(arn => SECRET_ARN.test(arn) && own(arn)).join(","),
    VaultParameterPathArns: paths.join(","),
    VaultKmsKeyArns: listValue(plan.kms_key_arns).filter(arn => KMS_KEY.test(arn) && own(arn)).join(","),
  };
}

/** Parameters added to a ``cli_command`` (cremore_aws_provider.aws_identity): one quoted Key=Value each. */
const overrides = (params: Record<string, string>) => Object.entries(params).map(([key, value]) => ` '${key}=${value}'`).join("");

function readerText(vault: Record<string, unknown> | undefined, L: Say) {
  const { EnableVaultValueRead: on, VaultValueReaderRoleName: role } = valueReaderParameters(vault, "aws", "");
  return on ? L(` 금고 값 대조를 켰으므로 값 읽기 역할(${role})의 매개변수가 함께 들어갑니다. 이미 배포한 스택은 이 값으로 갱신합니다.`,
    ` Vault comparison reads values, so the value-reader role's parameters (${role}) are included; update a stack already deployed with them.`) : "";
}

function awsSteps(method: Method, conn: GuideConnection | null, view: AwsIdentityView | null, L: Say, openMachine?: () => void,
  vault?: Record<string, unknown>): GuideStep[] {
  if (!view || method.id === "customer_cli") return [];
  if (view.api.state !== "READY" && (method.id === "role" || method.id === "runtime")) return [{ key: "aws-bootstrap",
    title: L("서버 AWS 신원 먼저 설정하기", "Set up the server's AWS identity first"),
    text: L("AWS 접근은 서버 신원과 AWS의 신뢰 설정이 필요합니다. 인프라 관리자가 최초 한 번 설정한 뒤 담당자는 자동 확인된 신원과 수집 대상을 선택합니다.",
      "AWS access requires a server identity and AWS trust. An infrastructure administrator sets this up once; operators then select the detected identity and collection targets."),
    body: <AwsIdentitySetup openMachine={openMachine} /> }];
  const steps: GuideStep[] = [];
  const caller = view.api.caller_arn?.match(/^arn:(aws(?:-[a-z]+)*):sts::([0-9]{12}):assumed-role\/([A-Za-z0-9+=,.@_-]{1,64})\/[A-Za-z0-9+=,.@_-]{1,64}$/);
  if (view.api.requires === "ROLE_ARN" && caller) {
    const [, partition, account, role] = caller;
    // IAM role names are unique within an account; both resources name this role, with or without a path.
    const lookup = { Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: "iam:GetRole",
      Resource: [`arn:${partition}:iam::${account}:role/${role}`, `arn:${partition}:iam::${account}:role/*/${role}`] }] };
    steps.push({ key: "identity-lookup", title: L("서버 역할 자동 확인 권한 설정", "Allow automatic server role lookup"),
      text: L(`서버 신원은 확인됐지만 역할의 전체 경로를 읽지 못했습니다. 인프라 관리자가 ${role} 역할에 아래 조회 정책을 추가한 뒤 ‘AWS 신원 다시 확인’을 누르세요. 담당자가 ARN을 입력할 필요가 없습니다.`,
        `The server identity is known, but its full role path could not be read. Ask an infrastructure administrator to add this lookup policy to ${role}, then refresh the AWS identity. Operators do not need to enter the ARN.`),
      actions: [{ kind: "copy", label: L("자기 역할 조회 정책 복사", "Copy self-role lookup policy"), text: json(lookup) },
        { kind: "link", label: L("IAM 역할 설정 열기", "Open IAM role settings"), href: `https://console.aws.amazon.com/iam/home#/roles/details/${encodeURIComponent(role)}`, external: true }] });
  }
  if (method.id === "role") {
    const draftAccounts = ((conn?.target.generated as { aws_roles?: { account_id: string }[] } | undefined)?.aws_roles ?? []).map(role => role.account_id);
    steps.push({ key: "hub", title: L("CreMore 신원에 역할 맡기 권한 주기", "Let CreMore's identity assume the roles"),
      text: L("CreMore 서버의 IAM 역할에 이 인라인 정책을 넣습니다. 등록한 계정(모두 한 조직에 있으면 그 조직)과 지금 연결하는 계정의 이 이름 읽기 역할만 맡게 하며, 계정을 더 연결하면 그때 보이는 정책으로 바꿉니다. 역할을 실제로 맡으려면 그 역할의 신뢰 정책이 CreMore 신원을 허용해야 합니다(계정별 역할 템플릿은 ExternalId도 요구).",
        "Add this inline policy to the CreMore server's IAM role. It lets it assume the read role of this name only in the registered accounts (their organization, when all are in one) and the ones being connected now; when you connect more, replace it with the policy shown then. A role can only be assumed if its trust policy allows CreMore's identity (the per-account role template also requires the ExternalId)."),
      actions: [{ kind: "copy", label: L("정책 복사", "Copy policy"), text: json(withAccounts(view.policy, draftAccounts)) }] });
    steps.push({ key: "organization-list", title: L("조직 계정 자동 조회 (선택)", "Discover organization accounts (optional)"),
      text: L("Organizations 위임 관리자 계정(권장) 또는 관리 계정에서 실행하는 서버 역할에 계정 목록과 조직·OU 구조를 읽는 권한을 줍니다. 이 권한이 없어도 기존 등록 계정과 서버 자신의 계정은 수집 역할로 연결할 수 있습니다.",
        "Let the server role in an Organizations delegated administrator account (preferred) or the management account read the account list and the organization's OU structure. Without it, registered accounts and the server's own account can still connect through collection roles."),
      actions: [{ kind: "copy", label: L("조직 목록 조회 정책 복사", "Copy organization listing policy"),
        text: json({ Version: "2012-10-17", Statement: [{ Effect: "Allow", Action: ["organizations:ListAccounts",
          "organizations:ListAccountsForParent", "organizations:ListOrganizationalUnitsForParent", "organizations:ListRoots",
          "organizations:DescribeOrganization"], Resource: "*" }] }) }] });
    const accounts = conn?.children.filter(child => child.kind === "aws_account") ?? [];
    const draftRoles = (conn?.target.generated as { aws_roles?: { account_id: string; role_arn: string; existing: boolean; command: string; parameters: Record<string, string> }[] } | undefined)?.aws_roles ?? [];
    steps.push({ key: "roles", title: L("계정마다 읽기 역할 만들기", "Create the read role in each account"),
      text: (accounts.length ? L("계정마다 고유한 ExternalId로 역할을 만듭니다. 역할은 승인한 CreMore 신원만 신뢰합니다.",
        "Each account gets its role with its own ExternalId. The role trusts only the approved CreMore identity.")
        : L("인증 후 계정 목록에서 대상을 고르면 역할 설정을 안내합니다. 수집 역할과 신뢰 설정을 확인한 뒤에 계정을 등록합니다.",
          "After authentication, choose accounts to see role setup. Accounts are registered only after collection-role access and trust are verified."))
        + (accounts.length ? readerText(vault, L) : ""),
      actions: [{ kind: "link", label: L("템플릿 받기", "Download template"), href: "/api/backend/aws/onboarding/template", download: "member-account-role.yaml", icon: "download" }],
      body: accounts.length ? <AccountRoles ids={accounts.map(child => child.id)} vault={vault} /> : undefined });
    for (const role of draftRoles) {
      // The value-reader role is made by the same first deployment (design decision 5).
      const reader = valueReaderParameters(vault, role.role_arn.split(":")[1] || "aws", role.account_id);
      steps.push({ key: `draft-role:${role.account_id}`, title: `${role.account_id} · ${L("수집 역할 설정", "Collection role setup")}`,
        text: (role.existing ? L(`기존 역할 ${role.role_arn}의 신뢰 대상을 현재 서버 역할로 확인하고 ExternalId를 유지하세요. 아래 값으로 기존 설정을 비교한 뒤 하단의 ‘권한 확인·다음’을 다시 누르세요.`,
          `Check that ${role.role_arn} trusts the current server role and keep its ExternalId. Compare the parameters below, then check access again.`)
          : L(`대상 계정 ${role.account_id}에 로그인한 관리자에게 템플릿과 만들기 명령을 전달하세요. 역할이 이미 있으면 신뢰 대상과 ExternalId를 아래 값과 맞춘 뒤 다시 확인합니다.`,
            `Give the template and create command to an administrator signed into ${role.account_id}. If the role exists, align its trust and ExternalId with these parameters, then check again.`))
          + readerText(vault, L),
        actions: [{ kind: "copy", label: L("역할 설정값 복사", "Copy role parameters"), text: json({ ...role.parameters, ...reader }) },
          ...(!role.existing ? [{ kind: "copy" as const, label: L("역할 만들기 명령 복사", "Copy role creation command"), text: role.command + overrides(reader) }] : [])] });
    }
  } else {
    steps.push({ key: "read", title: method.id === "sso" ? L("권한 세트에 읽기 정책 넣기", "Give the permission set the read policy")
      : L("CreMore 신원에 읽기 정책 넣기", "Give CreMore's identity the read policy"),
      text: method.id === "sso" ? L("각 계정에 할당한 권한 세트가 곧 접근 권한이라, 읽기 작업 권한을 직접 가져야 합니다.",
        "The permission set assigned in each account is the access itself, so it carries the read-only work.")
        : L("CreMore가 실행 중인 계정 하나를 이 신원으로 읽습니다.", "The one account CreMore runs in is read with this identity."),
      actions: [{ kind: "copy", label: L("정책 복사", "Copy policy"), text: json(view.permission_set_policy) }] });
  }
  return steps;
}

/* ---------- Okta: an API service app signing with a key CreMore made ---------- */

export function slackManifest(audit: boolean) {
  return {
    _metadata: { major_version: 2, minor_version: 1 },
    display_information: { name: "CreMore", description: "Lists the apps the organization approved. Posts and changes nothing." },
    features: { bot_user: { display_name: "CreMore", always_online: false } },
    oauth_config: { scopes: { user: ["admin.apps:read", ...(audit ? ["auditlogs:read"] : [])], bot: ["team:read"] } },
    settings: { org_deploy_enabled: true, token_rotation_enabled: false },
  };
}

function slackSteps(audit: boolean, stored: boolean, L: Say): GuideStep[] {
  if (stored) {
    // The app exists and its token is stored: turning the audit log on adds the scope to that app, not a new app.
    return audit ? [{ key: "scope", title: L("기존 앱에 감사 로그 범위 더하기", "Add the audit log scope to the app"),
      text: L("앱 설정의 OAuth & Permissions에서 User Token Scopes에 auditlogs:read를 더하고, 조직 소유자(Owner)가 조직에 다시 설치해야 합니다. 토큰이 바뀌면 새 토큰을 넣습니다.",
        "Add auditlogs:read to the User Token Scopes under OAuth & Permissions in the app settings; the organization's Owner must then reinstall it on the organization. Enter the token again if it changed.") }] : [];
  }
  const href = `https://api.slack.com/apps?new_app=1&manifest_json=${encodeURIComponent(JSON.stringify(slackManifest(audit)))}`;
  return [
    { key: "app", title: L("Slack에서 앱 만들기", "Make the app in Slack"),
      text: L(`링크를 열고 대상 조직의 워크스페이스를 고르면 권한 범위(admin.apps:read${audit ? ", auditlogs:read" : ""})와 조직 설치가 채워진 앱이 만들어집니다. 조직 설치에 필요한 봇 범위 team:read도 들어가지만 봇 토큰은 쓰지 않습니다. 토큰 교체는 꺼져 있습니다.`,
        `Open the link and choose a workspace of the target organization: the app is made with its scopes (admin.apps:read${audit ? ", auditlogs:read" : ""}) and organization-wide install filled in. The bot scope team:read that organization-wide install needs is included, but the bot token is not used. Token rotation is off.`),
      actions: [{ kind: "link", label: L("Slack에서 앱 만들기", "Make the app in Slack"), href, external: true }] },
    { key: "install", title: L("조직에 설치하기", "Install it on the organization"),
      text: audit ? L("앱 설정의 Install App에서 조직(Enterprise organization)에 설치합니다. auditlogs:read가 있어 조직 소유자(Owner)가 설치해야 합니다.",
        "Install it on the Enterprise organization from Install App in the app settings. With auditlogs:read the organization's Owner must install it.")
        : L("앱 설정의 Install App에서 조직(Enterprise organization)에 설치합니다. 조직 관리자나 조직 소유자(Owner)가 설치합니다.",
          "Install it on the Enterprise organization from Install App in the app settings. An org admin or the organization's Owner installs it.") },
    { key: "token", title: L("사용자 토큰 넣기", "Enter the user token"),
      text: L("OAuth & Permissions의 User OAuth Token(xoxp-)을 위 칸에 넣습니다. 봇 토큰은 쓰지 않습니다.",
        "Put the User OAuth Token (xoxp-) from OAuth & Permissions above. The bot token is not used.") },
  ];
}

/* ---------- Confluence Cloud: a service account with an OAuth 2.0 client ---------- */

export function SetupGuide({ steps, onCopy }: { steps: GuideStep[]; onCopy: (text: string) => void }) {
  const L = useL();
  if (!steps.length) return null;
  return <div className="ig-section ig-guide">
    <div className="ig-section-head"><h3>{L("설정 도우미", "Setup steps")}</h3></div>
    <ol className="ig-guide-steps">{steps.map((step, index) => <li key={step.key}>
      <span className="n">{index + 1}</span>
      <div className="ig-guide-body">
        <b>{step.title}</b>
        {step.text ? <p className="ig-sub">{step.text}</p> : null}
        {step.actions?.length ? <div className="ig-guide-acts">{step.actions.map(action => action.kind === "copy"
          ? <button key={action.label} type="button" className="ghost-btn" onClick={() => onCopy(action.text)}><Ic name={action.icon ?? "copy"} size={15} />{action.label}</button>
          : action.kind === "open"
            ? <button key={action.label} type="button" className="ghost-btn" onClick={action.onOpen}><Ic name={action.icon ?? "right"} size={15} />{action.label}</button>
            : <a key={action.label} className="ghost-btn" href={action.href} download={action.download}
              target={action.external ? "_blank" : undefined} rel={action.external ? "noopener noreferrer" : undefined}>
              <Ic name={action.icon ?? "ext"} size={15} />{action.label}</a>)}</div> : null}
        {step.body}
      </div>
    </li>)}</ol>
  </div>;
}

/* ---------- AWS: one read role per account ---------- */

type Deployment = {
  account_id: string; cloudformation_url: string | null;
  deployment: { stack_name: string; region: string; parameters: Record<string, string>; cli_command: string };
};

function AccountRoles({ ids, vault }: { ids: string[]; vault?: Record<string, unknown> }) {
  const L = useL();
  const [all, setAll] = useState(false);
  return <div className="ig-guide-rows">
    {(all ? ids : ids.slice(0, 10)).map(id => <AccountRole key={id} id={id} vault={vault} />)}
    {ids.length > 10 && !all ? <button type="button" className="link-btn" onClick={() => setAll(true)}>{L(`나머지 ${ids.length - 10}개 계정도 보기`, `Show the other ${ids.length - 10} accounts`)}</button> : null}
  </div>;
}

/** One account's member-role deployment: its CloudFormation link and CLI command. Updating a deployed stack (after a
 * key-action role is added) takes the CLI command: the CloudFormation link only creates the stack. ``vault`` (the
 * vault plan) adds the value-reader role's parameters to both. */
export function AccountRole({ id, update = false, vault }: { id: string; update?: boolean; vault?: Record<string, unknown> }) {
  const L = useL();
  const view = useApi<Deployment>(`aws/accounts/${id}/onboarding`);
  const [copied, setCopied] = useState(false);
  if (view.error) return <div className="ig-guide-row"><span className="ig-sub">{reasonText(view.error, L)}</span></div>;
  if (!view.data) return <div className="ig-guide-row"><span className="spinner" aria-hidden="true" /></div>;
  const { account_id, deployment } = view.data;
  // The trusted principal names the partition the account is in.
  const trusted = deployment.parameters.TrustedPrincipalArn || deployment.parameters.TrustedPrincipalPattern || "arn:aws";
  const reader = valueReaderParameters(vault, trusted.split(":")[1] || "aws", account_id);
  const cloudformation_url = view.data.cloudformation_url && Object.keys(reader).length
    ? `${view.data.cloudformation_url}&${new URLSearchParams(Object.entries(reader).map(([key, value]) => [`param_${key}`, value]))}`
    : view.data.cloudformation_url;
  const copy = () => navigator.clipboard?.writeText(deployment.cli_command + overrides(reader)).then(() => { setCopied(true); window.setTimeout(() => setCopied(false), 1600); }, () => undefined);
  return <div className="ig-guide-row">
    <span className="ig-guide-row-id"><b className="mono">{account_id}</b><span className="ig-sub">ExternalId <span className="mono">{deployment.parameters.ExternalId}</span></span>
      {cloudformation_url && !update ? <span className="ig-sub">{L("CloudFormation 링크는 스택을 처음 만들 때 씁니다. 이미 있는 스택은 CLI 명령으로 갱신합니다.", "The CloudFormation link creates the stack the first time; a stack already there is updated with the CLI command.")}</span> : null}</span>
    <span className="ig-guide-acts">
      {cloudformation_url && !update ? <a className="ghost-btn" href={cloudformation_url} target="_blank" rel="noopener noreferrer"><Ic name="ext" size={15} />{L("CloudFormation에서 만들기", "Create in CloudFormation")}</a> : null}
      <button type="button" className="ghost-btn" onClick={() => void copy()}><Ic name={copied ? "checkCircle" : "copy"} size={15} />{copied ? L("복사함", "Copied") : L("CLI 명령 복사", "Copy CLI command")}</button>
    </span>
  </div>;
}
