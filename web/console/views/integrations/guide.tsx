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
  type Descriptor, generatedOf, listValue, madeKeyOf, type Method, permissionsFor, type ProviderConnection, type Purpose, type Values,
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
  aws: ["role", "runtime"], gcp: ["adc"], azure: ["workload_identity"], entra_id: ["workload_identity"],
  vault: ["jwt"], openbao: ["jwt"],
};

export function guideSteps(d: Descriptor, method: Method, conn: GuideConnection | null, context: GuideContext, L: Say): GuideStep[] {
  const steps = d.provider === "aws" ? awsSteps(method, conn, context.aws ?? null, L, context.openMachine, context.plans?.vault)
    : d.provider === "azure" && method.id === "certificate" ? microsoftSteps(conn, context.plans, L)
    : d.provider === "azure" && method.id === "workload_identity" ? identitySteps(conn, context.plans, L)
    : d.provider === "confluence" && method.id === "service_account" ? confluenceSteps(d, method, L)
    : d.provider === "slack" && method.id === "token" ? slackSteps(context.plans?.inventory?.audit_events === true, Boolean(context.stored), L)
    : d.provider === "okta" && method.id === "made_key" ? oktaSteps(conn, context.target ?? conn?.target ?? {}, L) : [];
  if (context.openMachine && AMBIENT[d.provider]?.includes(method.id) && !steps.some(step => step.key === "aws-bootstrap")) steps.push(machineStep(d.provider, context.openMachine, L));
  return steps;
}

function machineStep(provider: string, open: () => void, L: Say): GuideStep {
  const vault = provider === "vault" || provider === "openbao";
  return { key: "machine", title: L("회사 IdP 신원으로 접근 (선택)", "Reach it as the company IdP identity (optional)"),
    text: vault ? L("JWT 로그인 토큰을 회사 IdP에서 받으려면 기계 신원에 이 클러스터의 토큰을 추가하고, 토큰 파일 이름을 idp-이름으로 두세요.",
      "To take the JWT login token from the company IdP, add this cluster's token to the machine identity and name the token file idp-<name>.")
      : L("클라우드 키나 이 컴퓨터의 로그인 없이 회사 IdP가 발급한 기계 토큰으로 접근하려면 기계 신원을 설정하세요.",
        "To reach it with a machine token from the company IdP instead of a cloud key or this computer's sign-in, set the machine identity."),
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

/** The Admin Console of an Okta org (acme.okta.com -> acme-admin.okta.com); none for a custom domain or the
 * okta.mil cell, whose admin host is not documented here. */
export function oktaAdmin(host: string) {
  const name = host.trim().toLowerCase().replace(/^https:\/\//, "").replace(/\/+$/, "");
  const match = /^([a-z0-9-]+)\.(okta|oktapreview|okta-emea|okta-gov)\.com$/.exec(name);
  return match ? `https://${match[1]}-admin.${match[2]}.com/admin/apps/active` : null;
}

function oktaSteps(conn: GuideConnection | null, target: Record<string, unknown>, L: Say): GuideStep[] {
  const host = typeof target.organization === "string" ? target.organization : "";
  const admin = oktaAdmin(host);
  const steps: GuideStep[] = [{ key: "app", title: L("API 서비스 앱 만들기", "Create the API service app"),
    text: L("Okta 관리 콘솔의 Applications and Resources → Applications → Create App Integration에서 API Services 앱을 만들고, General 탭의 클라이언트 ID를 위 칸에 넣은 뒤 키를 만듭니다.",
      "Create an API Services app under Applications and Resources → Applications → Create App Integration in the Okta Admin Console, put the client ID from its General tab above and make the key."),
    actions: admin ? [{ kind: "link", label: L("Okta 관리 콘솔 열기", "Open the Okta Admin Console"), href: admin, external: true }] : undefined }];
  const made = madeKeyOf(conn);
  if (!made) return steps;
  // Only the public members, whatever else the stored part might hold.
  const { kty, e, n, kid, alg, use } = made.public_jwk;
  steps.push({ key: "key", title: L("공개 키 붙여 넣기", "Paste the public key"),
    text: L(`앱의 General → Client Credentials → Edit에서 Public key / Private key를 고르고, Add key에 이 공개 키(kid ${made.kid})를 붙여 넣고 저장합니다.`,
      `Under the app's General → Client Credentials → Edit, choose Public key / Private key, paste this public key (kid ${made.kid}) under Add key and save.`),
    actions: [{ kind: "copy", label: L("공개 키 복사", "Copy the public key"), text: JSON.stringify({ kty, e, n, kid, alg, use }, null, 2) }] });
  steps.push({ key: "grants", title: L("권한 주기", "Grant access"),
    text: L("Okta API Scopes 탭에서 okta.users.read를 Grant하고(Grant는 Super Admin만 할 수 있습니다), Admin roles 탭에서 사용자 보기만 있는 역할(사용자 정의 역할: View users and their details, 리소스 세트: 모든 사용자)을 줍니다. 사용자 정의 역할을 쓸 수 없으면 Read-only Administrator를 줍니다. 앱 목록 옵션도 쓰면 okta.apps.read를 Grant하고, 역할에 View applications and their details를, 리소스 세트에 모든 앱을 더합니다(View client credentials는 주지 않습니다).",
      "Grant okta.users.read on the Okta API Scopes tab (only a Super Admin can grant scopes), and on the Admin roles tab assign a role that only views users (a custom role with View users and their details over all users). Where custom roles are not available, assign Read-only Administrator. For the app list option, also grant okta.apps.read, add View applications and their details to the role and all apps to its resource set (not View client credentials).") });
  if (made.previous?.kid) steps.push({ key: "retire", title: L("이전 키 비활성화·삭제", "Deactivate and delete the earlier key"),
    text: L(`새 키로 권한 확인이 끝나면 같은 화면의 공개 키 목록에서 이전 키(kid ${made.previous.kid})를 Deactivate한 뒤 삭제합니다. 지우기 전까지는 그 키로도 로그인할 수 있습니다.`,
      `Once the check passes with the new key, deactivate the earlier key (kid ${made.previous.kid}) in the same list of public keys, then delete it. Until then it can still sign in.`) });
  return steps;
}

/* ---------- Slack: an org-ready app made from a manifest ---------- */

/** The app an Enterprise org admin makes from a link: the user scopes the inventory reads with, org-wide
 * install (which asks for one bot scope), and no token rotation (a rotating token stops after 12 hours). */
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

const ATLASSIAN_ADMIN = "https://admin.atlassian.com";

function confluenceSteps(d: Descriptor, method: Method, L: Say): GuideStep[] {
  // The method's permissions are the OAuth scopes the credential is created with.
  const scopes = permissionsFor(d, "exposure", method.id, {}).map(permission => permission.id);
  return [
    { key: "account", title: L("서비스 계정 만들기", "Create the service account"),
      text: L("Atlassian 관리의 디렉터리 → 서비스 계정에서 계정을 만들고 Confluence 앱 접근을 줍니다.",
        "Create the account under Directory → Service accounts in Atlassian Administration and give it Confluence app access."),
      actions: [{ kind: "link", label: L("Atlassian 관리 열기", "Open Atlassian Administration"), href: ATLASSIAN_ADMIN, external: true }] },
    { key: "space", title: L("공간 보기 권한 주기", "Let it view the space"),
      text: L("검사할 공간의 공간 설정 → 권한에서 이 서비스 계정(또는 그 그룹)에 보기 권한을 줍니다.",
        "In the space settings → permissions of the space to scan, give this service account (or its group) view permission.") },
    { key: "oauth", title: L("OAuth 2.0 자격증명 만들기", "Create the OAuth 2.0 credential"),
      text: L("서비스 계정의 자격증명 만들기 → OAuth 2.0에서 아래 범위를 고르고, 클라이언트 ID와 시크릿을 위 칸에 넣습니다. 시크릿은 만든 직후에만 보입니다.",
        "Under the service account's Create credentials → OAuth 2.0, choose the scopes below and put the client ID and secret above. The secret shows only right after it is made."),
      actions: [{ kind: "copy", label: L("범위 복사", "Copy the scopes"), text: scopes.join("\n") }] },
  ];
}

/* ---------- Microsoft: one app registration for Entra ID, Azure and Azure DevOps ---------- */

const ENTRA_APPS = "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade";
// Microsoft Graph and the application permissions (app roles) a Microsoft connection asks for.
const GRAPH_API = "00000003-0000-0000-c000-000000000000";
const GRAPH_ROLES = {
  "Application.Read.All": "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30",
  "Organization.Read.All": "498476ce-e0fe-48b0-b801-37ba7e2685c6",
  "User.Read.All": "df021288-bdef-4463-88db-98f22de89214",
  "AuditLog.Read.All": "b0afded3-3588-46d8-8b3d-9842eff778da",
  "RoleManagement.Read.Directory": "483bed4a-2ad3-4361-a73b-c83ccdbdc53c",
} as const;
type GraphRole = keyof typeof GRAPH_ROLES;

/** The certificate as one line of Base64 DER, the form `az ad app credential reset --cert` takes inline. */
export function certificateBase64(pem: string) {
  return pem.replace(/-----(BEGIN|END) CERTIFICATE-----/g, "").replace(/\s+/g, "");
}

/** The Microsoft Graph application permissions the chosen features need: renewing CreMore's certificate
 * (``renews``) reads the app's own registration (Application.Read.All), the inventory's sign-in and audit
 * options read the logs (AuditLog.Read.All), and its app permissions option the apps' Entra roles
 * (RoleManagement.Read.Directory). */
export function graphRoles(purposes: string[], plans: GuideContext["plans"] = {}, renews = true): GraphRole[] {
  const inventory = purposes.includes("inventory");
  const logs = inventory && Boolean(plans?.inventory?.credential_sign_ins || plans?.inventory?.directory_audits);
  return [...(renews || inventory ? ["Application.Read.All"] : []), ...(inventory ? ["Organization.Read.All"] : []),
    ...(purposes.includes("identity") ? ["User.Read.All"] : []), ...(logs ? ["AuditLog.Read.All"] : []),
    ...(inventory && plans?.inventory?.app_permissions === true ? ["RoleManagement.Read.Directory"] : [])] as GraphRole[];
}

/** The targets to grant on: the ones an onboarding chose, each under its own subscription (``located``), or a saved
 * connection's one target, whose subscription is the inventory's alone. */
function rootsOf(conn: GuideConnection): (Root & { located: boolean })[] {
  return conn.roots?.length ? conn.roots.map(root => ({ ...root, located: true }))
    : [{ purposes: conn.purposes, target: conn.target as Record<string, unknown>, located: false }];
}

// The custom role the Azure roles option reads with at the tenant root management group.
const ROLE_READER = "CreMore Role Assignment Reader";

/** The Azure role assignments for ``who`` (the az assignee arguments): each target's own (its subscription, storage
 * account, Key Vaults) once, and the storage accounts the inventory reads key fingerprints from. */
function azureRoles(who: string, conn: GuideConnection, plans: GuideContext["plans"]): string[] {
  const assign = (role: string, scope: string) => `az role assignment create ${who} --role "${role}" --scope ${scope}`;
  const roots = rootsOf(conn);
  const lines = roots.flatMap(({ purposes, target, located }) => {
    const where = located && target.subscription ? ` --subscription ${target.subscription}` : "";
    const vault = (name: string) => `"$(az keyvault show --name ${name}${where} --query id -o tsv)"`;
    const vaults = purposes.includes("vault") ? listValue(target.key_vaults) : [];
    return [
      ...(purposes.includes("inventory") && target.subscription ? [assign("Reader", `/subscriptions/${target.subscription}`)] : []),
      ...(purposes.includes("exposure") && target.storage_account
        ? [assign("Storage Blob Data Reader", `"$(az storage account show --name ${target.storage_account}${where} --query id -o tsv)"`)] : []),
      ...vaults.map(name => assign("Key Vault Reader", vault(name))),
      ...(plans?.vault?.read_values === true ? vaults.map(name => assign("Key Vault Secrets User", vault(name))) : []),
    ];
  });
  const inventory = roots.some(root => root.purposes.includes("inventory"));
  const keys = inventory
    ? listValue(plans?.inventory?.storage_key_accounts).map(account => assign("Reader and Data Access", account)) : [];
  // Azure roles of the tenant's apps are read at the root management group (its ID is the tenant ID) with a custom role
  // that reads only role assignments and definitions.
  const tenant = typeof conn.target.tenant === "string" ? conn.target.tenant : "";
  const group = `/providers/Microsoft.Management/managementGroups/${tenant}`;
  const root = inventory && plans?.inventory?.app_azure_roles === true && tenant ? [
    `az role definition create --role-definition '${JSON.stringify({ Name: ROLE_READER, Description: "Reads Azure role assignments and role definitions",
      Actions: ["Microsoft.Authorization/roleAssignments/read", "Microsoft.Authorization/roleDefinitions/read"], AssignableScopes: [group] })}'`,
    assign(ROLE_READER, group)] : [];
  return [...new Set([...lines, ...keys, ...root])];
}

function azureRolesText(L: Say, plans: GuideContext["plans"]) {
  const root = plans?.inventory?.app_azure_roles === true;
  return L(`구독 Reader, Storage Blob Data Reader, Key Vault Reader(메타데이터만)를 줍니다. 키 지문을 읽을 스토리지 계정에는 Reader and Data Access를 주며, 그 키로 계정의 모든 데이터에 접근할 수 있습니다. Key Vault 역할은 Azure RBAC 권한 모델의 Key Vault에 적용되고, Key Vault Secrets User는 값을 대조할 때만 줍니다. 예전 액세스 정책 모델의 Key Vault에는 비밀 List(키·인증서를 고르면 키 List, 인증서 List·Get)를 주고, 값을 대조할 때만 비밀 Get을 더합니다.${root ? ` 앱의 Azure 역할은 역할 할당·정의만 읽는 사용자 지정 역할(${ROLE_READER})을 만들어 테넌트 루트 관리 그룹(ID가 테넌트 ID)에 주고 읽습니다. 새 역할이 퍼지는 데 몇 분 걸리므로 할당이 역할을 찾지 못하면 잠시 뒤 할당 줄을 다시 실행합니다. 루트 관리 그룹은 테넌트에서 관리 그룹을 처음 쓸 때 만들어지며, 그 범위는 전역 관리자가 Azure 리소스 액세스 관리를 켜서 받는 사용자 액세스 관리자가 다룰 수 있습니다.` : ""} 역할 할당은 그 범위의 소유자, 사용자 액세스 관리자 또는 역할 기반 액세스 제어 관리자가 실행합니다.`,
    `Give Reader on the subscription, Storage Blob Data Reader and Key Vault Reader (metadata only). A storage account whose key fingerprints are read takes Reader and Data Access, and its keys open all of the account's data. The Key Vault roles apply to vaults on the Azure RBAC permission model; Key Vault Secrets User is only for comparing values. A vault still on legacy access policies takes secret List (key List, and certificate List and Get, when chosen) and secret Get only for comparing values.${root ? ` The apps' Azure roles are read with a custom role (${ROLE_READER}) that only reads role assignments and definitions, given on the tenant root management group (its ID is the tenant ID). A new role takes a few minutes to spread, so if the assignment cannot find it, run the assignment line again shortly after. The root management group is made the first time the tenant uses management groups; a Global Administrator who turns on access management for Azure resources becomes User Access Administrator there and can work on it.` : ""} An Owner, User Access Administrator or Role Based Access Control Administrator on the scope runs the assignments.`);
}

function devopsSteps(target: Record<string, unknown>, L: Say): GuideStep[] {
  const organization = typeof target.devops_organization === "string" ? target.devops_organization : "";
  return organization ? [{ key: "devops", title: L("Azure DevOps에 이 앱 추가", "Add this app to Azure DevOps"),
    text: L("조직이 이 테넌트의 Microsoft Entra에 연결돼 있어야 합니다. 조직 설정 → 사용자에서 이 앱(서비스 주체)을 Basic 액세스로 추가하고 검사할 프로젝트에 넣습니다. PAT 목록(Token Admin)은 Project Collection Administrators 그룹(조직 설정 → 권한)만 읽을 수 있고, 이 그룹에 넣으면 앱이 조직 전체 관리자가 되어 사용자 PAT를 폐기할 수도 있습니다. 권한 확인이 실제 목록 호출로 이 앱이 PAT 목록을 읽는지 확인합니다.",
      "The organization must be connected to this tenant's Microsoft Entra ID. Under Organization settings → Users, add this app (its service principal) with Basic access and to the projects to scan. Only the Project Collection Administrators group (Organization settings → Permissions) can read the PAT list (Token Admin); in that group the app is a full organization administrator that can also revoke users' PATs. The access check confirms with a real list call that this app reads the PAT list."),
    actions: [{ kind: "link", label: L("사용자 설정 열기", "Open Users"), href: `https://dev.azure.com/${encodeURIComponent(organization)}/_settings/users`, external: true },
      { kind: "link", label: L("권한 설정 열기", "Open Permissions"), href: `https://dev.azure.com/${encodeURIComponent(organization)}/_settings/groups`, external: true }] }] : [];
}

/** The worker's own identity: a managed identity has no API permissions page, so its Graph app roles are assigned
 * to its service principal through Graph, and its Azure roles by object ID. */
function identitySteps(conn: GuideConnection | null, plans: GuideContext["plans"], L: Say): GuideStep[] {
  if (!conn) return [];
  const roles = graphRoles(conn.purposes, plans, false);
  const lines = azureRoles(`--assignee-object-id "$MI" --assignee-principal-type ServicePrincipal`, conn, plans);
  const mi = `MI="<${L("신원의 개체(주체) ID", "the identity's object (principal) ID")}>"`;
  return [
    ...(roles.length ? [{ key: "graph", title: L("Microsoft Graph 앱 역할 할당", "Assign the Microsoft Graph app roles"),
      text: L(`관리 ID는 포털의 API 권한 화면이 없어 Microsoft Graph 앱 역할 ${roles.join(", ")}을(를) Graph로 할당합니다. 권한 있는 역할 관리자가 Azure Cloud Shell(Bash)에서 MI에 신원의 개체(주체) ID를 넣고 실행합니다. 연합 자격 증명을 붙인 앱 등록이면 그 앱의 API 권한에서 같은 권한을 추가하고 관리자 동의를 줍니다.`,
        `A managed identity has no API permissions page in the portal, so its Microsoft Graph app roles ${roles.join(", ")} are assigned through Graph. A Privileged Role Administrator runs these in Azure Cloud Shell (Bash) with MI set to the identity's object (principal) ID. An app registration with a federated credential adds the same permissions under its API permissions with admin consent.`),
      actions: [{ kind: "copy" as const, label: L("권한 명령 복사", "Copy the permission commands"), text: [mi,
        `GRAPH=$(az ad sp show --id ${GRAPH_API} --query id -o tsv)`,
        ...roles.map(role => `az rest --method POST --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$MI/appRoleAssignments" --body "{\\"principalId\\":\\"$MI\\",\\"resourceId\\":\\"$GRAPH\\",\\"appRoleId\\":\\"${GRAPH_ROLES[role]}\\"}"`)].join("\n") }] }] : []),
    ...(lines.length ? [{ key: "azure", title: L("Azure 역할 할당", "Assign Azure roles"), text: azureRolesText(L, plans),
      actions: [{ kind: "copy" as const, label: L("역할 명령 복사", "Copy the role commands"), text: [mi, ...lines].join("\n") }] }] : []),
    ...devopsSteps(conn.target as Record<string, unknown>, L)];
}

function microsoftSteps(conn: GuideConnection | null, plans: GuideContext["plans"], L: Say): GuideStep[] {
  const steps: GuideStep[] = [{ key: "app", title: L("앱 등록 만들기", "Create the app registration"),
    text: L("Microsoft Entra 관리 센터의 앱 등록에서 새 등록을 만듭니다(이 조직 디렉터리만, 리디렉션 URI 없음). 개요의 애플리케이션(클라이언트) ID를 위 칸에 넣고 인증서를 만드세요. Azure Cloud Shell(Bash)에서는 명령 하나로 만들 수 있습니다.",
      "Create a new registration under App registrations in the Microsoft Entra admin center (this directory only, no redirect URI). Put the application (client) ID from its overview above and make the certificate. In Azure Cloud Shell (Bash) one command makes it."),
    actions: [{ kind: "link", label: L("앱 등록 열기", "Open app registrations"), href: ENTRA_APPS, external: true },
      { kind: "copy", label: L("만들기 명령 복사", "Copy the create command"),
        text: 'APP_ID=$(az ad app create --display-name "CreMore" --sign-in-audience AzureADMyOrg --query appId -o tsv)\naz ad sp create --id "$APP_ID"\necho "$APP_ID"' }] }];
  const made = generatedOf(conn);
  const app = (conn?.target.auth as Record<string, string> | undefined)?.client_id;
  if (!conn || !made || !app) return steps;
  const target = conn.target as Record<string, unknown>;
  const purposes = conn.purposes;
  const pem = made.certificate;
  steps.push({ key: "certificate", title: L("인증서 올리기", "Upload the certificate"),
    text: L(`앱 등록의 '인증서 및 비밀 → 인증서 → 인증서 업로드'에 받은 파일을 올리거나 명령을 실행합니다. 올라가는 것은 공개 인증서(지문 ${made.thumbprint})뿐입니다.`,
      `Upload the downloaded file under 'Certificates & secrets → Certificates → Upload certificate' of the app registration, or run the command. Only the public certificate (thumbprint ${made.thumbprint}) goes there.`),
    actions: [{ kind: "link", label: L("인증서 받기", "Download the certificate"), icon: "download",
      href: `data:application/x-pem-file;charset=utf-8,${encodeURIComponent(pem)}`, download: `CreMore-${made.thumbprint.slice(0, 8)}.pem` },
      { kind: "copy", label: L("올리기 명령 복사", "Copy the upload command"),
        text: `az ad app credential reset --id ${app} --append --cert "${certificateBase64(pem)}"` }] });
  if (!purposes.length) return steps;
  const roles = graphRoles(purposes, plans);
  const signIns = roles.includes("AuditLog.Read.All") && plans?.inventory?.credential_sign_ins === true;
  steps.push({ key: "graph", title: L("Microsoft Graph 권한과 관리자 동의", "Microsoft Graph permissions and admin consent"),
    text: L(`애플리케이션 권한 ${roles.join(", ")}을(를) 추가하고, 권한 있는 역할 관리자가 API 권한 화면에서 관리자 동의를 줍니다(명령의 admin-consent 줄은 전역 관리자가 실행합니다). Application.Read.All은 앱이 자기 인증서를 교체할 때도 씁니다.${signIns ? " 로그인 기록은 테넌트에 Microsoft Entra ID P1 또는 P2가 있어야 읽힙니다." : ""}`,
      `Add the application permissions ${roles.join(", ")}; a Privileged Role Administrator grants admin consent on the API permissions page (the command's admin-consent line needs a Global Administrator). Application.Read.All is also how the app renews its own certificate.${signIns ? " Sign-in logs need Microsoft Entra ID P1 or P2 in the tenant." : ""}`),
    actions: [{ kind: "copy", label: L("권한 명령 복사", "Copy the permission commands"),
      text: `az ad app permission add --id ${app} --api ${GRAPH_API} --api-permissions ${roles.map(role => `${GRAPH_ROLES[role]}=Role`).join(" ")}\naz ad app permission admin-consent --id ${app}` }] });
  const lines = azureRoles(`--assignee ${app}`, conn, plans);
  if (lines.length) steps.push({ key: "azure", title: L("Azure 역할 할당", "Assign Azure roles"), text: azureRolesText(L, plans),
    actions: [{ kind: "copy", label: L("역할 명령 복사", "Copy the role commands"), text: lines.join("\n") }] });
  if (made.previous?.thumbprint) steps.push({ key: "retire", title: L("이전 인증서 지우기", "Remove the earlier certificate"),
    text: L(`새 인증서로 권한 확인이 끝나면 앱 등록의 '인증서 및 비밀 → 인증서'에서 이전 인증서(지문 ${made.previous.thumbprint})를 삭제합니다. 지우기 전까지는 만료일까지 그 인증서로도 로그인할 수 있습니다.`,
      `Once the check passes with the new certificate, delete the earlier one (thumbprint ${made.previous.thumbprint}) under 'Certificates & secrets → Certificates' of the app registration. Until then it can still sign in until it expires.`) });
  return [...steps, ...devopsSteps(target, L)];
}

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
