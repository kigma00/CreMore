"use client";

/* The connect wizard, in the design's three steps and a done screen.
 *
 * 1 What to collect: features (the catalog's purposes), where the connection points, options.
 * 2 Sign in: an auth method in the provider's recommended order and its credential. "Test connection"
 *   stores the connection (the credential is sealed on arrival), then the worker checks every
 *   permission the chosen features need; the wizard follows the check until it answers.
 * 3 Review: the choices, the name and the schedule; finishing activates the features, which makes
 *   the records they run on. A collector token for a customer-side collection is shown once.
 *
 * An existing connection opens the same wizard: features already collecting keep running and their
 * credential types, options and schedule can change (from the next run), compatible features can be
 * added after checking access again, and the credential can be replaced. */

import { Fragment, type ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";

import { completeSignIn, pending, startSignIn } from "@/console/gcp-oauth";
import { useLocale } from "@/components/locale";
import { reasonText, send, useApi, useSaved } from "@/console/data";
import { Ic, Tick } from "@/console/icons";
import { Modal, useToast } from "@/console/layer";
import { Logo } from "@/console/logos";
import type { ViewProps } from "@/console/shell";
import { fmtDay, fmtDT, josa, type Say, useL } from "@/console/text";
import { Banner, Check, cls, InfoTip, SelectField, TextField } from "@/console/ui";
import {
  approval, type AwsIdentityView, IDENTITY_PATH, identityIssue, identityText, needsApproval, refusalText, signInText,
  SSO_LOGIN_PATH, type SsoLoginStart, type SsoLoginState,
} from "@/console/views/integrations/aws-identity";
import {
  AwsIdentityCenter, AwsInventory, AwsInvestigations, AwsKeyActionIdentity, AwsOrganizations, awsParts, investigationKeys,
} from "@/console/views/integrations/aws-settings";
import { capName, featureName, featureText, methodHint, renewalTag } from "@/console/views/integrations/copy";
import { FieldGrid, CredentialField } from "@/console/views/integrations/fields";
import { AuthFirstWizard, ReduceTargets, rememberedDraft } from "@/console/views/integrations/auth-first";
import { GoogleConsent } from "@/console/views/integrations/google-client";
import { startGitHubApp } from "@/console/views/integrations/github-app";
import { enterpriseReady, GitHubEnterpriseModal } from "@/console/views/integrations/github-enterprise";
import { readJourney, rememberJourney, setupGroups, type SetupGroup, type SetupJourney } from "@/console/views/integrations/setup";
import { guideSteps, SetupGuide } from "@/console/views/integrations/guide";
import {
  type Catalog, type CollectionEntry, forCollectionEntry, purposesForEdition, CONNECTIONS_PATH, type Created, checkItems, checkSummary, checked, combinable, type Descriptor, defaults,
  detailText, expiryDay, expiryKeys, familyOf, type FieldSpec, type Generated, generatedOf, type Health, HEALTH_PATH, type HealthItem, healthOf,
  idleReaderField, inEntryView, label, type MadeKey, madeKeyOf, type Method, methodsFor, missingRequired, onboardingText,
  payload, peopleDirectoryBlock, permissionsFor, planFields, type ProviderConnection, type Purpose, purposesOf, type Renewed, renewalText, saveExpiry, SCHEDULES,
  scanEntryOf, scansFor, scheduleLabel, sharedNote, sharedTarget, shown, switchable, switchType, takesExpiry, targetFields, targetSummary, type TypeChoice, typeChoices,
  typeFields, type Values, valuesOf,
} from "@/console/views/integrations/model";
import {
  applyScope, everythingOf, readProfiles, type ScopeMode, type ScopeProgress, scopedCount, scopeTargets, splitPatterns, unitOf,
} from "@/console/views/integrations/scope";
import { FULL_SCHEDULES, fullScanText, INSTALLATION_DEFAULT } from "@/console/views/integrations/targets-model";
import { api } from "@/lib/dashboard-api";

export type WizardOpen =
  | { provider: string; purpose?: string; target?: Values; edition?: string; entry?: CollectionEntry }
  | { id: string; step?: 1 | 2 | 3; addPurpose?: Purpose; entry?: CollectionEntry }
  | { oauth: string; entry?: CollectionEntry };

type Step = 1 | 2 | 3 | 4;
const POLL_MS = 1500, POLL_LIMIT_MS = 150_000;
const FEATURE_ICON = { inventory: "key", exposure: "scan", vault: "vault", identity: "users", remediation: "shield" } as const;

/** A new account connection never opts into a content scan. */
function firstPurposes(d: Descriptor, edition: string): Purpose[] {
  const all = purposesOf(d);
  const offered = methodsFor(d, [], edition);
  const first = offered.find(method => !method.advanced) ?? offered[0];
  const preferred = all.filter(p => p === "inventory" && first?.purposes.includes(p));
  if (preferred.length) return preferred;
  return all.length === 1 ? all : all.filter(p => first?.purposes.includes(p)).slice(0, 1);
}

const inOrder = (d: Descriptor, list: Purpose[]) => purposesOf(d).filter(p => list.includes(p));

function planChips(fields: FieldSpec[], stored: Record<string, unknown>, L: Say) {
  const out: string[] = [];
  for (const field of fields) {
    const value = stored[field.name];
    if (value === undefined || value === null || value === "" || value === false || (Array.isArray(value) && !value.length)) continue;
    out.push(field.kind === "bool" ? label(field, L) : `${label(field, L)}: ${shown(field, value, L)}`);
  }
  return out;
}

function checkWord(status: string, L: Say) {
  return ({ GRANTED: L("있음", "Granted"), MISSING: L("없음", "Missing"), NOT_REPORTED: L("알 수 없음", "Not reported"), ERROR: L("확인 실패", "Check failed") } as Record<string, string>)[status] ?? status;
}

type WizardProps = {
  catalog: Catalog; open: WizardOpen; onClose: () => void; go: ViewProps["go"]; can: ViewProps["can"]; admin: boolean;
  onMachineIdentity?: () => void; health?: HealthItem[]; onNext?: (provider: string) => void; connected?: string[];
  authenticationOnly?: boolean;
};

export function ConnectWizard(props: WizardProps) {
  const L = useL();
  const open = props.open;
  const provider = "provider" in open ? open.provider : "oauth" in open ? "gcp" : null;
  const original = props.catalog.providers.find(d => d.provider === provider);
  const named: CollectionEntry = "provider" in open && open.entry ? open.entry
    : "provider" in open && (open.purpose === "exposure" || open.provider === "website") ? "exposure" : "account";
  // The product and card a flow saved before leaving for a provider. An open naming its own card never takes the other's.
  const [saved] = useState<{ edition: string; entry: CollectionEntry } | null>(() => {
    if (!original || "id" in open) return null;
    try {
      const value = JSON.parse(sessionStorage.getItem(`cremore:onboarding-entry:${original.provider}`) ?? "null");
      if (value && original.editions.some(e => e.id === value.edition) && ["account", "exposure"].includes(value.entry)
        && !("provider" in open && open.entry && value.entry !== open.entry)) return { edition: value.edition, entry: value.entry };
    } catch { /* The draft still validates its own product and purposes. */ }
    return null;
  });
  // A saved choice is resumed with a provider's return, or with its own setup journey, checked against that card's
  // features (a content journey is not valid against the account card's).
  const resumed = saved && ("oauth" in open || (provider === "github" && rememberedDraft("cremore:onboarding:github:new"))
    || (original && readJourney(forCollectionEntry(original, saved.entry)))) ? saved : null;
  const restoring = "oauth" in open || Boolean(resumed) || Boolean(original && readJourney(forCollectionEntry(original, named)));
  const entry = resumed?.entry ?? named;
  // The account card offers only the editions with an account feature; with none (no account card), every edition stays.
  const withAccount = useMemo(() => {
    const view = original ? forCollectionEntry(original, "account") : null;
    return new Set(view ? view.editions.filter(e => purposesForEdition(view, e.id).length).map(e => e.id) : []);
  }, [original]);
  const onlyAccount = entry === "account" && Boolean(original?.editions.some(e => e.new_setup !== false && withAccount.has(e.id)));
  const editions = (original?.editions ?? []).filter(e => e.new_setup !== false && (!onlyAccount || withAccount.has(e.id)));
  const [choice, setChoice] = useState<{ edition: string; entry: CollectionEntry } | null>(() => {
    if (!original || "id" in open) return null;
    if ("provider" in open && open.edition && original.editions.some(e => e.id === open.edition)) return { edition: open.edition, entry };
    return resumed;
  });
  const [edition, setEdition] = useState(() => "provider" in open && open.edition || editions[0]?.id || "");
  const productFields = (original?.target ?? []).filter(f => f.product && (!f.editions || f.editions.includes(edition)));
  const [product, setProduct] = useState<Values>(() => defaults((original?.target ?? []).filter(f => f.product)
    .map(f => ({ ...f, default: f.default ?? f.options?.[0]?.id }))));
  const selectedEdition = choice?.edition ?? edition;
  const accountOnly = Boolean(original && (choice?.entry ?? entry) === "account" && !withAccount.has(selectedEdition) && original.purposes.exposure);
  const scoped = useMemo(() => original ? forCollectionEntry(original, choice?.entry ?? entry) : null,
    [original, choice?.entry, entry]);
  useEffect(() => {
    if (!original || "id" in open || restoring) return;
    if (choice || editions.length === 1) {
      try { sessionStorage.setItem(`cremore:onboarding-entry:${original.provider}`, JSON.stringify(choice ?? { edition, entry })); }
      catch { /* Redirect-free setup still works. */ }
    }
  }, [original, open, restoring, choice, edition, entry, editions.length]);
  const catalog = useMemo(() => scoped ? { ...props.catalog, providers: props.catalog.providers.map(d => d.provider === scoped.provider
    ? { ...scoped, editions: scoped.editions.filter(e => choice ? e.id === choice.edition : !onlyAccount || withAccount.has(e.id)) } : d) } : props.catalog,
  [props.catalog, scoped, choice, onlyAccount, withAccount]);
  if (!original || "id" in open) return <ConnectionFlow {...props} />;
  if (!choice && !restoring && (editions.length > 1 || productFields.length > 0)) return <Modal onClose={props.onClose} labelledBy="product-title" className="integ">
    <h2 id="product-title"><Logo id={original.provider} size={26} />{label(original, L)} <small>{L("제품 선택", "Choose product")}</small></h2>
    <p className="ig-hint">{L("사용 중인 제품·요금제를 먼저 선택하세요. 인증 후에는 이 제품에서 지원하는 기능만 표시합니다. 실제 이용 권한은 별도로 확인합니다.",
      "Choose your product or plan first. After authentication, only its supported features are shown. Actual access is checked separately.")}</p>
    <SelectField label={L("제품·요금제", "Product / plan")} value={edition} onChange={setEdition}
      options={editions.map(e => ({ id: e.id, label: label(e, L) }))} />
    <FieldGrid fields={productFields} values={product} onChange={(key, value) => setProduct(all => ({ ...all, [key]: value }))} />
    {accountOnly ? <Banner icon="info">{L("이 제품은 발급 목록 API가 없습니다. 먼저 계정을 연결한 뒤 콘텐츠 검사 위치를 추가할 수 있습니다.",
      "This product has no issuance inventory API. Connect the account first, then add content scan locations.")}</Banner> : null}
    <div className="modal-foot"><button type="button" className="primary-btn" disabled={!methodsFor(scoped!, [], edition).length}
      onClick={() => { const value = { edition, entry }; setChoice(value);
        try { sessionStorage.setItem(`cremore:onboarding-entry:${original.provider}`, JSON.stringify(value)); } catch { /* Redirect-free setup still works. */ }
      }}>{L("인증으로", "Continue to sign-in")}</button></div>
  </Modal>;
  // The entry the flow continues with: a provider's return ({oauth}) has only the choice saved before leaving.
  const flowEntry = choice?.entry ?? ("oauth" in open ? undefined : entry);
  return <ConnectionFlow {...props} authenticationOnly={accountOnly} catalog={catalog} open={"provider" in open ? {
    ...open, target: { ...open.target, ...Object.fromEntries(productFields.map(f => [f.name, product[f.name]])) }, edition: selectedEdition, entry: flowEntry }
    : { ...open, entry: flowEntry }} />;
}

function ConnectionFlow(props: WizardProps) {
  const L = useL();
  const toast = useToast();
  const [advanced, setAdvanced] = useState(false);
  const [legacyMethod, setLegacyMethod] = useState<{ method: string; edition: string } | null>(null);
  const [targetEditor, setTargetEditor] = useState<ProviderConnection | null>(null);
  const open = props.open;
  const [oauthDraft] = useState(() => "oauth" in open && pending()?.onboarding_id ? open.oauth : undefined);
  const initialDescriptor = props.catalog.providers.find(d => d.provider === ("provider" in open ? open.provider : oauthDraft ? "gcp" : ""));
  const [journey, setJourney] = useState<SetupJourney | null>(() => initialDescriptor ? readJourney(initialDescriptor) : null);
  const [assignment, setAssignment] = useState<SetupGroup | undefined>(() => journey?.current);
  const [finished, setFinished] = useState(false);
  const [enterprise, setEnterprise] = useState<ProviderConnection | null>(null);
  const descriptor = props.catalog.providers.find(d => d.provider === journey?.provider) ?? initialDescriptor;
  const update = (value: SetupJourney | null) => { setJourney(value); if (value) rememberJourney(value.provider, value); };
  function close() {
    if (journey) {
      rememberJourney(journey.provider, null);
      if (journey.completed.length && !finished) toast(L("저장한 기능은 유지됩니다. 나머지 기능의 설정은 완료되지 않았습니다.", "Saved features remain connected. The remaining features were not completed."));
    }
    props.onClose();
  }
  function selected(d: Descriptor, edition: string, requested: Purpose[], current: SetupGroup | undefined, pending: SetupGroup[]) {
    update({ provider: d.provider, edition, requested, current, pending, completed: journey?.completed ?? [], expires: Date.now() + 1800000 });
  }
  function advance(connection?: ProviderConnection) {
    if (!journey) { props.onClose(); return; }
    const completed = connection ? [...journey.completed.filter(c => c.id !== connection.id), { id: connection.id, purposes: Object.keys(connection.plans) as Purpose[] }] : journey.completed;
    const [next, ...rest] = journey.pending;
    const value = { ...journey, current: next, pending: rest, completed };
    update(value); setAdvanced(false); setTargetEditor(null); setAssignment(next);
    if (!next) { rememberJourney(journey.provider, null); setFinished(true); }
  }
  function additional(d: Descriptor, connection: ProviderConnection, requested: Purpose[]) {
    const groups = setupGroups(d, requested, connection.edition, "");
    if (!groups.length) return;
    const [next, ...rest] = groups;
    update({ provider: d.provider, edition: connection.edition, requested, current: next, pending: rest,
      completed: [], expires: Date.now() + 1800000 });
    setAssignment(next); setTargetEditor(null); setAdvanced(false);
  }
  const progress = journey?.completed.length ? L(`저장한 기능 ${journey.completed.flatMap(c => c.purposes).map(p => featureName(p, L)).join(" · ")} · 추가 인증을 계속합니다`,
    `Saved: ${journey.completed.flatMap(c => c.purposes).map(p => featureName(p, L)).join(" · ")}. Continue with additional sign-in.`) : assignment
    ? L("앞에서 선택한 기능에 필요한 추가 인증입니다. 기능별 인증정보는 분리해 보관합니다.", "Additional sign-in for the selected features. Each credential keeps its own scope.") : undefined;
  if (enterprise) return <GitHubEnterpriseModal conn={enterprise} onClose={() => setEnterprise(null)} />;
  if (finished) return <Modal onClose={close} labelledBy="setup-done" className="integ">
    <h2 id="setup-done">{L("선택한 기능의 설정을 마쳤습니다", "Selected features are configured")}</h2>
    <p>{journey?.completed.flatMap(c => c.purposes).map(p => featureName(p, L)).join(" · ")}</p>
    <p className="ig-hint">{L("인증정보가 다른 기능은 각각의 연결에서 관리합니다. 저장한 범위와 실행 주기는 연동 설정에서 변경할 수 있습니다.", "Features with different credentials keep separate connections. Update their scope and schedule in integration settings.")}</p>
    {journey?.provider === "github" ? <GitHubSetupNext completed={journey.completed.map(c => c.id)} onEnterprise={setEnterprise} /> : null}
    <div className="modal-foot"><button type="button" className="primary-btn" onClick={close}>{L("연동 현황 보기", "View connected services")}</button></div>
  </Modal>;
  const entry = open.entry;
  const editingDescriptor = targetEditor && props.catalog.providers.find(d => d.provider === targetEditor.provider);
  if (targetEditor && editingDescriptor) return <AuthFirstWizard descriptor={editingDescriptor} existing={targetEditor} admin={props.admin} entry={entry}
    initialPurposes={entry === "exposure" ? ["id" in open && open.addPurpose || "exposure"] : "id" in open && open.addPurpose ? [open.addPurpose] : undefined}
    schedulesAllowed={props.catalog.schedules_allowed}
    onClose={close} onAdvanced={() => setTargetEditor(null)} />;
  const initialPurposes = assignment?.purposes ?? journey?.requested ?? ("provider" in open && open.purpose && descriptor?.purposes[open.purpose as Purpose] ? [open.purpose as Purpose] : undefined);
  if (!advanced && descriptor?.auth_methods.some(m => m.auth_first && m.new_setup !== false) && (!assignment || descriptor.auth_methods.find(m => m.id === assignment.method)?.auth_first)) return <AuthFirstWizard
    key={assignment ? `${assignment.edition}:${assignment.method}:${assignment.purposes.join()}` : "initial"} descriptor={descriptor} resumeOauth={oauthDraft} admin={props.admin} schedulesAllowed={props.catalog.schedules_allowed}
    initialPurposes={initialPurposes} initialMethod={assignment?.method} initialEdition={assignment?.edition ?? journey?.edition ?? ("provider" in open ? open.edition : undefined)} supplemental={Boolean(assignment)} progress={progress}
    authenticationOnly={props.authenticationOnly} entry={entry}
    onIntent={assignment ? undefined : (edition, requested) => selected(descriptor, edition, requested, undefined, [])}
    onSelection={assignment ? undefined : (edition, requested, current, rest) => selected(descriptor, edition, requested, current, rest)}
    onDeferred={(edition, requested, groups) => { const [next, ...rest] = groups; selected(descriptor, edition, requested, next, rest); setAssignment(next); }}
    onComplete={advance}
    initialTarget={{ ...(props.catalog.sign_in_idp?.provider === descriptor.provider ? props.catalog.sign_in_idp.target ?? {} : {}),
      ...("provider" in open ? open.target ?? {} : {}) }} onClose={close} onAdvanced={(method, edition) => { setLegacyMethod({ method, edition }); setAdvanced(true); }} />;
  return <ConnectionSettings {...props} key={assignment ? `${assignment.edition}:${assignment.method}:${assignment.purposes.join()}` : "settings"}
    open={assignment && descriptor ? { provider: descriptor.provider, purpose: assignment.purposes[0], entry } : open}
    setupGroup={assignment} setupEdition={assignment?.edition ?? legacyMethod?.edition ?? journey?.edition ?? ("provider" in open ? open.edition : undefined)} initialMethod={legacyMethod?.method} progress={progress} onClose={close}
    onSelection={assignment ? undefined : selected} onComplete={assignment || "provider" in open ? advance : undefined} onAdditional={additional} onEditTargets={setTargetEditor} />;
}

function GitHubSetupNext({ completed, onEnterprise }: { completed: string[]; onEnterprise: (c: ProviderConnection) => void }) {
  const L = useL();
  const [connections, setConnections] = useState<ProviderConnection[]>([]);
  useEffect(() => {
    let active = true;
    void Promise.all(completed.map(id => api<ProviderConnection>(`${CONNECTIONS_PATH}/${id}`)))
      .then(items => { if (active) setConnections(items); }).catch(() => { /* The integration menu offers the same action after reloading. */ });
    return () => { active = false; };
  }, [completed.join(",")]);
  const ready = connections.filter(enterpriseReady);
  return <div className="ig-section">
    <p className="ig-hint">{L("이미 App이 설치된 조직은 대상 수정에서 함께 선택할 수 있습니다. 엔터프라이즈의 다른 조직에 설치하려면 App 소유권 이전, 엔터프라이즈 조직 설치 권한, 엔터프라이즈 설치가 필요합니다. 설치할 조직과 저장소 콘텐츠 검사 범위는 각각 선택합니다.",
      "Select installed organizations together when editing targets. Installing on other enterprise organizations requires transferring App ownership, the enterprise organization installations permission, and an enterprise installation. Choose installation organizations and repository scan scope separately.")}</p>
    {ready.map(c => <button key={c.id} type="button" className="ghost-btn" onClick={() => onEnterprise(c)}>{L("엔터프라이즈 조직에 설치", "Install on enterprise organizations")}</button>)}
  </div>;
}

function ConnectionSettings({ catalog, open, onClose, admin, onMachineIdentity, health, onNext, connected, onEditTargets, setupGroup, setupEdition, initialMethod, progress: setupProgress, onSelection, onComplete, onAdditional }: WizardProps & {
  onEditTargets: (c: ProviderConnection) => void; setupGroup?: SetupGroup; setupEdition?: string; initialMethod?: string; progress?: string;
  onComplete?: (connection: ProviderConnection) => void; onAdditional: (d: Descriptor, c: ProviderConnection, purposes: Purpose[]) => void;
  onSelection?: (d: Descriptor, edition: string, requested: Purpose[], current: SetupGroup | undefined, pending: SetupGroup[]) => void;
}) {
  const L = useL();
  const locale = useLocale();
  const toast = useToast();
  const saved = useSaved();
  const edit = !("provider" in open);
  // The card the wizard was opened from (a new or an existing connection) shows only its own features; the others stay as
  // they are.
  const entry = open.entry;
  const [conn, setConn] = useState<ProviderConnection | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [provider, setProvider] = useState<string>("provider" in open ? open.provider : "");
  const d = catalog.providers.find(item => item.provider === (conn?.provider ?? provider));
  const [step, setStep] = useState<Step>("id" in open && open.step ? open.step : 1);
  const [edition, setEdition] = useState<string>(setupEdition ?? d?.editions[0]?.id ?? "");
  // A link may name the feature to start with (the dashboard's secret store gap names the vault).
  const [purposes, setPurposes] = useState<Purpose[]>(() => {
    if (!d) return [];
    const asked = "provider" in open && open.purpose && d.purposes[open.purpose as Purpose] ? [open.purpose as Purpose] : null;
    return setupGroup?.purposes ?? asked ?? firstPurposes(d, d.editions[0].id);
  });
  const [targetValues, setTargetValues] = useState<Values>(() => ({ ...defaults(d?.target ?? []),
    // A team install's sign-in IdP opens with what its issuer names (its organization, tenant or realm) when it is
    // opened to read people; a Microsoft connection for another tenant's inventory starts empty.
    ...(d && catalog.sign_in_idp?.provider === d.provider
      && (("provider" in open && open.purpose === "identity") || purposesOf(d).every(p => p === "identity"))
      ? catalog.sign_in_idp.target ?? {} : {}),
    ...("provider" in open && open.target ? open.target : {}) }));
  const [plans, setPlans] = useState<Partial<Record<Purpose, Values>>>({});
  const [additionalPurposes, setAdditionalPurposes] = useState<Purpose[]>([]);
  const [methodId, setMethodId] = useState<string>(setupGroup?.method ?? initialMethod ?? "");
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  const [byRef, setByRef] = useState(false);
  const [reference, setReference] = useState("");
  const [name, setName] = useState("");
  const [schedule, setSchedule] = useState<number | null>(null);
  // The full-scan choice: -1 keeps an existing scope's own, INSTALLATION_DEFAULT saves null (the installation's default).
  const [fullSchedule, setFullSchedule] = useState<number | null>(null);
  // Whether a new scope scans what changed when its provider says so.
  const [changeScans, setChangeScans] = useState(true);
  const [busy, setBusy] = useState<"" | "test" | "finish" | "google" | "restart" | "github" | "feature">("");
  // A GitHub App's values typed by hand (an App registered on GitHub by the admin) instead of made by GitHub.
  const [typeApp, setTypeApp] = useState(false);
  const [polling, setPolling] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<Created[]>([]);
  const [started, setStarted] = useState<Purpose[]>([]);
  // The token's expiry an admin enters (YYYY-MM-DD, "" clears it); null leaves the entered one as it is.
  const [expiry, setExpiry] = useState<string | null>(null);
  const [expiryLeft, setExpiryLeft] = useState(0);
  const [expirySaving, setExpirySaving] = useState(false);
  const [scopeMode, setScopeMode] = useState<ScopeMode | "keep">(edit ? "keep" : "all");
  const [scopeText, setScopeText] = useState("");
  const [scopeNow, setScopeNow] = useState<{ count: number; unit: string } | null>(null);
  const [progress, setProgress] = useState<Record<string, ScopeProgress>>({});
  // A feature being switched back on while the check it needs is running.
  const [resuming, setResuming] = useState<Purpose | null>(null);
  // The refused features last listed: shown while a new check runs, when the evidence on screen is not current.
  const [heldShown, setHeldShown] = useState<Purpose[]>([]);
  // A held feature being checked again; it is turned on once the check passes for it.
  const [retrying, setRetrying] = useState<Purpose | null>(null);
  // Every AWS integration CreMore reaches itself goes through the AWS identity an administrator approved;
  // testing an AWS connection approves it, as entering any other provider's credential does.
  const identity = useApi<AwsIdentityView>((conn?.provider ?? provider) === "aws" ? IDENTITY_PATH : null, { every: 0 });
  const [roleArn, setRoleArn] = useState("");
  const [ssoRegion, setSsoRegion] = useState("");
  const adopted = useRef(false);
  const leaving = useRef(false);
  // Development mounts twice; the second mount is the one that stays.
  useEffect(() => { leaving.current = false; return () => { leaving.current = true; }; }, []);

  const copy = useCallback((text: string) => {
    navigator.clipboard?.writeText(text).then(() => toast(L("복사했습니다", "Copied")), () => toast(L("복사하지 못했습니다", "Could not copy"), "bad"));
  }, [L, toast]);

  // A new credential every owned record should now use; one that could not be moved keeps the earlier credential.
  const moved = useCallback((record: ProviderConnection & { not_updated?: string[] }) => {
    const left = record.not_updated?.length ?? 0;
    if (left) setError(L(`수집 ${left}개가 새 자격증명으로 바뀌지 않아 이전 자격증명을 쓰고 있습니다. 새로 불러온 뒤 자격증명을 다시 저장하세요.`,
      `${left} collection${left > 1 ? "s" : ""} could not move to the new credential and still use${left > 1 ? "" : "s"} the earlier one. Reload and save the credential again.`));
  }, [L]);
  const fail = useCallback((reason: unknown, fields: FieldSpec[] = []) => {
    const message = reason instanceof Error ? reason.message : "";
    setError(onboardingText(message, fields, L) ?? reasonText(reason, L));
  }, [L]);

  // An existing connection, or one coming back from Google: its settings become the wizard's.
  const adopt = useCallback((record: ProviderConnection) => {
    setConn(record);
    if (adopted.current) return;
    adopted.current = true;
    const found = catalog.providers.find(item => item.provider === record.provider);
    setProvider(record.provider);
    setEdition(record.edition);
    const requested = "id" in open ? open.addPurpose : undefined;
    setPurposes(requested && !record.purposes.includes(requested) ? [...record.purposes, requested] : record.purposes);
    setScopeMode(record.plans.exposure ? "keep" : "all");
    setMethodId(record.auth_method);
    setName(record.name);
    if (found) setTargetValues(valuesOf(found.target ?? [], record.target));
  }, [catalog.providers]);

  useEffect(() => {
    if ("provider" in open) return;
    let live = true;
    (async () => {
      try {
        const id = "oauth" in open ? await completeSignIn(open.oauth) : open.id;
        const record = await api<ProviderConnection>(`${CONNECTIONS_PATH}/${id}`);
        if (!live) return;
        adopt(record);
        if ("id" in open && (record.checks.authentication_only || open.addPurpose && record.provider !== "aws")
          && catalog.providers.find(d => d.provider === record.provider)?.auth_methods.some(m => m.id === record.auth_method && m.auth_first)) {
          onEditTargets(record); return;
        }
        if ("oauth" in open) { setStep(2); setPolling(true); saved(); }
        else if (record.checks.requested_at && !checked(record) && record.status !== "DISABLED") setPolling(true);
        else if (!open.step) setStep(record.status === "ACTIVE" ? 1 : record.status === "CHECKED" && checked(record) ? 3 : 2);
      } catch (reason) {
        if (!live) return;
        const message = reason instanceof Error ? reason.message : "";
        setLoadError(message.startsWith("GCP_OAUTH_SESSION_EXPIRED")
          ? L("Google 승인 세션이 만료됐습니다. 연동 설정에서 다시 승인하세요.", "The Google approval session expired. Approve again from the integration settings.")
          : onboardingText(message, [], L) ?? reasonText(reason, L));
      }
    })();
    return () => { live = false; };
  // The wizard reads its connection once; later changes come back from its own requests.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Follow the worker's permission check until it answers for the connection as it is now.
  useEffect(() => {
    if (!polling || !conn) return;
    let stop = false, timer = 0;
    const began = Date.now();
    const tick = async () => {
      try {
        const next = await api<ProviderConnection>(`${CONNECTIONS_PATH}/${conn.id}`);
        if (stop) return;
        setConn(next);
        if (checked(next)) { setPolling(false); saved(); return; }
      } catch { /* A missed poll is retried; the limit below ends the wait. */ }
      if (stop) return;
      if (Date.now() - began > POLL_LIMIT_MS) {
        setPolling(false);
        setError(L("권한 확인이 끝나지 않았습니다. 운영 상태에서 워커가 실행 중인지 본 뒤 다시 확인하세요.", "The access check has not finished. Check that the worker is running in Operations, then test again."));
        return;
      }
      timer = window.setTimeout(tick, POLL_MS);
    };
    timer = window.setTimeout(tick, 900);
    return () => { stop = true; window.clearTimeout(timer); };
  // Keyed by the connection id: its own updates must not restart the wait.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [polling, conn?.id]);

  // Once that check has answered, switch the feature on (once); a wait that ended unanswered drops it, and a feature
  // someone else switched on meanwhile is left as it is.
  useEffect(() => {
    if (polling || !resuming || !conn) return;
    setResuming(null);
    if (checked(conn) && conn.feature_enabled?.[resuming] === false) void switchFeature(conn, resuming, true, true);
  // Only the end of the wait matters; switchFeature reads the connection it is given.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [polling, resuming]);

  useEffect(() => {
    if (polling || !retrying || !conn) return;
    setRetrying(null);
    if (checked(conn)) void startHeld(conn, retrying);
  // Only the end of the wait matters; startHeld reads the connection it is given.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [polling, retrying]);

  const active = useMemo(() => new Set(Object.keys(conn?.plans ?? {}) as Purpose[]), [conn]);

  // An exposure scan already running shows the scope it reads now.
  const scopeKey = conn && conn.plans.exposure ? scopeTargets(conn).map(target => target.id).join(",") : "";
  useEffect(() => {
    if (!conn || !scopeKey) return;
    let live = true;
    const targets = scopeTargets(conn);
    Promise.all(targets.map(target => readProfiles(target).then(page => scopedCount(page.profiles)).catch(() => 0)))
      .then(counts => { if (live) setScopeNow({ count: counts.reduce((sum, n) => sum + n, 0), unit: unitOf(targets[0]?.sourceType ?? "", L) }); });
    return () => { live = false; };
  // Read once per set of targets; the wizard's own saves report what they changed.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scopeKey]);

  if (!d) {
    return <Modal onClose={onClose} labelledBy="ig-title" className="integ">
      <h2 id="ig-title">{L("연동 설정", "Integration settings")}</h2>
      {loadError ? <Banner tone="bad" icon="alert">{loadError}</Banner>
        : <div className="loading-line" role="status"><span className="spinner" aria-hidden="true" />{L("불러오는 중", "Loading")}</div>}
      <div className="modal-foot"><button type="button" className="ghost-btn" onClick={onClose}>{L("닫기", "Close")}</button></div>
    </Modal>;
  }

  const locked = Boolean(conn);
  const tFields = targetFields(d, edition, targetValues);
  const targetNow: Record<string, unknown> = conn ? sharedTarget(conn.target) : payload(tFields, targetValues);
  const methods = methodsFor(d, purposes.length ? purposes : conn?.purposes ?? purposesOf(d), edition, conn?.auth_method);
  const method: Method | undefined = methods.find(item => item.id === methodId)
    ?? (conn ? d.auth_methods.find(item => item.id === conn.auth_method) : undefined) ?? methods[0];
  // What this card edits: started, re-planned and validated here. The connection's other features are kept as saved:
  // active ones are checked with their saved plans, unfinished ones are left for their own card.
  const own = purposes.filter(p => inEntryView(p, entry));
  const checkPurposes = purposes.filter(p => inEntryView(p, entry) || active.has(p));
  const toStart = own.filter(p => !active.has(p));
  const purposesChanged = Boolean(conn && (purposes.length !== conn.purposes.length || purposes.some(p => !conn.purposes.includes(p))));
  const planOf = (p: Purpose) => planFields(d, p, edition, targetNow, active.has(p));
  // A feature already collecting starts from its saved plan; changing it applies from the next run. Only the options
  // this edition and target offer count: a choice made before the target changed and hid it is not sent or counted.
  const planValues = (p: Purpose): Values => valuesOf(planOf(p), plans[p] ?? (active.has(p) ? conn?.plans[p] ?? {} : {}));
  const scheduled = (p: Purpose) => planOf(p).some(field => field.name === "schedule_minutes");
  const scheduleSaved = own.filter(p => active.has(p)).map(p => conn?.plans[p]?.schedule_minutes).find(value => typeof value === "number") as number | undefined;
  const scheduleDefault = toStart.map(p => planOf(p).find(field => field.name === "schedule_minutes")?.default).find(value => typeof value === "number") as number | undefined;
  const scheduleNow = schedule ?? scheduleSaved ?? scheduleDefault ?? 1440;
  const hasSchedule = own.some(scheduled);
  // What a purpose's plan sends: a schedule picked in step 3 reaches every feature of this card; left alone, or not this
  // card's, each keeps its own.
  const planBody = (p: Purpose) => {
    const fields = planOf(p);
    const keep = active.has(p) && (schedule === null || !inEntryView(p, entry));
    return payload(fields, { ...planValues(p), ...(scheduled(p) && !keep ? { schedule_minutes: String(scheduleNow) } : {}) });
  };
  const replans = own.filter(p => active.has(p) && JSON.stringify(planBody(p)) !== JSON.stringify(payload(planOf(p), valuesOf(planOf(p), conn?.plans[p] ?? {}))));
  // One feature's own answer in a check: it can start when nothing it needs was refused or left unverified.
  const passes = (record: ProviderConnection, p: Purpose) =>
    ["ok", "none"].includes(checkSummary(checkItems(record, [p], d, { [p]: planValues(p) })));
  const serviceName = label(d, L);
  const scanEntry = entry === "exposure" ? scanEntryOf(d, L) : null;
  const regionOptions = (d.purposes.inventory?.plan?.find(field => field.name === "cloudtrail_regions")?.options ?? []).map(option => ({ id: option.id, label: label(option, L) }));
  const editionName = d.editions.length > 1 ? label(d.editions.find(item => item.id === edition) ?? d.editions[0], L) : null;
  const allFields = [...(d.target ?? []), ...d.auth_methods.flatMap(item => item.fields ?? []), ...purposesOf(d).flatMap(p => d.purposes[p]?.plan ?? [])];

  /* ---------- step 1: what to collect ---------- */

  const togglePurpose = (p: Purpose) => setPurposes(list => list.includes(p) ? list.filter(item => item !== p) : inOrder(d, [...list, p]));
  const setTarget = (field: string, value: string | boolean | string[]) => setTargetValues(values => ({ ...values, [field]: value }));
  const setPlan = (p: Purpose, field: string, value: string | boolean | string[]) => setPlans(all => ({ ...all, [p]: { ...planValues(p), [field]: value } }));
  const planMissing = own.map(p => missingRequired(planOf(p).filter(field => field.name !== "schedule_minutes"), planValues(p))).find(Boolean);
  // A team install reads people only from the IdP people sign in with (the API decides; this says why first).
  const peopleBlock = active.has("identity") ? null : peopleDirectoryBlock(catalog, d, targetNow, L);
  const step1Ready = own.length > 0 && !planMissing && !(own.includes("identity") && peopleBlock)
    && (locked || (!missingRequired(tFields, targetValues) && methods.length > 0));

  async function switchFeature(record: ProviderConnection, purpose: Purpose, enabled: boolean, retried = false) {
    setBusy("feature"); setError(null);
    try {
      const next = await send<ProviderConnection>(`${CONNECTIONS_PATH}/${record.id}/features/${purpose}`, "PUT", {
        enabled, expected_revision: record.revision });
      setConn(next); saved();
    } catch (reason) {
      // Switching back on needs permission evidence from the last 30 minutes: ask for the check, then switch on once it answers.
      if (enabled && !retried && reason instanceof Error && reason.message.startsWith("PERMISSION_CHECK_REQUIRED")) {
        try {
          const next = await send<ProviderConnection>(`${CONNECTIONS_PATH}/${record.id}/check`, "POST");
          setConn(next); setResuming(purpose); setPolling(true);
        } catch (failure) { fail(failure); }
      } else fail(reason);
    } finally { setBusy(""); }
  }
  const featureCards = <><div className="ig-feats">
    {(setupGroup?.purposes ?? [...new Set([...purposesForEdition(d, edition), ...(conn?.purposes ?? [])])]).filter(p => inEntryView(p, entry)).map(p => {
      const fixed = active.has(p);
      const on = fixed ? conn?.feature_enabled?.[p] !== false : purposes.includes(p) || additionalPurposes.includes(p);
      const blocked = !on && (!combinable(d, purposes, p, edition, conn?.auth_method)
        || Boolean(conn && !methodsFor(d, [...purposes, p], edition, conn.auth_method).some(item => item.id === conn.auth_method)));
      const extra = additionalPurposes.includes(p) || blocked;
      const people = p === "identity" && !on ? peopleBlock : null;
      const requiredEdition = d.editions.find(e => e.id === edition && methodsFor(d, [p], e.id, conn?.auth_method).length);
      const available = requiredEdition ? methodsFor(d, [p], requiredEdition.id, conn?.auth_method) : [];
      const disabled = !admin || Boolean(busy) || Boolean(resuming) || Boolean(setupGroup) || Boolean(people);
      const tip = fixed ? L("기능을 끄거나 다시 켭니다. 수집 이력과 설정은 유지합니다.", "Turn this feature off or on. Its settings and history are kept.")
        : people ? people
          : blocked && (p === "remediation" || purposes.includes("remediation"))
            ? L("별도 조치용 인증을 이어서 설정합니다.", "Continue with a separate acting credential.")
            : blocked ? L("이 기능의 추가 인증을 같은 설정 흐름에서 진행합니다.", "Continue its additional sign-in in this setup.") : undefined;
      return <button type="button" key={p} className="ig-feat-card" role="checkbox" aria-checked={on} aria-disabled={disabled || undefined}
        data-tip={tip} onClick={() => {
          if (disabled) return;
          if (fixed) { if (conn) void switchFeature(conn, p, conn.feature_enabled?.[p] === false); return; }
          if (!available.length) { setError(L("이 기능을 지원하는 제품·판으로 새 인증을 설정해야 합니다.", "Set up a new sign-in with an edition supporting this feature.")); return; }
          if (extra) { setAdditionalPurposes(all => all.includes(p) ? all.filter(x => x !== p) : [...all, p]); return; }
          togglePurpose(p);
        }}>
        <Check on={on} />
        <span className="ig-feat-ic"><Ic name={FEATURE_ICON[p]} size={18} /></span>
        <span className="ig-feat-text"><span className="t">{featureName(p, L)}{fixed ? <span className="ig-feat-on">{on ? L("켜짐", "On") : L("꺼짐", "Off")}</span> : null}</span>
          <span className="d">{featureText(p, serviceName, L, d.provider)}</span>
          {extra && available.length ? <span className="d">{L("추가 인증", "Additional sign-in")}: {requiredEdition?.id !== edition ? `${label(requiredEdition!, L)} · ` : ""}{label(available[0], L)}</span> : null}</span>
      </button>;
    })}
  </div>
  {edit && conn && additionalPurposes.length ? <div className="ig-section"><p className="ig-hint">{L("기존 연결은 유지하며 선택한 기능의 추가 인증을 이어서 설정합니다. 아직 저장하지 않은 옵션 변경은 먼저 저장하세요.", "Keep the existing connection and continue additional sign-in for the selected features. Save any unsaved option changes first.")}</p>
    <button type="button" className="primary-btn" disabled={Boolean(busy)} onClick={() => onAdditional(d, conn, additionalPurposes)}>{L("선택한 기능의 추가 인증", "Continue selected features")}</button></div> : null}</>;
  const resumeNote = resuming ? <Banner icon="info">{L(`${featureName(resuming, L)} 다시 켜기: 권한을 확인하고 있습니다. 확인되면 바로 켭니다.`,
    `Turning ${featureName(resuming, L)} back on: checking access first; it switches on once the check passes.`)}</Banner> : null;

  const targetSection = <div className="ig-section">
    <div className="ig-section-head"><h3>{L("연동 대상", "Where to connect")}</h3>
      {locked && !edit ? <button type="button" className="link-btn ig-all" disabled={Boolean(busy)} onClick={() => void restart()}>{L("대상 다시 정하기", "Change the target")}</button> : null}</div>
    {conn ? <dl className="kv ig-target-kv">
      {conn.target.version === 2 ? <><dt>{L("선택한 대상", "Selected targets")}</dt><dd>{targetSummary(d, conn)}</dd></> : null}
      {editionName ? <><dt>{L("제품", "Edition")}</dt><dd>{editionName}</dd></> : null}
      {(d.target ?? []).filter(field => field.kind !== "multiline" && conn.target[field.name] !== undefined && conn.target[field.name] !== "").map(field =>
        <Fragment key={field.name}><dt>{label(field, L)}</dt><dd className={field.kind === "id" || field.kind === "url" || field.kind === "list" ? "mono" : undefined}>{shown(field, conn.target[field.name], L)}</dd></Fragment>)}
    </dl> : <>
      {d.editions.length > 1 ? <div className="row2 ig-fields"><SelectField label={L("제품", "Edition")} value={edition} disabled={Boolean(setupGroup)} options={d.editions.map(item => ({ id: item.id, label: label(item, L) }))}
        onChange={value => { setEdition(value); setMethodId(""); setPlans({}); setPurposes(list => list.filter(p => combinable(d, list.filter(item => item !== p), p, value))); }} /></div> : null}
      <FieldGrid fields={tFields} values={targetValues} onChange={setTarget} />
    </>}
    {own.includes("identity") && peopleBlock ? <Banner tone="warn" icon="alert">{peopleBlock}</Banner> : null}
    {/* The connection's targets serve every feature: they are changed from the account card or the full settings, and a
        scan's own places from its scan scope. */}
    {entry !== "exposure" && conn?.status === "ACTIVE" && d.provider !== "aws" && d.auth_methods.some(m => m.id === conn.auth_method && m.auth_first) ?
      <button type="button" className="ghost-btn" disabled={!admin || Boolean(busy)} onClick={() => onEditTargets(conn)}>{L("인증된 목록에서 대상 추가·제외", "Add or remove targets from the authenticated list")}</button> : null}
    {entry !== "exposure" && conn?.status === "ACTIVE" && conn.target.version === 2 ? <ReduceTargets key={conn.revision} connection={conn} descriptor={d}
      disabled={!admin || Boolean(busy)} onSaved={next => { setConn(next); saved(); }} /> : null}
  </div>;

  const choices: TypeChoice[] = purposes.includes("inventory") && inEntryView("inventory", entry) ? typeChoices(d, edition, targetNow, planOf("inventory"), planValues("inventory")) : [];
  const shownByTypes = typeFields(choices, planOf("inventory"));
  const setTypes = (next: Values) => setPlans(all => ({ ...all, inventory: next }));
  const allTypes = choices.length > 0 && choices.every(choice => choice.on);
  const typeTip = (choice: TypeChoice) => {
    const permission = d.purposes.inventory?.permissions?.find(item => item.id === choice.type.permission);
    const parts = [choice.type.description ? L(choice.type.description_ko ?? choice.type.description, choice.type.description) : "",
      permission ? L(`필요 권한: ${label(permission, L)}`, `Needs: ${label(permission, L)}`) : ""];
    if (!choice.field) parts.push(L("이 연동에서 항상 가져옵니다", "Always collected by this integration"));
    else if (!switchable(choice)) parts.push(L(`아래 '${label(choice.field, L)}'에 넣은 곳에서 가져옵니다`, `Collected from what you list in '${label(choice.field, L)}' below`));
    return parts.filter(Boolean).join(" · ");
  };
  const typeSection = choices.length ? <div className="ig-section">
    <div className="ig-section-head"><h3>{L("가져올 Credential 유형", "Credential types to collect")}</h3>
      <button type="button" className="ig-all" role="checkbox" aria-checked={allTypes} disabled={!choices.some(switchable)}
        onClick={() => setTypes(choices.filter(switchable).reduce((values, choice) => switchType(choice, values, !allTypes), planValues("inventory")))}>
        <Check on={allTypes} />{L("모두 선택", "Select all")} <span className="num subtle">{choices.filter(choice => choice.on).length}/{choices.length}</span></button></div>
    <div className="ig-opts">{choices.map(choice => {
      const locked = !switchable(choice);
      return <button type="button" key={choice.type.id} className="ig-opt" role="checkbox" aria-checked={choice.on} aria-readonly={locked || undefined}
        data-tip={typeTip(choice)} onClick={() => { if (!locked) setTypes(switchType(choice, planValues("inventory"), !choice.on)); }}>
        <Check on={choice.on} /><span className="nm">{label(choice.type, L)}</span><Ic name="info" size={15} className="ig-opt-i" /></button>;
    })}</div>
  </div> : null;

  const scans = purposes.includes("exposure") && inEntryView("exposure", entry) ? scansFor(d, edition, targetNow) : [];
  const scopeSource = d.provider === "aws" ? "s3" : d.provider === "azure" ? "azure_blob" : d.provider;
  const scopeUnit = unitOf(scopeSource, L);
  const scopePatterns = splitPatterns(scopeText);
  const scopeMissing = own.includes("exposure") && scopeMode === "named" && !scopePatterns.length;
  // The content-scan card has no feature cards: a scan already set up is switched off and on from its own section.
  const scanOn = conn?.feature_enabled?.exposure !== false;
  const scanSwitch = entry === "exposure" && conn && active.has("exposure") ? <button type="button" className="ig-all" role="switch" aria-checked={scanOn}
    disabled={!admin || Boolean(busy) || Boolean(resuming)} onClick={() => void switchFeature(conn, "exposure", !scanOn)}
    data-tip={L("기능을 끄거나 다시 켭니다. 수집 이력과 설정은 유지합니다.", "Turn this feature off or on. Its settings and history are kept.")}>
    <Check on={scanOn} />{L(`이 계정의 ${featureName("exposure", L)} ${scanOn ? "켜짐" : "꺼짐"}`, `${featureName("exposure", L)} on this account: ${scanOn ? "On" : "Off"}`)}</button> : null;
  const scanSection = scans.length ? <div className="ig-section">
    <div className="ig-section-head"><h3>{L("노출을 검사할 위치", "Where to scan for exposures")}</h3>
      {scanSwitch}<span className={cls("ig-count", !scanSwitch && "ig-all")}><span className="num subtle">{scans.length}/{scans.length}</span></span></div>
    <div className="ig-opts">{scans.map(item => <button type="button" key={item.id} className="ig-opt" role="checkbox" aria-checked aria-readonly
      data-tip={[item.description ? L(item.description_ko ?? item.description, item.description) : "", L("노출 검사에서 항상 읽습니다", "Always read by the exposure scan")].filter(Boolean).join(" · ")}>
      <Check on /><span className="nm">{label(item, L)}</span><Ic name="info" size={15} className="ig-opt-i" /></button>)}</div>
    <div className="row2 ig-scope">
      <div className="field"><label htmlFor="ig-scope">{L("검사 범위", "Scan scope")}</label>
        <select id="ig-scope" value={scopeMode} onChange={event => setScopeMode(event.target.value as ScopeMode | "keep")}>
          {edit && active.has("exposure") ? <option value="keep">{scopeNow ? L(`지금 범위 유지 · ${scopeNow.unit} ${scopeNow.count}개`, `Keep the current scope · ${scopeNow.count} ${scopeNow.unit}`) : L("지금 범위 유지", "Keep the current scope")}</option> : null}
          <option value="all">{everythingOf(scopeSource, L)}</option>
          <option value="named">{L("지정한 곳만", "Only the places I name")}</option>
        </select></div>
      {scopeMode === "named" ? <div className="field"><label htmlFor="ig-scope-text">{L(`${scopeUnit} 이름·경로`, `Names or paths of ${scopeUnit}`)}</label>
        <input id="ig-scope-text" value={scopeText} onChange={event => setScopeText(event.target.value)} spellCheck={false}
          placeholder={scopeSource === "website" ? L("예: acme.com", "e.g. acme.com") : L("예: platform/*, data/ingest-worker", "e.g. platform/*, data/ingest-worker")} /></div> : null}
    </div>
    <p className="ig-hint"><Ic name="info" size={15} /><span>{scopeMode === "all"
      ? L(`연동을 마치면 ${scopeUnit} 목록을 가져와 지금 보이는 전부를 검사 범위로 저장하고 첫 검사를 시작합니다. 나중에 생긴 ${josa(scopeUnit, "은/는")} 범위를 다시 정할 때 들어갑니다.`, `After connecting, the ${scopeUnit} list is read and everything visible now is saved as the scan scope, then the first scan starts. Any ${scopeUnit} created later join when the scope is set again.`)
      : scopeMode === "named" ? L("* 는 아무 글자나 뜻합니다. 이름이나 경로가 맞는 곳만 검사 범위로 저장합니다.", "* matches any characters. Only places whose name or path matches are saved as the scan scope.")
        : L("지금 저장된 검사 범위를 그대로 씁니다.", "The saved scan scope stays as it is.")}</span></p>
  </div> : null;

  const optionFields = (p: Purpose) => planOf(p).filter(field => field.name !== "schedule_minutes" && !(p === "inventory" && shownByTypes.has(field.name))
    && !idleReaderField(d.provider, p, field.name, planValues(p)));
  const withOptions = purposes.filter(p => inEntryView(p, entry) && optionFields(p).length);
  const optionSections = withOptions.map(p => <div className="ig-section" key={p}>
    <div className="ig-section-head"><h3>{withOptions.length > 1 ? L(`${featureName(p, L)} · 추가 옵션`, `${featureName(p, L)} · Extra options`) : L("추가 옵션", "Extra options")}</h3></div>
    <FieldGrid fields={optionFields(p)} values={planValues(p)} onChange={(field, value) => setPlan(p, field, value)} valueReading />
  </div>);

  /* ---------- step 2: sign in and check ---------- */

  const fieldsOf = method?.fields ?? [];
  const sameMethod = Boolean(conn && method && conn.auth_method === method.id);
  const storedCredential = Boolean(sameMethod && conn!.credential.roles.length);
  const visible = fieldsOf.filter(field => !byRef || field.public);
  // A credential CreMore makes (a Microsoft app certificate): its public field says which app it is for, and
  // a certificate exists once it was made for this connection.
  const generating = Boolean(method?.generated);
  const made = sameMethod ? generatedOf(conn) : null;
  const madeKey = sameMethod ? madeKeyOf(conn) : null;
  // What CreMore makes: a certificate (Microsoft) or a signing key (Okta).
  const keyKind = d.provider === "okta";
  const storedPublic = sameMethod ? conn?.target.auth as Record<string, string> | undefined : undefined;
  const changedPublic = visible.some(field => secrets[field.name]?.trim() && secrets[field.name].trim() !== storedPublic?.[field.name]);
  const entered = generating ? changedPublic : Boolean(reference.trim()) || visible.some(field => secrets[field.name]?.trim());
  const filled = visible.filter(field => !field.optional).every(field => secrets[field.name]?.trim()) && (!byRef || Boolean(reference.trim()));
  const credentialReady = entered ? filled : storedCredential || filled;
  const credentialBody = () => {
    const given = Object.fromEntries(visible.filter(field => secrets[field.name]?.trim())
      .map(field => [field.name, field.kind === "multiline" ? secrets[field.name] : secrets[field.name].trim()]));
    return byRef ? { vault_ref: reference.trim(), ...given } : given;
  };
  const forget = () => { setSecrets({}); setReference(""); };
  // A token that expires: the date the provider reports for the records, or the one an admin entered. A new token
  // starts without the old token's date.
  const expires = Boolean(method && takesExpiry(method));
  const ownHealth = conn ? healthOf(conn, health) : [];
  const reportedExpiry = ownHealth.find(item => item.expires_source === "PROVIDER")?.expires_at ?? null;
  const storedDay = expiryDay(ownHealth.find(item => item.expires_source === "OPERATOR")?.expires_at);
  const enteredExpiry = expiry ?? (entered ? "" : storedDay);
  const today = expiryDay(new Date().toISOString());
  // A typed day before today would end the sign-in at once.
  const expiryInvalid = Boolean(expires && expiry && expiry < today);
  // The entered day (or "" to clear) on every record the token serves; read after they exist, from health itself.
  async function keepExpiry(record: ProviderConnection, day: string) {
    setExpirySaving(true);
    try {
      const fresh = await api<Health>(HEALTH_PATH).catch(() => null);
      const keys = fresh ? expiryKeys(record, fresh.items, day) : [];
      const failed = await saveExpiry((key, body) => send(`${HEALTH_PATH}/${encodeURIComponent(key)}/expiry`, "PUT", body), keys, day);
      setExpiryLeft(failed.length + (fresh ? 0 : record.children.length));
      setExpiry(null); saved();
    } finally { setExpirySaving(false); }
  }
  // What a made credential is for: the typed values, or the ones the stored certificate was made with.
  const madeFor = () => Object.fromEntries(visible.map(field => [field.name, secrets[field.name]?.trim() || storedPublic?.[field.name] || ""]));
  const madeReady = generating && visible.filter(field => !field.optional).every(field => madeFor()[field.name]);

  async function savePurposes() {
    if (!conn || !purposesChanged) return conn;
    const next = await send<ProviderConnection>(`${CONNECTIONS_PATH}/${conn.id}/purposes`, "PUT",
      { purposes, expected_revision: conn.revision });
    setConn(next); saved();
    return next;
  }

  // CreMore makes the key and the certificate; nothing secret is typed. A new connection is stored with it (the
  // check waits until the certificate is uploaded); an existing one takes a new certificate for every record.
  async function makeCertificate() {
    if (!method) return;
    setBusy("test"); setError(null);
    try {
      let current = await savePurposes();
      if (!current) {
        current = await send<ProviderConnection>(CONNECTIONS_PATH, "POST", { provider: d!.provider, edition, purposes,
          auth_method: method.id, target: payload(tFields, targetValues), credential: madeFor() });
        setName(current.name); adopted.current = true;
      } else {
        current = await send<ProviderConnection>(`${CONNECTIONS_PATH}/${current.id}/credential`, "PUT",
          { auth_method: method.id, credential: madeFor(), expected_revision: current.revision });
        moved(current);
      }
      forget(); setConn(current); saved();
    } catch (reason) {
      fail(reason, allFields);
    } finally { setBusy(""); }
  }
  const scheduleNames = new Set(purposes.flatMap(p => planOf(p).filter(f => f.name === "schedule_minutes" || f.schedule).map(f => f.name)));
  const accessPlan = (value: Record<string, unknown>) => Object.fromEntries(Object.entries(value).filter(([key]) => !scheduleNames.has(key)).sort(([a], [b]) => a.localeCompare(b)));
  const checkedAt = Date.parse(conn?.checks.checked_at ?? "");
  const checkedNow = Boolean(conn && !purposesChanged && sameMethod && checked(conn)
    && Number.isFinite(checkedAt) && checkedAt <= Date.now() && Date.now() - checkedAt <= 30 * 60 * 1000
    && checkPurposes.every(p => conn.checks.requested_plans?.[p]
      && JSON.stringify(accessPlan(conn.checks.requested_plans[p]!)) === JSON.stringify(accessPlan(planBody(p)))));
  const awsIdentity = d.provider === "aws" && method?.id !== "customer_cli";
  const idView = awsIdentity ? identity.data ?? null : null;
  const approving = Boolean(idView && needsApproval(idView));
  const idNeeds = idView && approving ? approval(idView, admin).needs : null;
  const idIssue = idView ? identityIssue(idView, L, approving) : null;
  const idInputMissing = (idNeeds === "ROLE_ARN" && !roleArn.trim()) || (idNeeds === "IDENTITY_CENTER_REGION" && !ssoRegion.trim());
  // What keeps "Test connection" from running for AWS: the identity is still being read, or cannot be used.
  const idBlocked = awsIdentity && (!idView || Boolean(idIssue) || idInputMissing || (approving && !admin));
  const items = conn && checkedNow ? checkItems(conn, checkPurposes, d, Object.fromEntries(checkPurposes.map(p => [p, planValues(p)]))) : [];
  const summary = checkSummary(items);
  // Each of this card's features stands on its own check: those that pass go on, the refused ones are held. Features
  // already collecting are never switched off by a refusal.
  const someReady = Boolean(conn && checkedNow && own.some(p => passes(conn, p)));
  const heldNow = conn && checkedNow ? [...toStart, ...replans].filter(p => !passes(conn, p)) : [];
  // A refused feature is left off at finishing and listed; the server checks again what is sent. Read from the current
  // check, so a connection reopened at review (CHECKED) holds the same features; the done step keeps the ones held at
  // finishing until each is turned on, and a running check shows the last list.
  const held = step !== 4 && checkedNow ? heldNow : heldShown;
  const startNow = toStart.filter(p => !held.includes(p));

  async function test() {
    if (!method) return;
    setBusy("test"); setError(null);
    try {
      if (idView && approving) {
        try {
          const next = await send<AwsIdentityView>(IDENTITY_PATH, "PUT", {
            confirm: true, ...(roleArn.trim() ? { role_arn: roleArn.trim() } : {}), ...(ssoRegion.trim() ? { sso_region: ssoRegion.trim() } : {}) });
          identity.replace(next);
        } catch (reason) {
          setError(refusalText(reason instanceof Error ? reason.message : "", L, idView?.identity_source) ?? reasonText(reason, L));
          return;
        }
      }
      let current = await savePurposes();
      if (!current) {
        current = await send<ProviderConnection>(CONNECTIONS_PATH, "POST", { provider: d!.provider, edition, purposes,
          auth_method: method.id, target: payload(tFields, targetValues), credential: credentialBody() });
        forget(); setConn(current); setName(current.name); adopted.current = true;
        current = await send<ProviderConnection>(`${CONNECTIONS_PATH}/${current.id}/check`, "POST", { plans: Object.fromEntries(checkPurposes.map(p => [p, planBody(p)])) });
      } else if (entered || current.auth_method !== method.id) {
        current = await send<ProviderConnection>(`${CONNECTIONS_PATH}/${current.id}/credential`, "PUT",
          { auth_method: method.id, credential: credentialBody(), expected_revision: current.revision });
        forget(); moved(current);
        current = await send<ProviderConnection>(`${CONNECTIONS_PATH}/${current.id}/check`, "POST", { plans: Object.fromEntries(checkPurposes.map(p => [p, planBody(p)])) });
        // The records now use the new token: its date replaces the old one's (none entered clears it).
        if (expires && !reportedExpiry && current.children.length) await keepExpiry(current, enteredExpiry);
      } else {
        current = await send<ProviderConnection>(`${CONNECTIONS_PATH}/${current.id}/check`, "POST", { plans: Object.fromEntries(checkPurposes.map(p => [p, planBody(p)])) });
        // Checking again keeps a date changed on its own, as saving at the review step would.
        if (expires && !reportedExpiry && expiry !== null && current.children.length) await keepExpiry(current, expiry);
      }
      setConn(current); setPolling(true); saved();
    } catch (reason) {
      fail(reason, allFields);
    } finally { setBusy(""); }
  }

  // GitHub makes the App from CreMore's manifest and the admin installs it; the API exchanges GitHub's code and
  // finds the installation, so no App ID, installation ID or key is typed. The page leaves for GitHub.
  async function github() {
    setBusy("github"); setError(null);
    try {
      const current = await savePurposes();
      await startGitHubApp({ ...(current ? { provider_connection_id: current.id } : {}), edition, purposes,
        target: conn ? Object.fromEntries(Object.entries(conn.target).filter(([key]) => key !== "auth")) : payload(tFields, targetValues),
        ...(name.trim() ? { name: name.trim() } : {}) });
    } catch (reason) {
      fail(reason, allFields); setBusy("");
    }
  }

  async function google() {
    if (!method) return;
    setBusy("google"); setError(null);
    try {
      let current = await savePurposes();
      if (!current) {
        current = await send<ProviderConnection>(CONNECTIONS_PATH, "POST", { provider: d!.provider, edition, purposes,
          auth_method: method.id, target: payload(tFields, targetValues), credential: {} });
        setConn(current); setName(current.name); adopted.current = true; saved();
      } else if (current.auth_method !== method.id) {
        current = await send<ProviderConnection>(`${CONNECTIONS_PATH}/${current.id}/credential`, "PUT",
          { auth_method: method.id, credential: {}, expected_revision: current.revision });
        setConn(current);
      }
      await startSignIn(current.id, locale);
    } catch (reason) {
      fail(reason, allFields); setBusy("");
    }
  }

  // Before activation the target can still change: an unused draft is deleted; one that already
  // registered records (AWS accounts) is stopped, so a new connection takes those records over.
  async function restart() {
    if (!conn) return;
    setBusy("restart"); setError(null);
    try {
      if (conn.children.length) await send(`${CONNECTIONS_PATH}/${conn.id}/disable`, "POST");
      else await send(`${CONNECTIONS_PATH}/${conn.id}`, "DELETE");
      setConn(null); setPolling(false); adopted.current = false; saved();
    } catch (reason) { fail(reason); }
    finally { setBusy(""); }
  }

  /* ---------- step 3: review and start ---------- */

  async function finish() {
    if (!conn) return;
    if (!edit && onSelection) {
      const requested = [...purposes, ...additionalPurposes];
      const groups = setupGroups(d!, requested, edition, conn.auth_method);
      onSelection(d!, edition, requested, groups[0], groups.slice(1));
    }
    setBusy("finish"); setError(null); setHeldShown(held);
    // Each request answers with the connection as it now is; a later refusal keeps what the earlier ones saved.
    let current = conn;
    try {
      const wanted = name.trim();
      if (wanted && wanted !== current.name) current = await send<ProviderConnection>(`${CONNECTIONS_PATH}/${current.id}`, "PATCH", { name: wanted, expected_revision: current.revision });
      let made: Created[] = [];
      if (startNow.length) {
        const body = Object.fromEntries(startNow.map(p => [p, planBody(p)]));
        const result = await send<ProviderConnection & { created?: Created[] }>(`${CONNECTIONS_PATH}/${current.id}/activate`, "POST", { purposes: body });
        made = result.created ?? [];
        current = result;
      }
      // A changed plan reaches the collections it runs on from their next run; one it adds may carry a collector token.
      for (const p of replans.filter(item => !held.includes(item))) {
        const result = await send<ProviderConnection & { changed?: Created[] }>(`${CONNECTIONS_PATH}/${current.id}/plans/${p}`, "PUT",
          { plan: planBody(p), expected_revision: current.revision });
        made = [...made, ...(result.changed ?? [])];
        current = result;
      }
      setStarted(all => [...new Set([...all, ...startNow])]); setConn(current); setCreated(all => [...all, ...made]); setStep(4); saved();
      // What started stays started: the expiry an admin entered follows, and a record it misses is said on the done step;
      // saving again fills in only the records not on that day yet.
      if (expires && expiry !== null && !reportedExpiry) void keepExpiry(current, expiry);
      if (current.plans.exposure && inEntryView("exposure", entry) && (startNow.includes("exposure") || scopeMode !== "keep")) void startScope(current);
    } catch (reason) { setConn(current); fail(reason, allFields); }
    finally { setBusy(""); }
  }

  // A held feature after its permissions were granted: check again, then start it (or save its changed plan) alone.
  async function retryHeld(p: Purpose) {
    if (!conn) return;
    setBusy("test"); setError(null);
    try {
      const next = await send<ProviderConnection>(`${CONNECTIONS_PATH}/${conn.id}/check`, "POST", { plans: Object.fromEntries(checkPurposes.map(q => [q, planBody(q)])) });
      setHeldShown(held); setConn(next); setRetrying(p); setPolling(true); saved();
    } catch (reason) { fail(reason); }
    finally { setBusy(""); }
  }

  // Still refused, it stays listed with what the new check found.
  async function startHeld(record: ProviderConnection, p: Purpose) {
    if (!passes(record, p)) {
      setError(L(`${featureName(p, L)}에 필요한 권한이 아직 없습니다. 보류된 기능의 목록을 확인하세요.`,
        `${featureName(p, L)} still lacks permissions it needs. See the held features list.`));
      return;
    }
    setBusy("finish"); setError(null);
    const replanned = Boolean(record.plans[p]);
    try {
      type Answer = ProviderConnection & { created?: Created[]; changed?: Created[] };
      const result = await (replanned
        ? send<Answer>(`${CONNECTIONS_PATH}/${record.id}/plans/${p}`, "PUT", { plan: planBody(p), expected_revision: record.revision })
        : send<Answer>(`${CONNECTIONS_PATH}/${record.id}/activate`, "POST", { purposes: { [p]: planBody(p) } }));
      setCreated(all => [...all, ...(result.created ?? []), ...(result.changed ?? [])]);
      setHeldShown(all => all.filter(item => item !== p));
      if (!replanned) setStarted(all => [...all, p]);
      setConn(result); saved();
      toast(replanned ? L(`${featureName(p, L)} 변경을 저장했습니다`, `${featureName(p, L)} changes saved`)
        : L(`${josa(featureName(p, L), "을/를")} 켰습니다`, `${featureName(p, L)} is on`));
      if (p === "exposure" && result.plans.exposure && inEntryView("exposure", entry)) void startScope(result);
    } catch (reason) { fail(reason, allFields); }
    finally { setBusy(""); }
  }

  // The scope an admin chose becomes the approved scope profile of every place the scan reads, and runs.
  async function startScope(record: ProviderConnection) {
    const mode: ScopeMode = scopeMode === "named" ? "named" : "all";
    const targets = scopeTargets(record);
    const cadence = schedule ?? (typeof record.plans.exposure?.schedule_minutes === "number" ? record.plans.exposure.schedule_minutes as number : scheduleNow);
    const full = fullSchedule ?? (edit ? -1 : INSTALLATION_DEFAULT);
    for (const target of targets) {
      const report = (value: ScopeProgress) => { if (!leaving.current) setProgress(all => ({ ...all, [target.id]: value })); };
      const result = await applyScope(target, mode, scopePatterns, {
        name: L(`${record.name} 노출 검사`, `${record.name} exposure scan`), schedule: cadence,
        fullScan: full === -1 ? undefined : full === INSTALLATION_DEFAULT ? null : full,
        events: changeScans && record.provider !== "website", L, report, stopped: () => leaving.current });
      report(result);
    }
    if (!leaving.current) saved();
  }

  /* ---------- rendering ---------- */

  const head = <h2 id="ig-title"><Logo id={scanEntry?.logo ?? d.provider} size={26} />{scanEntry?.title ?? serviceName} <small>{edit ? L("연동 설정", "Integration settings") : L("연동하기", "Connect")}</small></h2>;
  // What each held feature still misses, as its last check answered.
  const heldSection = held.length && conn ? <div className="ig-section">
    <div className="ig-section-head"><h3>{L("보류된 기능", "Held features")}</h3></div>
    <p className="ig-hint"><Ic name="info" size={15} /><span>{L("필요한 권한이 확인되지 않아 시작하거나 변경하지 않습니다. 이미 수집 중인 기능은 그대로 둡니다. 권한을 준 뒤 다시 확인하면 그 기능만 켭니다.",
      "Not started or changed: permissions they need were not confirmed. Features already collecting keep running. Grant the permissions and check again to turn on that feature only.")}</span></p>
    {held.map(p => <div className="ig-perm-group" key={p}>
      <span className="ig-sub">{featureName(p, L)}</span>
      <div className="ig-perms">{checkItems(conn, [p], d, { [p]: planValues(p) }).filter(item => item.status !== "GRANTED").map((item, index) => {
        const permission = d.purposes[p]?.permissions?.find(entry => entry.id === item.permission);
        const tip = [item.permission, checkWord(item.status, L), item.detail ? detailText(item.detail, L) : "", item.subject ?? ""].filter(Boolean).join(" · ");
        return <span key={`${item.permission}:${item.subject ?? index}`} className={cls("tag", item.status === "NOT_REPORTED" ? "perm-none" : "perm-bad")} data-tip={tip}>
          <Ic name={item.status === "NOT_REPORTED" ? "minusCircle" : "xCircle"} size={13} />{permission ? label(permission, L) : item.permission}{item.subject ? ` · ${item.subject}` : ""}</span>;
      })}</div>
      <div className="ig-test">
        <button type="button" className="ghost-btn" disabled={!admin || Boolean(busy) || polling} onClick={() => void retryHeld(p)}>
          <Ic name="refresh" size={15} />{L("권한 부여 후 다시 확인", "Check again after granting")}</button>
        {polling && retrying === p ? <span className="ig-result none" role="status"><span className="spinner" aria-hidden="true" />{L("권한을 확인하고 있습니다", "Checking access")}</span> : null}
      </div>
    </div>)}
  </div> : null;

  if (step === 4) {
    const tokens = created.filter(item => item.collector_token);
    // After a new start, the vendor's other services not connected yet -- once the scope being saved is saved.
    const family = started.length ? familyOf(d.provider) : null;
    const others = (family?.others ?? []).filter(other => !connected?.includes(other))
      .map(other => catalog.providers.find(item => item.provider === other)).filter((item): item is Descriptor => Boolean(item));
    const settling = expirySaving || Object.values(progress).some(value => ["listing", "selecting", "saving"].includes(value.step));
    const places = conn ? scopeTargets(conn).filter(target => progress[target.id]) : [];
    return <Modal onClose={onClose} labelledBy="ig-title" className="integ" dismissable={!tokens.length}>
      <div className="ig-done">
        <div className="big"><Ic name="checkCircle" size={30} /></div>
        {started.includes("remediation") ? <>
          <h2 id="ig-title">{L(`${serviceName} 조치용 연동을 켰습니다`, `${serviceName} is ready for approved actions`)}</h2>
          <p>{L("승인된 조치 계획을 실행할 때만 이 자격증명을 씁니다. Credential 상세의 조치 계획에서 요청하세요.",
            "This credential is used only when an approved action plan runs. Request one from a credential's action plans.")}</p>
        </> : <>
          <h2 id="ig-title">{onComplete ? L("이 단계의 기능을 저장했습니다", "Features in this step are saved") : started.length ? L(`${serviceName} 수집을 시작했습니다`, `Started collecting from ${serviceName}`) : L("변경을 저장했습니다", "Changes saved")}</h2>
          <p>{started.length ? L("첫 수집이 끝나면 Credential 목록과 Credential 관리 현황에 나타납니다.", "Results appear in the credential inventory and the overview after the first run.")
            : L("다음 수집부터 바뀐 범위로 가져옵니다.", "The next run uses the new settings.")}
          </p>
        </>}
      </div>
      {places.length ? <div className="ig-section ig-scope-progress" role="status">
        <div className="ig-section-head"><h3>{L("노출 검사 범위", "Exposure scan scope")}</h3></div>
        {places.map(target => <ScopeLine key={target.id} name={places.length > 1 ? target.name : ""} progress={progress[target.id]}
          onRetry={() => { if (conn) void startScope(conn); }} />)}
      </div> : null}
      {tokens.length ? <div className="ig-section ig-tokens">
        <Banner tone="warn" icon="alert">{L("수집기 토큰은 지금 한 번만 보여 줍니다. 복사해 고객 환경의 CreMore CLI 설정에 넣으세요.", "Collector tokens are shown only now. Copy them into the CreMore CLI settings in your environment.")}</Banner>
        {tokens.map(item => <div className="ig-token" key={item.id}>
          <span className="ig-sub">{item.name || capName(item.purpose, L)}</span>
          <code className="mono">{item.collector_token}</code>
          <button type="button" className="ghost-btn" onClick={() => copy(item.collector_token!)}><Ic name="copy" size={15} />{L("복사", "Copy")}</button>
        </div>)}
      </div> : null}
      {error ? <Banner tone="bad" icon="alert" onClose={() => setError(null)}>{error}</Banner> : null}
      {heldSection}
      {expiryLeft ? <div className="ig-section"><Banner tone="warn" icon="alert">{L(`만료일을 수집 ${expiryLeft}개에 저장하지 못했습니다. 연동 설정에서 다시 저장하면 나머지에만 저장합니다.`,
        `The expiry could not be saved on ${expiryLeft} collection${expiryLeft > 1 ? "s" : ""}. Saving again in the integration's settings saves it on those only.`)}</Banner></div> : null}
      {family && onNext && others.length ? <div className="ig-section ig-family">
        <div className="ig-section-head"><h3>{L(`${family.name}의 다른 서비스도 이어서 연동`, `Connect more ${family.name} services`)}</h3></div>
        <div className="pill-wrap">{others.map(item =>
          <button type="button" className="ghost-btn" key={item.provider} disabled={settling} onClick={() => onNext(item.provider)}
            data-tip={settling ? L("노출 검사 범위를 저장한 뒤에 이어서 연동할 수 있습니다.", "Continue once the exposure scan scope is saved.") : undefined}>
            <Logo id={item.provider} size={18} />{label(item, L)}</button>)}</div>
      </div> : null}
      <div className="modal-foot ig-foot-center">
        <button type="button" className="primary-btn" disabled={settling} onClick={() => { if (onComplete && conn) onComplete(conn); else onClose(); }}>{onComplete ? L("다음 설정 계속", "Continue setup") : L("연동 현황 보기", "View connected services")}</button>
      </div>
    </Modal>;
  }

  let body: ReactNode = null;
  if (step === 1) {
    body = <>{entry === "exposure" ? null : featureCards}{resumeNote}{targetSection}{typeSection}{scanSection}{optionSections}</>;
  } else if (step === 2 && method) {
    const renewal = renewalTag(method, L);
    const hint = methodHint(d.provider, method, L);
    const blockedMethod = (item: Method) => Boolean(conn && conn.children.length && item.id !== conn.auth_method);
    // A permission several features need (the Microsoft app's Application.Read.All) is listed once, under the first.
    const listed = new Set<string>();
    const perms = checkPurposes.map(p => {
      const all = permissionsFor(d, p, method.id, targetNow, planValues(p));
      return { p, shared: all.length > 0, list: all.filter(permission => !listed.has(permission.id) && Boolean(listed.add(permission.id))) };
    });
    const result = (p: Purpose, id: string) => (checkedNow ? conn!.checks.results[p]?.items.find(item => item.permission === id) : undefined);
    const approved = Boolean(conn && sameMethod && conn.credential.roles.length);
    body = <>
      <div className="ig-auth-head">
        <div className="mtabs" role="tablist" aria-label={L("인증 방식", "Sign-in method")}>
          {methods.map(item => <button type="button" role="tab" key={item.id} aria-selected={item.id === method.id} aria-disabled={blockedMethod(item) || undefined}
            data-tip={blockedMethod(item) ? L("연결된 수집이 있는 동안에는 인증 방식을 바꿀 수 없습니다.", "The sign-in method cannot change while collections use it.")
              : item.advanced ? L("고급 방식입니다. 앞의 권장 방식을 쓸 수 없을 때 고르세요.", "An advanced method. Use it when the recommended one does not fit.") : undefined}
            onClick={() => { if (blockedMethod(item)) return; setMethodId(item.id); setByRef(false); forget(); setError(null); }}>{label(item, L)}{item.new_setup === false ? L(" · 기존 연결", " · existing connection") : ""}</button>)}
        </div>
        <span className="tag" data-tip={renewal.tip}><Ic name={method.renewal === "AUTOMATIC" || method.renewal === "ROTATES" ? "refresh" : method.renewal === "EXPIRES" ? "hourglass" : "key"} size={13} />{renewal.text}</span>
      </div>
      <div className="ig-auth-pane">
        {method.flow === "gcp_oauth" ? <>
          <GoogleConsent d={d} approved={approved} perms={perms.flatMap(item => item.list.map(permission => permission.id))} busy={busy === "google"} onApprove={() => void google()} />
          {approved ? <div className="ig-test">
            <button type="button" className="ghost-btn" disabled={Boolean(busy) || polling} onClick={() => void test()}><Ic name="bolt" size={15} />{L("권한 다시 확인", "Check again")}</button>
            <TestResult polling={polling || busy === "test"} checkedNow={checkedNow} summary={summary} items={items} error={conn?.checks.error} />
          </div> : null}
        </> : method.id === "github_app" && !typeApp && !storedCredential ? <>
          <div className="ig-make">
            <span className="ig-make-logo"><Logo id="github" size={22} /></span>
            <div className="ig-cert-body">
              <b>{L("GitHub에서 App 만들기", "Make the App on GitHub")}</b>
              <span className="ig-sub">{L("조직 소유자가 GitHub에서 '만들기'와 '설치'만 누르면 됩니다. 권한은 고른 기능에 필요한 읽기만 채워져 있고, App ID·설치 ID·개인 키는 GitHub에서 CreMore 서버로 바로 옵니다.",
                "An organization owner presses Create and Install on GitHub. The permissions are filled with the reads the chosen features need, and the App ID, installation ID and private key go from GitHub straight to CreMore.")}</span>
            </div>
            <button type="button" className="primary-btn" disabled={Boolean(busy) || polling} onClick={() => void github()}>
              <Ic name="ext" size={15} />{busy === "github" ? L("GitHub로 이동 중", "Going to GitHub") : L("GitHub에서 만들기", "Make on GitHub")}</button>
          </div>
          <button type="button" className="link-btn ig-ref-toggle" onClick={() => setTypeApp(true)}>{L("직접 등록한 App의 값 입력", "Enter the values of an App you registered")}</button>
        </> : <>
          {method.id === "github_app" && typeApp && !storedCredential ? <button type="button" className="link-btn ig-ref-toggle" onClick={() => { setTypeApp(false); forget(); }}>
            {L("GitHub에서 만들기로 돌아가기", "Back to making it on GitHub")}</button> : null}
          {made ? <CertificateCard made={made} renewal={conn?.checks.renewal ?? null} busy={Boolean(busy) || polling}
            onRemake={() => void makeCertificate()} /> : null}
          {madeKey ? <KeyCard made={madeKey} busy={Boolean(busy) || polling} onRemake={() => void makeCertificate()} /> : null}
          {visible.map(field => <CredentialField key={field.name} field={field} value={secrets[field.name] ?? ""} stored={storedCredential}
            shownValue={field.public && sameMethod ? (conn?.target.auth as Record<string, string> | undefined)?.[field.name] : undefined}
            onChange={value => setSecrets(all => ({ ...all, [field.name]: value }))} />)}
          {byRef ? <TextField label={L("Vault 참조", "Vault reference")} value={reference} onChange={setReference} placeholder="vault://secret/cremore/integration"
            hint={L(`이 KV 항목에 ${method.reference_keys?.join(", ")} 키가 있어야 합니다.`, `The KV entry must hold ${method.reference_keys?.join(", ")}.`)} /> : null}
          {method.reference_keys ? <button type="button" className="link-btn ig-ref-toggle" onClick={() => { setByRef(value => !value); forget(); }}>
            {byRef ? L("값을 직접 입력", "Enter the value") : L("Vault 참조로 입력", "Use a Vault reference")}</button> : null}
          {idNeeds === "ROLE_ARN" ? <details><summary>{L("역할 ARN 직접 입력 (고급)", "Enter the role ARN manually (advanced)")}</summary>
            <TextField label={L("이 신원이 쓰는 IAM 역할 ARN(경로 포함)", "IAM role ARN this identity uses (with its path)")} value={roleArn}
              onChange={setRoleArn} placeholder="arn:aws:iam::111111111111:role/path/RoleName" /></details> : null}
          {idNeeds === "IDENTITY_CENTER_REGION" ? <SelectField label={L("IAM Identity Center 리전", "IAM Identity Center Region")} value={ssoRegion}
            onChange={setSsoRegion} options={[{ id: "", label: L("리전을 선택하세요", "Select a region") }, ...regionOptions]} /> : null}
          {hint ? <p className="ig-hint"><Ic name="info" size={15} /><span>{hint}</span></p> : null}
          {expires && reportedExpiry ? <p className="ig-hint"><Ic name="hourglass" size={15} /><span>{L(`서비스가 알려 준 만료일(${fmtDay(reportedExpiry, locale)})의 14일·3일 전에 알립니다.`,
            `You are warned 14 and 3 days before the expiry the service reports (${fmtDay(reportedExpiry, locale)}).`)}</span></p>
            : expires ? <TextField type="date" label={L("토큰 만료일 (선택)", "Token expiry (optional)")} value={enteredExpiry} onChange={setExpiry} min={today}
              hint={expiryInvalid ? L("오늘이나 그 뒤의 날짜를 넣으세요.", "Enter today or a later day.")
                : L("토큰을 만들 때 정한 날짜를 넣으면 만료 14일·3일 전에 연동 현황과 알림에서 알립니다.", "Enter the expiry you set when making the token; the integrations page and notifications warn you 14 and 3 days before it.")} /> : null}
          {expiryLeft ? <Banner tone="warn" icon="alert">{L(`만료일을 수집 ${expiryLeft}개에 저장하지 못했습니다. 다시 저장하면 나머지에만 저장합니다.`,
            `The expiry could not be saved on ${expiryLeft} collection${expiryLeft > 1 ? "s" : ""}. Saving again saves it on those only.`)}</Banner> : null}
          {idView && identityText(idView, L) ? <p className="ig-hint"><Ic name="shield" size={15} /><span>{approving
            ? L(`CreMore는 지금 ${identityText(idView, L)}(으)로 AWS에 로그인해 있습니다. 연결 확인을 누르면 이 신원을 승인하고 권한을 확인합니다.`,
              `CreMore is signed in to AWS as ${identityText(idView, L)}. Test connection approves this identity and checks access.`)
            : L(`CreMore는 승인한 AWS 신원 ${identityText(idView, L)}(으)로 계정에 접근합니다.`, `CreMore reaches the accounts as the approved AWS identity ${identityText(idView, L)}.`)}</span></p> : null}
          <SetupGuide steps={guideSteps(d, method, conn, { aws: idView, openMachine: onMachineIdentity, target: targetNow,
            plans: Object.fromEntries(checkPurposes.map(p => [p, planValues(p)])), stored: storedCredential }, L)} onCopy={copy} />
          {generating && (!(made || madeKey) || entered) ? <div className="ig-test">
            <button type="button" className="primary-btn" disabled={Boolean(busy) || polling || !madeReady} onClick={() => void makeCertificate()}
              data-tip={madeReady ? undefined : keyKind ? L("클라이언트 ID를 먼저 입력하세요.", "Enter the client ID first.")
                : L("애플리케이션(클라이언트) ID를 먼저 입력하세요.", "Enter the application (client) ID first.")}>
              <Ic name="key" size={15} />{keyKind ? (madeKey ? L("이 앱의 키 만들기", "Make a key for this app") : L("키 만들기", "Make the key"))
                : made ? L("이 앱의 인증서 만들기", "Make a certificate for this app") : L("인증서 만들기", "Make the certificate")}</button>
            <span className="ig-sub">{keyKind ? L("개인 키는 CreMore 안에서만 쓰고, 서비스 앱에는 공개 키만 붙여 넣습니다.", "The private key stays inside CreMore; only the public key goes to the service app.")
              : L("개인 키는 CreMore 안에서만 쓰고, 앱 등록에는 공개 인증서만 올립니다.", "The private key stays inside CreMore; only the public certificate goes to the app registration.")}</span>
          </div> : <div className="ig-test">
            <button type="button" className="ghost-btn" disabled={Boolean(busy) || polling || !credentialReady || idBlocked || expiryInvalid} onClick={() => void test()}
              data-tip={awsIdentity && !idView ? L("CreMore의 AWS 로그인을 확인하고 있습니다.", "Checking CreMore's AWS sign-in.")
                : approving && !admin ? L("관리자가 연결을 확인하면서 신원을 승인합니다.", "An administrator approves the identity while testing.") : undefined}>
              <Ic name="bolt" size={15} />{conn?.checks.checked_at && !entered && sameMethod && !approving ? L("권한 다시 확인", "Check again") : L("연결 확인", "Test connection")}</button>
            {idIssue ? <span className="ig-result bad" role="status"><Ic name="alert" size={16} />{idIssue.text}</span>
              : <TestResult polling={polling || busy === "test"} checkedNow={checkedNow} summary={summary} items={items} error={conn?.checks.error} />}
          </div>}
          {idIssue?.fix ? <p className="ig-hint"><Ic name="info" size={15} /><span>{idIssue.fix}</span></p> : null}
          {idIssue?.signIn && admin ? <AwsSignIn onDone={() => identity.reload()} /> : null}
          {idIssue?.code ? <pre className="re-preview ig-code">{idIssue.code}</pre> : null}
        </>}
      </div>
      {conn && checkedNow && sharedNote(conn, L) ? <Banner tone="warn" icon="alert">{sharedNote(conn, L)}</Banner> : null}
      {someReady && heldNow.length ? <Banner icon="info">{L(`권한이 확인된 기능만 켭니다. 보류: ${heldNow.map(p => featureName(p, L)).join(" · ")}`,
        `Only the features whose permissions were confirmed are turned on. Held: ${heldNow.map(p => featureName(p, L)).join(" · ")}`)}</Banner> : null}
      <div className="ig-section">
        <div className="ig-section-head"><h3>{L("필요한 권한", "Permissions needed")}</h3>
          <InfoTip text={L("1단계에서 고른 기능에 필요한 권한만 모았습니다.", "Only what the features chosen in step 1 need.")} /></div>
        {perms.map(({ p, list, shared }) => <div className="ig-perm-group" key={p}>
          {perms.length > 1 ? <span className="ig-sub">{featureName(p, L)}</span> : null}
          <div className="ig-perms">{list.length ? list.map(permission => {
            const found = result(p, permission.id);
            const tone = !found ? "" : found.status === "GRANTED" ? "ok" : found.status === "NOT_REPORTED" ? "none" : "bad";
            const tip = [permission.id, found ? checkWord(found.status, L) : "", found?.detail ? detailText(found.detail, L) : "", found?.subject ?? ""].filter(Boolean).join(" · ");
            return <span key={permission.id} className={cls("tag", tone && `perm-${tone}`)} data-tip={tip}>
              {found ? <Ic name={found.status === "GRANTED" ? "checkCircle" : found.status === "NOT_REPORTED" ? "minusCircle" : "xCircle"} size={13} /> : null}
              {label(permission, L)}</span>;
          }) : <span className="subtle">{shared ? L("위 기능과 같은 권한을 씁니다.", "Uses the same permissions as above.")
            : L("따로 필요한 권한이 없습니다.", "No extra permission is needed.")}</span>}</div>
        </div>)}
      </div>
    </>;
  } else if (step === 3) {
    const reads = own.some(p => planValues(p).read_values === true);
    body = <>
      <dl className="kv">
        <dt>{L("연동 서비스", "Service")}</dt>
        <dd className="ig-kv-svc"><Logo id={d.provider} size={20} />{serviceName}{editionName ? ` · ${editionName}` : ""}{conn ? ` · ${targetSummary(d, conn)}` : ""}</dd>
        <dt><label htmlFor="ig-name">{L("이름", "Name")}</label></dt>
        <dd><input id="ig-name" className="ig-select ig-name" value={name} maxLength={120} onChange={event => setName(event.target.value)} /></dd>
        {own.map(p => {
          const fields = planOf(p).filter(field => field.name !== "schedule_minutes" && !(p === "inventory" && shownByTypes.has(field.name))
            && !idleReaderField(d.provider, p, field.name, planValues(p)));
          const chips = planChips(fields, payload(planOf(p), planValues(p)), L);
          const kinds = p === "inventory" ? choices.filter(choice => choice.on).map(choice => label(choice.type, L)) : p === "exposure" ? scans.map(item => label(item, L)) : [];
          return <Fragment key={p}><dt>{p === "exposure" ? L("노출 검사 위치", "Scan locations") : featureName(p, L)}</dt><dd>
            <div className="pill-wrap">{active.has(p) ? <span className="tag">{replans.includes(p) ? L("수집 중 · 변경", "Collecting · changed") : L("수집 중", "Collecting")}</span> : null}
              {kinds.map(text => <span className="tag" key={`k-${text}`}>{text}</span>)}
              {chips.map(text => <span className="tag" key={text}>{text}</span>)}
              {!chips.length && !kinds.length && !active.has(p) ? <span className="subtle">{L("기본 설정", "Defaults")}</span> : null}</div>
            {p === "exposure" ? <div className="ig-sub">{scopeMode === "keep" ? (scopeNow ? L(`지금 범위 유지 · ${scopeNow.unit} ${scopeNow.count}개`, `Current scope kept · ${scopeNow.count} ${scopeNow.unit}`) : L("지금 범위 유지", "Current scope kept"))
              : scopeMode === "all" ? everythingOf(scopeSource, L) : L(`지정한 곳만: ${scopePatterns.join(", ")}`, `Only: ${scopePatterns.join(", ")}`)}</div> : null}
          </dd></Fragment>;
        })}
        <dt>{L("인증 방식", "Sign-in method")}</dt><dd>{method ? label(method, L) : "—"}{conn?.credential.reference ? ` · ${L("Vault 참조", "Vault reference")}` : ""}</dd>
        <dt>{L("권한 확인", "Access check")}</dt><dd><CheckLine summary={summary} items={items} checkedNow={checkedNow} error={conn?.checks.error} /></dd>
        {own.includes("exposure") && scopeMode !== "keep" ? <>
          <dt><label htmlFor="ig-full-sched">{L("전체 범위 검사 주기", "Full scope scan schedule")}</label></dt>
          <dd><select id="ig-full-sched" className="ig-select" value={String(fullSchedule ?? (edit ? -1 : INSTALLATION_DEFAULT))}
            onChange={event => setFullSchedule(Number(event.target.value))}>
            {[...(edit ? [-1] : []), INSTALLATION_DEFAULT, ...FULL_SCHEDULES].map(minutes => <option key={minutes} value={minutes}>
              {minutes === -1 ? L("기존 주기 유지", "Keep existing schedule") : minutes === INSTALLATION_DEFAULT ? L("설치 기본값", "Installation default")
                : fullScanText(minutes, L)}</option>)}
          </select></dd>
          {d.provider !== "website" ? <><dt>{L("변경되면 검사", "Scan when it changes")}</dt>
            <dd><label className="set-check"><input type="checkbox" checked={changeScans} onChange={event => setChangeScans(event.target.checked)} />
              <span>{edit ? L("새로 추가한 대상에 적용합니다: 변경 감지·큐 알림·웹훅이 알린 바뀐 곳만 검사합니다. 기존 대상은 검사 대상 설정의 값을 그대로 씁니다.",
                "Applies to targets added now: only what a change feed, a queue notification or a webhook reports as changed is scanned. Existing targets keep the setting in Scan targets.")
                : L("변경 감지·큐 알림·웹훅이 알린 바뀐 곳만 검사합니다", "Only what a change feed, a queue notification or a webhook reports as changed is scanned")}</span></label></dd></> : null}
        </> : null}
        {hasSchedule || own.includes("exposure") ? <><dt><label htmlFor="ig-sched">{own.includes("exposure") ? L("수집·변경분 검사 주기", "Collection / incremental schedule") : L("수집 주기", "Schedule")}</label></dt>
          <dd><select id="ig-sched" className="ig-select" value={String(scheduleNow)} onChange={event => setSchedule(Number(event.target.value))}>
            {[...SCHEDULES.map(item => item.minutes), ...(SCHEDULES.some(item => item.minutes === scheduleNow) ? [] : [scheduleNow])].map(minutes =>
              <option key={minutes} value={minutes}>{scheduleLabel(minutes, L)}</option>)}
          </select></dd></> : null}
      </dl>
      {heldSection}
      <div className="safety">
        <div className="ok"><Ic name="checkCircle" size={16} /><span>{L("값 원문은 저장하지 않고 지문(HMAC)만 남깁니다", "Raw values are never stored; only HMAC fingerprints are kept")}</span></div>
        {reads ? <div className="ok"><Ic name="checkCircle" size={16} /><span>{L("값은 메모리에서 지문화해 노출 발견값과 대조하고 변경을 확인합니다", "Values are fingerprinted in memory to compare with exposures and track changes")}</span></div> : null}
        <div className="ok"><Ic name="checkCircle" size={16} /><span>{L("읽기만 합니다. 폐기·수정은 하지 않습니다", "Read only. Nothing is revoked or changed")}</span></div>
      </div>
    </>;
  }

  // AWS's parts of the common steps (the installation's AWS settings): what to collect ends with the issuance
  // inventory's schedule and the investigations of discovered credentials; the sign-in ends with how the other
  // accounts come in for the chosen method and the identity key actions run as. They stay mounted, hidden, across
  // steps and methods, so an edit not saved yet is still there on coming back. They belong to the account card, not
  // to the Amazon S3 one.
  const aws = awsParts(d.provider, admin, method?.id, purposes);
  const awsTail = d.provider === "aws" && admin && entry !== "exposure" ? <>
    <div hidden={step !== 1}>
      <div className="ig-section" hidden={!aws.inventory}>
        <div className="ig-section-head"><h3>{L(`${featureName("inventory", L)} · 자동 수집`, `${featureName("inventory", L)} · Automatic collection`)}</h3></div>
        <AwsInventory regionOptions={regionOptions} />
      </div>
      <div className="ig-section" hidden={!aws.investigations}>
        <div className="ig-section-head"><h3>{L("발견한 Credential 조사 기능", "Investigations of discovered credentials")}</h3></div>
        <AwsInvestigations keys={investigationKeys(purposes)} />
      </div>
    </div>
    <div hidden={step !== 2}>
      <div className="ig-section" hidden={!aws.organization}>
        <div className="ig-section-head"><h3>{L("AWS Organizations 계정을 한 번에 연결 (선택)", "Connect AWS Organizations accounts at once (optional)")}</h3></div>
        <p className="ig-sub">{L("같은 읽기 역할을 StackSet 하나로 조직 전체에 배포하고, 조직의 새 계정을 자동으로 등록합니다. 1단계의 '자동 발견으로 등록되는 계정도 포함'을 켠 멤버 역할 연동에 들어옵니다.",
          "Deploy the same read role across the organization with one StackSet and register the organization's new accounts automatically. They join the member-role integrations with 'Take in accounts that discovery registers' on (step 1).")}</p>
        <AwsOrganizations regionOptions={regionOptions} />
      </div>
      <div className="ig-section" hidden={!aws.assigned}>
        <div className="ig-section-head"><h3>{L("할당된 계정", "Assigned accounts")}</h3></div>
        <p className="ig-sub">{L("기본 권한 세트가 할당된 계정을 읽어 등록합니다. 1단계의 '자동 발견으로 등록되는 계정도 포함'을 켠 연동 가운데 권한 세트를 비워 두었거나 같은 권한 세트를 쓰는 연동에 들어옵니다.",
          "Registers the accounts the default permission set is assigned in. They join the integrations with 'Take in accounts that discovery registers' on (step 1) whose permission set is empty or the same.")}</p>
        <AwsIdentityCenter />
      </div>
      <div className="ig-section" hidden={!aws.keyActions}>
        <div className="ig-section-head"><h3>{L("키 조치에 쓰는 신원 (선택)", "The identity key actions run as (optional)")}</h3></div>
        <AwsKeyActionIdentity regionOptions={regionOptions} />
      </div>
    </div>
  </> : null;

  const stepNames = [entry === "exposure" ? L("검사 범위", "Scan scope") : L("수집 범위", "What to collect"), L("인증", "Sign in"), L("확인", "Review")];
  const typesMissing = own.includes("inventory") && choices.length > 0 && !choices.some(choice => choice.on);
  const canNext = step === 1 ? step1Ready && !scopeMissing && !typesMissing
    : step === 2 ? Boolean(conn) && !polling && !busy && !entered && !expiryInvalid && !purposesChanged
      && (someReady || (!toStart.length && !replans.length && conn!.status === "ACTIVE")) : true;
  // A connection reopened at review (CHECKED) whose current check refused everything it would start or change: Finish
  // would save nothing, so it waits for a check that passes (the held list's recheck, or the sign-in step).
  const noneReady = checkedNow && toStart.length + replans.length > 0 && heldNow.length === toStart.length + replans.length;
  const noneReadyTip = L("필요한 권한이 확인된 기능이 없습니다. 권한을 준 뒤 다시 확인하세요.", "No feature has the permissions it needs. Grant them and check again.");
  const nextTip = step === 2 && !canNext
    ? entered ? L("연결 확인을 눌러 새 값을 저장하세요.", "Press Test connection to save the new value.")
      : checkedNow ? noneReadyTip
        : L("연결 확인을 마치면 다음으로 갈 수 있습니다.", "Finish the connection test to continue.")
    : step === 1 && !canNext && planMissing ? L(`${label(planMissing, L)}을(를) 입력하세요.`, `Enter ${label(planMissing, L)}.`)
      : step === 1 && scopeMissing ? L("검사할 곳의 이름이나 경로를 입력하세요.", "Enter the names or paths to scan.")
        : step === 1 && typesMissing ? L("가져올 Credential 유형을 하나 이상 고르세요.", "Choose at least one credential type to collect.") : undefined;

  return <Modal onClose={onClose} labelledBy="ig-title" className="integ" dismissable={!busy}>
    {head}
    {setupProgress ? <Banner icon="info">{setupProgress}</Banner> : null}
    {setupGroup && !method?.auth_first ? <Banner icon="info">{L("이 인증 방식은 대상 자동 조회를 제공하지 않아 연결할 대상 정보를 직접 확인해야 합니다. 같은 설정 창에서 인증·권한 검사와 범위 설정을 이어갑니다.", "This sign-in method does not expose automatic target discovery. Confirm its target details here, then continue sign-in, access checks, and scope setup in this window.")}</Banner> : null}
    <ol className="ig-steps">
      {stepNames.map((text, index) => {
        const n = index + 1;
        return <li key={text} aria-current={n === step ? "step" : undefined} className={n < step ? "done" : undefined}>
          <span className="n">{n < step ? <Tick /> : n}</span>{text}</li>;
      })}
    </ol>
    {error ? <Banner tone="bad" icon="alert" onClose={() => setError(null)}>{error}</Banner> : null}
    {loadError ? <Banner tone="bad" icon="alert">{loadError}</Banner> : null}
    {body}
    {awsTail}
    <div className="modal-foot">
      {step === 2 && fieldsOf.length ? <span className="note">{method?.generated ? L("CreMore가 만든 개인 키는 암호화해 저장하고 밖으로 내보내지 않습니다.", "The private key CreMore makes is stored encrypted and never leaves it.")
        : L("입력한 값은 암호화해 저장하고 화면에 다시 보여 주지 않습니다.", "What you enter is stored encrypted and never shown again.")}</span> : null}
      {step > 1 ? <button type="button" className="ghost-btn" disabled={Boolean(busy)} onClick={() => { setError(null); setStep(value => (value - 1) as Step); }}>{L("이전", "Back")}</button>
        : <button type="button" className="ghost-btn" onClick={onClose}>{L("취소", "Cancel")}</button>}
      {step < 3 ? <button type="button" className="primary-btn" id="ig-next" disabled={!canNext} data-tip={nextTip}
        onClick={() => { setError(null); setStep(value => (value + 1) as Step); }}>{L("다음", "Next")}</button>
        : <button type="button" className="primary-btn" disabled={Boolean(busy) || !conn || polling || noneReady} data-tip={noneReady ? noneReadyTip : undefined}
          onClick={() => void finish()}>
          {busy === "finish" ? L("저장 중", "Saving") : startNow.includes("remediation") ? L("연동하고 켜기", "Connect and turn on")
            : startNow.length ? L("연동하고 수집 시작", "Connect and start") : L("변경 저장", "Save changes")}</button>}
    </div>
  </Modal>;
}

/* ---------- exposure scope ---------- */

function ScopeLine({ name, progress, onRetry }: { name: string; progress: ScopeProgress; onRetry: () => void }) {
  const L = useL();
  const unit = progress.unit ?? "";
  const who = name ? `${name} · ` : "";
  if (progress.step === "started") return <div className="ig-result ok"><Ic name="checkCircle" size={16} />
    <span>{who}{L(`${unit} ${progress.count}개를 검사 범위로 저장하고 첫 검사를 시작했습니다`, `Saved ${progress.count} ${unit} as the scan scope and started the first scan`)}</span></div>;
  if (progress.step === "saved") return <div className="ig-result ok"><Ic name="checkCircle" size={16} />
    <span>{who}{L(`${unit} ${progress.count}개를 검사 범위로 저장했습니다. 지금은 실행할 수 없는 범위입니다. 수집·탐지 현황에서 이유를 확인하세요.`, `Saved ${progress.count} ${unit} as the scan scope. It cannot run right now; see why under Collection & detection status.`)}</span></div>;
  if (progress.step === "empty") return <div className="ig-result bad"><Ic name="alert" size={16} />
    <span>{who}{L(`검사할 ${josa(unit, "을/를")} 찾지 못했습니다. 연동 설정에서 범위를 다시 정하세요.`, `No ${unit} to scan were found. Set the scope again in the integration settings.`)}</span></div>;
  if (progress.step === "failed") return <div className="ig-result bad"><Ic name="alert" size={16} />
    <span>{who}{L("검사 범위를 저장하지 못했습니다", "The scan scope could not be saved")}{progress.code ? ` · ${detailText(progress.code, L)}` : ""}
      {" "}<button type="button" className="link-btn" onClick={onRetry}>{L("다시 시도", "Try again")}</button></span></div>;
  const text = progress.step === "listing" ? L(`${unit} 목록을 가져오는 중입니다`, `Reading the list of ${unit}`)
    : progress.step === "selecting" ? L("검사할 곳을 고르는 중입니다", "Choosing what to scan")
      : L(`${unit} ${progress.count}개를 검사 범위로 저장하는 중입니다`, `Saving ${progress.count} ${unit} as the scan scope`);
  return <div className="ig-result none"><span className="spinner" aria-hidden="true" /><span>{who}{text}</span></div>;
}

/* ---------- a certificate CreMore made ---------- */

function CertificateCard({ made, renewal, busy, onRemake }: { made: Generated; renewal: Renewed | null; busy: boolean; onRemake: () => void }) {
  const L = useL();
  const locale = useLocale();
  const failed = renewal?.state === "FAILED" && renewal.action !== "retire";
  return <div className={cls("ig-cert", failed && "bad")}>
    <span className="ig-cert-ic"><Ic name="shield" size={18} /></span>
    <div className="ig-cert-body">
      <b>{L("CreMore가 만든 인증서", "Certificate CreMore made")}</b>
      <span className="ig-sub">{L("지문(SHA-1)", "Thumbprint (SHA-1)")} <span className="mono">{made.thumbprint}</span></span>
      <span className="ig-sub">{L(`${fmtDay(made.not_after, locale)}까지 · 만료 전에 CreMore가 새 인증서로 바꿉니다`,
        `Valid until ${fmtDay(made.not_after, locale)} · CreMore replaces it before it expires`)}</span>
      {failed ? <span className="ig-cert-note"><Ic name="alert" size={14} />{L("자동 교체 실패", "Renewal failed")} · {renewalText(renewal?.code, L)}</span>
        : renewal?.renewed_at ? <span className="ig-sub">{L(`마지막 교체 ${fmtDT(renewal.renewed_at, locale)}`, `Last renewed ${fmtDT(renewal.renewed_at, locale)}`)}</span> : null}
    </div>
    <button type="button" className="link-btn" disabled={busy} onClick={onRemake}
      data-tip={L("인증서가 만료됐거나 새어 나갔거나 앱 등록에서 지워졌을 때 씁니다. 새 인증서를 올릴 때까지 수집이 멈추고, 이전 인증서는 앱 등록에서 지워야 효력이 없어집니다.",
        "For a certificate that expired, leaked or was removed from the app registration. Collection stops until the new one is uploaded, and the earlier one stops working only once it is deleted from the app registration.")}>
      {L("새 인증서 만들기", "Make a new certificate")}</button>
  </div>;
}

/* ---------- IAM Identity Center sign-in from the dashboard ---------- */

/** What `aws sso login --use-device-code` does, from here: the admin approves a code in the AWS access portal and
 * the sign-in is saved where the command saves it, for the API and the worker alike. */
function AwsSignIn({ onDone }: { onDone: () => void }) {
  const L = useL();
  const [started, setStarted] = useState<SsoLoginStart | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);
  const live = useRef(true);
  useEffect(() => { live.current = true; return () => { live.current = false; }; }, []);

  async function begin() {
    setBusy(true); setProblem(null); setDone(false);
    try {
      const start = await send<SsoLoginStart>(`${SSO_LOGIN_PATH}/start`, "POST");
      setStarted(start);
      const until = Date.parse(start.expires_at);
      while (live.current && Date.now() < until + 5000) {
        await new Promise(resolve => window.setTimeout(resolve, start.interval * 1000));
        if (!live.current) return;
        const answer = await send<SsoLoginState>(`${SSO_LOGIN_PATH}/poll`, "POST", { session_id: start.session_id });
        if (answer.state === "PENDING") continue;
        setStarted(null);
        if (answer.state === "DONE") { setDone(true); onDone(); } else setProblem(signInText(answer.code ?? answer.state, L));
        return;
      }
      setStarted(null); setProblem(signInText("EXPIRED", L));
    } catch (reason) {
      setStarted(null);
      setProblem(signInText(reason instanceof Error ? reason.message : "", L));
    } finally { if (live.current) setBusy(false); }
  }

  if (done) return <p className="ig-hint"><Ic name="checkCircle" size={15} /><span>{L("AWS에 로그인했습니다. CreMore가 이 로그인으로 확인합니다.", "Signed in to AWS. CreMore checks with this sign-in.")}</span></p>;
  return <div className="ig-make">
    <span className="ig-make-logo"><Logo id="aws" size={22} /></span>
    <div className="ig-cert-body">
      <b>{started ? L(`AWS 접근 포털에서 코드 ${started.user_code}를 승인하세요`, `Approve code ${started.user_code} in the AWS access portal`)
        : L("IAM Identity Center에 로그인", "Sign in to IAM Identity Center")}</b>
      <span className="ig-sub">{started ? L("승인하면 여기서 바로 이어집니다. 로그인은 명령으로 할 때와 같은 곳에 저장됩니다.", "Once approved it continues here. The sign-in is saved where the command saves it.")
        : problem ?? L("터미널 없이 여기서 로그인합니다. AWS 접근 포털에서 코드를 승인하면 됩니다.", "Sign in here without a terminal: approve a code in the AWS access portal.")}</span>
    </div>
    {started ? <a className="primary-btn" href={started.verification_uri_complete} target="_blank" rel="noopener noreferrer">
      <Ic name="ext" size={15} />{L("AWS에서 승인", "Approve in AWS")}</a>
      : <button type="button" className="primary-btn" disabled={busy} onClick={() => void begin()}><Ic name="key" size={15} />{L("AWS에서 로그인", "Sign in with AWS")}</button>}
  </div>;
}

/* ---------- a signing key CreMore made ---------- */

function KeyCard({ made, busy, onRemake }: { made: MadeKey; busy: boolean; onRemake: () => void }) {
  const L = useL();
  const locale = useLocale();
  return <div className="ig-cert">
    <span className="ig-cert-ic"><Ic name="key" size={18} /></span>
    <div className="ig-cert-body">
      <b>{L("CreMore가 만든 키", "Key CreMore made")}</b>
      <span className="ig-sub">kid <span className="mono">{made.kid}</span></span>
      <span className="ig-sub">{L(`${fmtDay(made.created_at, locale)}에 만듦 · 만료 없음 · 액세스 토큰은 읽을 때마다 받습니다`,
        `Made ${fmtDay(made.created_at, locale)} · no expiry · an access token is taken for each read`)}</span>
    </div>
    <button type="button" className="link-btn" disabled={busy} onClick={onRemake}
      data-tip={L("키가 새어 나갔거나 앱에서 지워졌을 때 씁니다. 새 공개 키를 붙여 넣을 때까지 수집이 멈추고, 이전 키는 Okta에서 비활성화·삭제해야 효력이 없어집니다.",
        "For a key that leaked or was removed from the app. Collection stops until the new public key is pasted, and the earlier key stops working only once it is deactivated and deleted in Okta.")}>
      {L("새 키 만들기", "Make a new key")}</button>
  </div>;
}

/* ---------- check results ---------- */

type Summary = ReturnType<typeof checkSummary>;
type Items = ReturnType<typeof checkItems>;

function TestResult({ polling, checkedNow, summary, items, error }: { polling: boolean; checkedNow: boolean; summary: Summary; items: Items; error?: string | null }) {
  const L = useL();
  if (polling) return <span className="ig-result none" role="status"><span className="spinner" aria-hidden="true" />{L("권한을 확인하고 있습니다", "Checking access")}</span>;
  if (!checkedNow) return null;
  return <span role="status"><CheckLine summary={summary} items={items} checkedNow error={error} /></span>;
}

function CheckLine({ summary, items, checkedNow, error }: { summary: Summary; items: Items; checkedNow: boolean; error?: string | null }) {
  const L = useL();
  if (!checkedNow) return <span className="subtle">{L("아직 확인하지 않았습니다", "Not checked yet")}</span>;
  const missing = items.filter(item => item.status === "MISSING").length;
  const failed = items.find(item => item.status === "ERROR");
  const why = failed?.detail ?? error ?? "";
  if (summary === "ok") return <span className="ig-result ok"><Ic name="checkCircle" size={16} />{L("필요한 권한을 모두 확인했습니다", "Every permission needed is granted")}</span>;
  if (summary === "missing") return <span className="ig-result bad"><Ic name="alert" size={16} />{L(`권한 ${missing}개가 없습니다. 권한을 준 뒤 다시 확인하세요`, `${missing} permission${missing > 1 ? "s are" : " is"} missing. Grant ${missing > 1 ? "them" : "it"} and check again`)}</span>;
  if (summary === "error") return <span className="ig-result bad"><Ic name="alert" size={16} />{L("권한을 확인하지 못했습니다", "The access check failed")}{why ? ` · ${detailText(why, L)}` : ""}</span>;
  if (summary === "unreported") return <span className="ig-result none"><Ic name="info" size={16} />{L("필수 권한 중 확인하지 못한 항목이 있습니다", "Some required access could not be verified")}</span>;
  return <span className="subtle">{L("확인할 권한이 없습니다", "Nothing to check")}</span>;
}

/* ---------- provider panes ---------- */
