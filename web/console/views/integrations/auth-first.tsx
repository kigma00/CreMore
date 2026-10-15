"use client";

import { useEffect, useRef, useState } from "react";
import { useDisplayTimezone } from "@/components/display-timezone";
import { useLocale } from "@/components/locale";
import { completeDraftSignIn, pending, startSignIn } from "@/console/gcp-oauth";
import { reasonText as apiReasonText, send, useApi, useSaved } from "@/console/data";
import { Ic } from "@/console/icons";
import { Modal, useToast } from "@/console/layer";
import { Logo } from "@/console/logos";
import { josa, type Say, useL } from "@/console/text";
import { Banner, Check, cls, MultiSelectField, SelectField, TextField } from "@/console/ui";
import { featureName, featureText, methodHint } from "@/console/views/integrations/copy";
import { CredentialField, FieldGrid } from "@/console/views/integrations/fields";
import { defaultRoot, defaultText, FULL_SCHEDULES, fullScanText, INSTALLATION_DEFAULT, pickable, rootProblem } from "@/console/views/integrations/targets-model";
import { guideSteps, SetupGuide } from "@/console/views/integrations/guide";
import { startGitHubApp } from "@/console/views/integrations/github-app";
import { type GoogleClient, GoogleClientSetup } from "@/console/views/integrations/google-client";
import { setupGroups, type SetupGroup } from "@/console/views/integrations/setup";
import { featureOutcomes, type Blocker, type Missing } from "@/console/views/integrations/outcomes";
import { MissingList, PermissionPreview, type PreviewTarget } from "@/console/views/integrations/permissions-preview";
import { approval, type AwsIdentityView, IDENTITY_PATH, identityIssue, identityText, needsApproval, refusalText } from "@/console/views/integrations/aws-identity";
import { MachineIdentityModal } from "@/console/views/integrations/machine";
import { collectConnection, CollectionProgress, type CollectionRequest } from "@/console/views/integrations/collect";
import { AwsInvestigationFields, investigationKeys, investigationRequest, type InvestigationEdits, type Investigations } from "@/console/views/integrations/aws-settings";
import type { ScopeResource, ScopeSelection } from "@/lib/scan-scope";
import {
  type Descriptor, type Purpose, type Values, type CheckItem, type CollectionEntry, type PurposeCheck, type ProviderConnection,
  defaults, detailText, idleReaderField, isScheduleField, label, methodsFor, missingRequired, onboardingText, payload, permissionsFor, planFields, PURPOSE_ORDER, purposesForEdition, serves, targetSummary, valuesOf,
} from "@/console/views/integrations/model";

type Draft = {
  id: string; revision: number; expires_at: string; state: string; error?: string;
  authentication?: CheckItem; roots?: { id: string; label: string; target: Record<string, unknown>; purposes?: Purpose[]; plan_options?: Record<string, string[]> }[];
  completeness?: "COMPLETE" | "PARTIAL"; snapshot_id?: string; has_more?: boolean;
  discovery_notice?: string;
  resources?: (ScopeResource & { source_key: string })[];
  generated?: Record<string, unknown>; blockers?: Blocker[];
  public_auth?: Record<string, string>;
  checks?: { results?: Partial<Record<Purpose, PurposeCheck>> };
  purposes?: Purpose[];
  /** Features left out when the check passed for the others only (sessions.inspect narrowing). */
  held_purposes?: Purpose[];
  edition?: string; auth_method?: string; context?: Record<string, unknown>; editing?: string; name?: string;
  previous_target_ids?: string[]; previous_plans?: Partial<Record<Purpose, Record<string, unknown>>>;
  /** Targets the edited integration collects from that this listing lacks; inspect refuses until they are listed. */
  previous_unlisted?: number;
  feature_enabled?: Partial<Record<Purpose, boolean>>;
  selected_targets?: string[]; selected_resources?: string[];
  selected_roots?: ScopeSelection[];
  plans?: Partial<Record<Purpose, Record<string, unknown>>>;
};

const BASE = "onboarding-sessions";

function selectedPlanFields(d: Descriptor, purpose: Purpose, edition: string, roots: NonNullable<Draft["roots"]>) {
  const targets = roots.length ? roots.map(root => root.target) : [{}];
  const offered = new Map(targets.flatMap(target => planFields(d, purpose, edition, target)).map(field => [field.name, field]));
  return [...offered.values()].map(field => {
    const choices = roots.map(root => root.plan_options?.[field.name]).filter((value): value is string[] => value !== undefined);
    return choices.length ? { ...field, options: [...new Set(choices.flat())].map(id => ({ id, label: id, label_ko: id })) } : field;
  });
}

function reasonText(reason: unknown, L: Say) {
  return onboardingText(reason instanceof Error ? reason.message : "", [], L) ?? apiReasonText(reason, L);
}

export function rememberedDraft(key: string): { id: string; key: string; schedules?: Record<string, number>; startNow?: boolean; changeScans?: boolean; reviewName?: string; investigations?: InvestigationEdits } | null {
  try {
    const value = JSON.parse(sessionStorage.getItem(key) ?? "null");
    return value && typeof value.id === "string" && /^[A-Za-z0-9_-]{43,128}$/.test(value.key) ? value : null;
  } catch { return null; }
}

function forgetDraft(key: string) {
  try { sessionStorage.removeItem(key); } catch { /* Storage may be disabled. */ }
}

/** A reduction needs no live provider access; history stays with the same owner. */
export function ReduceTargets({ connection, descriptor, disabled, onSaved }: {
  connection: ProviderConnection; descriptor: Descriptor; disabled: boolean; onSaved: (next: ProviderConnection) => void;
}) {
  const L = useL();
  const roots = connection.target.roots as { id: string; target: Record<string, unknown> }[];
  const [ids, setIds] = useState(() => roots.map(r => r.id));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return <div className="ig-section">
    <MultiSelectField label={L("유지할 기존 대상", "Existing targets to keep")} disabled={disabled || busy} value={ids}
      options={roots.map(r => ({ id: r.id, label: targetSummary(descriptor, { ...connection, target: r.target }) }))} onChange={setIds}
      hint={L("권한이 없어도 대상을 제외할 수 있습니다. 전체 중지는 연동 끄기를 사용하세요.", "Targets can be removed without provider access. Turn off the integration to stop all targets.")} />
    {error ? <Banner tone="bad" icon="alert">{error}</Banner> : null}
    <button type="button" className="ghost-btn" disabled={disabled || busy || !ids.length || ids.length === roots.length}
      onClick={() => { setBusy(true); setError(null); void send<ProviderConnection>(`provider-connections/${connection.id}/targets`, "PUT", {
        expected_revision: connection.revision, target_ids: ids }).then(onSaved).catch(reason => setError(reasonText(reason, L))).finally(() => setBusy(false)); }}>
      {L("선택에서 빠진 대상의 수집 중지", "Stop collecting removed targets")}</button>
  </div>;
}

export function AuthFirstWizard({ descriptor: d, admin, schedulesAllowed = true, resumeOauth, existing, initialTarget, initialPurposes, initialMethod, initialEdition, supplemental, authenticationOnly: accountOnly = false, entry, progress, onIntent, onSelection, onDeferred, onComplete, onClose, onAdvanced }: {
  descriptor: Descriptor; admin: boolean; resumeOauth?: string; existing?: ProviderConnection; initialTarget?: Record<string, unknown>; onClose: () => void; onAdvanced: (method: string, edition: string) => void;
  authenticationOnly?: boolean;
  /** The card it was opened from: a content-scan card ("exposure") never asks which features to use. */
  entry?: CollectionEntry;
  initialPurposes?: Purpose[]; initialMethod?: string; initialEdition?: string; supplemental?: boolean; progress?: string;
  onIntent?: (edition: string, requested: Purpose[]) => void;
  onSelection?: (edition: string, requested: Purpose[], current: SetupGroup, pending: SetupGroup[]) => void;
  onDeferred?: (edition: string, requested: Purpose[], groups: SetupGroup[]) => void;
  onComplete?: (connection: ProviderConnection) => void;
  schedulesAllowed?: boolean;
}) {
  const L = useL();
  const locale = useLocale();
  const zone = useDisplayTimezone();
  const saved = useSaved();
  const toast = useToast();
  const storageKey = `cremore:onboarding:${d.provider}:${existing?.id ?? "new"}`;
  const [remembered] = useState(() => rememberedDraft(storageKey));
  const editions = d.editions.filter(e => (e.new_setup !== false || existing?.edition === e.id) && methodsFor(d, [], e.id, existing?.auth_method).length);
  const [edition, setEdition] = useState(initialEdition ?? existing?.edition ?? editions[0].id);
  const methods = methodsFor(d, supplemental ? initialPurposes ?? [] : [], edition, existing?.auth_method);
  const [methodId, setMethod] = useState(initialMethod ?? (resumeOauth ? "google_oauth"
    : methodsFor(d, initialPurposes ?? [], edition).find(m => m.auth_first)?.id ?? methods.find(m => m.auth_first)?.id ?? methods[0].id));
  const method = methods.find(m => m.id === methodId) ?? methods[0];
  const authenticationOnly = accountOnly || method.authentication_only === true;
  // Opened from a content-scan card: the scan is the only feature chosen here, so no feature step is shown.
  const contentOnly = entry === "exposure" && !authenticationOnly;
  const awsIdentity = d.provider === "aws" && method.id !== "customer_cli";
  const identity = useApi<AwsIdentityView>(awsIdentity ? IDENTITY_PATH : null, { every: 0 });
  const [roleArn, setRoleArn] = useState("");
  const [ssoRegion, setSsoRegion] = useState("");
  const [machineOpen, setMachineOpen] = useState(false);
  const idView = awsIdentity ? identity.data : undefined;
  const approving = Boolean(idView && needsApproval(idView));
  const idNeeds = idView && approving ? approval(idView, admin).needs : null;
  const idIssue = idView ? identityIssue(idView, L, approving) : null;
  const idInputMissing = (idNeeds === "ROLE_ARN" && !roleArn.trim()) || (idNeeds === "IDENTITY_CENTER_REGION" && !ssoRegion.trim());
  const idBlocked = awsIdentity && (!idView || Boolean(identity.error) || Boolean(idIssue) || idInputMissing || (approving && !admin));
  const shownIdentity = approving ? idView?.api : idView?.approved;
  const [context, setContext] = useState<Values>(() => valuesOf(d.target ?? [], initialTarget ?? {}));
  const [credential, setCredential] = useState<Record<string, string>>({});
  const [draft, setDraft] = useState<Draft | null>(null);
  const [step, setStep] = useState(1);
  const investigations = useApi<Investigations>(awsIdentity && admin && step === 5 ? "settings/aws-investigations" : null, { every: 0 });
  const [investigationEdits, setInvestigationEdits] = useState<InvestigationEdits>(remembered?.investigations ?? {});
  const triggers = useApi<{ schedules: { enabled: boolean; full_scan_default_minutes?: number; full_scan_start_minute?: number } }>(
    step === 5 ? "settings/scan-triggers" : null, { every: 0 });
  const [purposes, setPurposes] = useState<Purpose[]>([]);
  const [selectedFeatures, setSelectedFeatures] = useState<Purpose[]>(initialPurposes ?? []);
  const [manualApp, setManualApp] = useState(false);
  // A content card's App asks GitHub for the scan's read access only; nothing else is chosen there.
  const [installationPurposes, setInstallationPurposes] = useState<Purpose[]>(supplemental ? initialPurposes ?? [] : contentOnly ? ["exposure"] : []);
  const [targetIds, setTargets] = useState<string[]>([]);
  const [resources, setResources] = useState<string[]>([]);
  const [rowIds, setRowIds] = useState<Record<string, string[]>>({});
  const [authConfig, setAuthConfig] = useState("");
  const [credentialsChanged, setCredentialsChanged] = useState(false);
  const [plans, setPlans] = useState<Partial<Record<Purpose, Values>>>({});
  const [schedules, setSchedules] = useState<Record<string, number>>(remembered?.schedules ?? {});
  const [startNow, setStartNow] = useState(remembered?.startNow ?? !existing);
  // A new integration's scopes scan what changed when their provider says so, unless this is switched off.
  const [changeScans, setChangeScans] = useState(remembered?.changeScans ?? true);
  const [completed, setCompleted] = useState<ProviderConnection | null>(null);
  const [requests, setRequests] = useState<CollectionRequest[]>([]);
  const [name, setName] = useState(label(d, L));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const errorBox = useRef<HTMLDivElement>(null);
  // What a held feature lacked when the others went on without it (sessions.inspect narrowing).
  const [heldDetails, setHeldDetails] = useState<Partial<Record<Purpose, { missing: Missing[]; targets: PreviewTarget[] }>>>({});
  const [adding, setAdding] = useState<Purpose | null>(null);
  const autoListed = useRef(false);
  const [checkedChoices, setCheckedChoices] = useState("");
  const [advancingCheck, setAdvancingCheck] = useState(false);
  const [pollRetry, setPollRetry] = useState(0);
  const live = useRef(true);
  const [browserKey] = useState(() => (resumeOauth ? pending()?.browser_key : undefined)
    ?? remembered?.key
    ?? Array.from(crypto.getRandomValues(new Uint8Array(32)), n => n.toString(16).padStart(2, "0")).join(""));
  const appSetup = d.provider === "github" && method.id === "github_app" && !manualApp;
  const googleOAuth = method.flow === "gcp_oauth";
  const googleClient = useApi<GoogleClient>(googleOAuth && step === 1 ? "v2/gcp/oauth/status" : null, { every: 0 });
  const [editGoogleClient, setEditGoogleClient] = useState(false);
  const contextFields = (d.target ?? []).filter(f => method.auth_first?.context.includes(f.name) && (!f.editions || f.editions.includes(edition)));
  const registrationFields = (d.target ?? []).filter(f => (method.auth_first?.context.includes(f.name) || f.name === "organization")
    && (!f.editions || f.editions.includes(edition)));
  const config = JSON.stringify([edition, method.id, payload(contextFields, context)]);
  const reusable = Boolean(draft && authConfig === config && !credentialsChanged && Date.parse(draft.expires_at) > Date.now()
    && !["CANCELLED", "EXPIRED", "COMPLETED"].includes(draft.state));
  const googleReady = !googleOAuth || (reusable && draft?.authentication?.status === "GRANTED") || googleClient.data?.configured === true;
  const missingAuthField = missingRequired(appSetup && !reusable ? registrationFields : contextFields, context);
  const shownFields = (appSetup && !reusable ? registrationFields : contextFields).filter(f => !f.product);
  // The App's start button sits right under the organization it is made for.
  const appSplit = appSetup && !reusable ? shownFields.findIndex(f => f.name === "organization") + 1 || shownFields.length : shownFields.length;
  const appStartReason = missingAuthField ? L(`${josa(label(missingAuthField, L), "을/를")} 먼저 입력하세요.`, `Enter ${label(missingAuthField, L)} first.`) : null;
  // A content flow edits where the scan reads: a target added there serves only the scan, so the account's other features
  // stay on the targets they had (inspect's `target_purposes`, which the server holds to the same rule).
  const scanOnlyIds = contentOnly ? (draft?.roots ?? []).filter(t => !(draft?.previous_target_ids ?? []).includes(t.id)
    && (t.purposes ?? draft?.purposes ?? []).includes("exposure") && (t.purposes ?? draft?.purposes ?? []).some(p => p !== "exposure"))
    .map(t => t.id) : [];
  const targets = (draft?.roots ?? []).map(t => scanOnlyIds.includes(t.id) ? { ...t, purposes: ["exposure" as Purpose] } : t);
  const targetsAt = (p: Purpose, ids: string[]) => targets.filter(t => ids.includes(t.id) && (!t.purposes || t.purposes.includes(p)));
  const targetsFor = (p: Purpose) => targetsAt(p, targetIds);
  const fieldsAt = (p: Purpose, ids: string[]) => selectedPlanFields(d, p, edition, targetsAt(p, ids));
  const fields = (p: Purpose) => fieldsAt(p, targetIds);
  const plan = (p: Purpose) => valuesOf(fields(p), plans[p] ?? {});
  const bodyFor = (ids: string[], list: Purpose[]) => Object.fromEntries(list.map(p => [p, payload(fieldsAt(p, ids), valuesOf(fieldsAt(p, ids), plans[p] ?? {}))]));
  const planBody = bodyFor(targetIds, purposes);
  // An existing account's active features ride along unchanged in a content flow ("유지"); only the scan is gated here.
  const kept = existing ? (Object.keys(draft?.previous_plans ?? existing.plans) as Purpose[])
    .filter(p => (draft?.feature_enabled ?? existing.feature_enabled)?.[p] !== false) : [];
  const contentFeatures = PURPOSE_ORDER.filter(p => p === "exposure" || kept.includes(p));
  const keptShown: Purpose[] = contentOnly ? kept.filter(p => p !== "exposure") : [];
  const gating = contentOnly ? purposes.filter(p => p === "exposure") : purposes;
  const previewPurposes = authenticationOnly ? [] : contentOnly ? ["exposure" as Purpose] : supplemental ? initialPurposes ?? []
    : purposesForEdition(d, edition).filter(p => serves(method, p, edition));
  // A content flow edits where the scan reads; the account's other targets stay as they are.
  const listedTargets = contentOnly ? targets.filter(t => !t.purposes || t.purposes.includes("exposure")) : targets;
  // A shared target a kept feature already collects from stays selected whatever the scan picker says ("유지").
  const fixedTargets = contentOnly ? (draft?.previous_target_ids ?? []).filter(id => listedTargets.some(t => t.id === id
    && (!t.purposes || t.purposes.some(p => keptShown.includes(p))))) : [];
  const unlisted = draft?.previous_unlisted ?? 0;
  const optionGroups = gating.map(p => ({ purpose: p, fields: fields(p).filter(f => !isScheduleField(f)
    && !(awsIdentity && p === "inventory" && f.name.startsWith("cloudtrail_") && plan(p).cloudtrail !== true)
    && !idleReaderField(d.provider, p, f.name, plan(p))) })).filter(group => group.fields.length);
  const scheduledPurposes = gating.filter(p => p === "exposure" || fields(p).some(f => f.name === "schedule_minutes"));
  const scheduleOf = (p: Purpose) => schedules[p] ?? (existing ? -1 : !schedulesAllowed ? 0 : Number(plan(p).schedule_minutes || 1440));
  // -1 keeps an existing scope's full-scan cadence; a new one follows the installation default unless one is chosen.
  const fullSchedule = schedules["exposure.full_scan_minutes"] ?? (existing ? -1 : INSTALLATION_DEFAULT);
  // A scope saved now (every one of a new integration's, a target added while editing) takes this; saved ones keep theirs.
  const changeScanChoice = purposes.includes("exposure") && d.provider !== "website";
  const extraSchedules = (p: Purpose) => fields(p).filter(f => f.schedule && (d.provider !== "github"
    || (f.name === "enterprise_schedule_minutes" ? plan(p).enterprise_inventory === true
      : f.name !== "audit_schedule_minutes" || ["audit_events", "enterprise_audit", "token_digests"].some(key => plan(p)[key] === true))));
  const extraScheduleOf = (p: Purpose, field: ReturnType<typeof fields>[number]) => schedules[`${p}.${field.name}`]
    ?? (!schedulesAllowed ? 0 : Number(existing?.plans[p]?.[field.name] ?? existing?.plans[p]?.schedule_minutes ?? plan(p)[field.name] ?? field.default ?? 0));
  const scheduleBody: Partial<Record<Purpose, number | Record<string, number | null>>> = {};
  for (const p of scheduledPurposes) {
    const extras = extraSchedules(p);
    if (extras.length) scheduleBody[p] = { ...(scheduleOf(p) >= 0 ? { schedule_minutes: scheduleOf(p) } : {}),
      ...Object.fromEntries(extras.map(field => [field.name, extraScheduleOf(p, field)])) };
    else if (scheduleOf(p) >= 0) scheduleBody[p] = scheduleOf(p);
  }
  if (scheduledPurposes.includes("exposure") && (scheduleOf("exposure") >= 0 || fullSchedule !== -1)) scheduleBody.exposure = {
    ...(scheduleOf("exposure") >= 0 ? { schedule_minutes: scheduleOf("exposure") } : {}),
    // null saves the scope without a cadence of its own: it follows the installation default.
    ...(fullSchedule >= 0 ? { full_scan_minutes: fullSchedule } : fullSchedule === INSTALLATION_DEFAULT ? { full_scan_minutes: null } : {}),
  };
  const needsScheduleSwitch = (scheduleOf("exposure") > 0 || fullSchedule > 0) && scheduledPurposes.includes("exposure") && !triggers.data?.schedules.enabled;
  const choices = JSON.stringify([targetIds, planBody]);
  const rows = draft?.resources ?? [];
  const selectedRows = rows.filter(r => resources.includes(r.id));
  const selectedRoots = selectedRows.map(r => ({ ...(draft?.selected_roots?.find(root => root.resource_id === r.id) ?? defaultRoot(r)),
    descendant_ids: rowIds[r.id] ?? [] }));
  const resourcesReady = selectedRows.length > 0 && selectedRoots.every((r, i) => !rootProblem(r, selectedRows[i].resource_type))
    && rows.filter(r => pickable(r).ok).every(r => selectedRows.some(chosen => chosen.source_key === r.source_key));
  const required = gating.flatMap(p => [...new Map(targetsFor(p).flatMap(t => permissionsFor(d, p, method.id, t.target, plan(p)))
    .map(permission => [permission.id, permission])).values()]
    .filter(permission => permission.required !== false).map(permission => ({ p, permission,
      answers: draft?.checks?.results?.[p]?.items.filter(item => item.permission === permission.id) ?? [] })));
  // Per feature (and target): ready, or held with exactly what the check found missing.
  const checkedNow = Boolean(draft?.checks?.results) && (draft?.state === "CHECKED" || draft?.state === "SELECTED") && checkedChoices === choices;
  const outcomes = checkedNow ? featureOutcomes(d, method.id, gating, targetsFor, plan, draft!.checks!.results, draft!.blockers ?? []) : [];
  // A kept feature is not chosen here, but the server still requires it: a refusal stops this flow before the scope step.
  const keptHeld = checkedNow && keptShown.length ? featureOutcomes(d, method.id, keptShown.filter(p => purposes.includes(p)), targetsFor, plan,
    draft!.checks!.results, draft!.blockers ?? []).filter(o => !o.ok) : [];
  const accessReady = (draft?.state === "CHECKED" || draft?.state === "SELECTED") && checkedChoices === choices
    && Date.parse(draft.expires_at) > Date.now()
    && Boolean(draft.blockers) && !draft.blockers!.some(b => !b.purpose || gating.includes(b.purpose))
    && required.every(r => r.answers.length && r.answers.every(a => a.status === "GRANTED")) && !keptHeld.length;
  const ready = outcomes.filter(o => o.ok).map(o => o.purpose);
  const heldNow = outcomes.filter(o => !o.ok);
  const heldIds = heldNow.map(o => o.purpose);
  // An edited integration keeps what it already runs (TARGET_EDIT_KEEP_FEATURES): only a new feature can be held.
  const canNarrow = ready.length > 0 && heldIds.length > 0 && heldIds.every(p => !(p in (draft?.previous_plans ?? {})));
  const narrowIds = targetIds.filter(id => targets.find(t => t.id === id)?.purposes?.some(p => !heldIds.includes(p)) ?? true);
  // A target a running feature collects from (a root without its own features serves them all) is never dropped by
  // continuing with the passing targets: completion replaces the integration's targets.
  const runningTargets = (draft?.previous_target_ids ?? []).filter(id => targets.some(t => t.id === id
    && (!t.purposes || t.purposes.some(p => p in (draft?.previous_plans ?? {})))));
  const failingTargets = heldNow.flatMap(o => targetsFor(o.purpose).map(t => t.id).filter(id => !o.passing.includes(id)));
  const passIds = targetIds.filter(id => !failingTargets.includes(id));
  const canPassTargets = heldNow.length > 0 && heldNow.every(o => o.passing.length > 0) && passIds.length > 0
    && purposes.every(p => targetsAt(p, passIds).length > 0) && !failingTargets.some(id => runningTargets.includes(id));
  const heldPurposes = draft?.held_purposes ?? [];
  const canAddHeld = d.provider !== "aws"; // sessions.edit: an AWS owner adds features in its settings, not here
  const working = busy || draft?.state === "WORKING";
  const authDisabled = working || idBlocked || !googleReady || (googleOAuth && editGoogleClient) || !method.auth_first || Boolean(missingAuthField)
    || (!appSetup && !reusable && (method.fields ?? []).some(f => !f.optional && !credential[f.name]?.trim()));
  const investigationOptions = awsIdentity && admin ? investigationKeys(purposes) : [];

  useEffect(() => {
    if (!advancingCheck || working) return;
    setAdvancingCheck(false);
    if (accessReady) setStep(4);
  }, [advancingCheck, working, accessReady]);
  useEffect(() => { live.current = true; return () => { live.current = false; }; }, []);
  useEffect(() => {
    if (!draft) return;
    try {
      if (completed || ["CANCELLED", "EXPIRED", "COMPLETED"].includes(draft.state)) sessionStorage.removeItem(storageKey);
      else sessionStorage.setItem(storageKey, JSON.stringify({ id: draft.id, key: browserKey, schedules, startNow, changeScans, reviewName: name, investigations: investigationEdits }));
    } catch { /* A blocked browser store does not prevent completing the open wizard. */ }
  }, [draft, browserKey, storageKey, schedules, startNow, changeScans, name, completed, investigationEdits]);
  function restore(next: Draft) {
    if (!d.editions.some(e => e.id === next.edition) || !methodsFor(d, [], next.edition ?? edition, existing?.auth_method).some(m => m.id === next.auth_method)
      || (next.purposes ?? []).some(p => !purposesForEdition(d, next.edition ?? edition).includes(p))
      || authenticationOnly && Boolean(next.purposes?.length)) {
      forgetDraft(storageKey);
      setError(L("이전 초안은 현재 제품·연결 목적과 다릅니다. 인증을 다시 확인하세요.", "The previous draft belongs to a different product or connection purpose. Authenticate again."));
      return;
    }
    setDraft(next);
    setEdition(next.edition ?? d.editions[0].id); setMethod(next.auth_method ?? method.id);
    setContext(valuesOf(d.target ?? [], next.context ?? {})); setPurposes(next.purposes ?? []); setSelectedFeatures(next.purposes?.length ? next.purposes : initialPurposes ?? []);
    const ids = next.selected_targets?.length ? next.selected_targets : next.previous_target_ids?.length
      ? next.previous_target_ids : next.roots?.length === 1 ? [next.roots[0].id] : [];
    setTargets(ids); setResources(next.selected_resources ?? []);
    setRowIds(Object.fromEntries((next.selected_roots ?? []).map(r => [r.resource_id, r.descendant_ids ?? []])));
    const restoredPlans = { ...next.previous_plans, ...next.plans };
    const restoredFields = (p: Purpose) => selectedPlanFields(d, p, next.edition ?? edition,
      (next.roots ?? []).filter(r => ids.includes(r.id) && (!r.purposes || r.purposes.includes(p))));
    const restoredValues = Object.fromEntries(Object.entries(restoredPlans).map(([p, v]) => [p, valuesOf(restoredFields(p as Purpose), v)]));
    setPlans(restoredValues);
    setCheckedChoices(JSON.stringify([ids, Object.fromEntries((next.purposes ?? []).map(p =>
      [p, payload(restoredFields(p), valuesOf(restoredFields(p), restoredValues[p] ?? {}))]))]));
    if (next.name) setName(next.name);
    const selectedMethod = d.auth_methods.find(m => m.id === next.auth_method) ?? method;
    setCredential(Object.fromEntries((selectedMethod.fields ?? [])
      .filter(field => field.public && !field.secret && typeof next.public_auth?.[field.name] === "string")
      .map(field => [field.name, next.public_auth![field.name]])));
    setCredentialsChanged(false);
    const inputFields = (d.target ?? []).filter(f => selectedMethod.auth_first?.context.includes(f.name));
    setAuthConfig(JSON.stringify([next.edition ?? edition, selectedMethod.id, payload(inputFields, valuesOf(inputFields, next.context ?? {}))]));
    setAdvancingCheck(next.state === "WORKING" && Boolean(next.selected_targets?.length));
    setStep(next.state === "SELECTED" ? 5 : next.state === "CHECKED" && next.blockers?.length === 0 ? 4
      : next.roots?.length ? 3 : next.authentication?.status === "GRANTED" ? 2 : 1);
  }
  const reading = useRef<Promise<Draft> | null>(null);
  useEffect(() => {
    if (!remembered || resumeOauth) return;
    let cancelled = false;
    reading.current ??= send<Draft>(`${BASE}/${remembered.id}/read`, "POST", { browser_key: browserKey });
    void reading.current.then(next => {
      if (cancelled) return;
      if (["CANCELLED", "EXPIRED", "COMPLETED"].includes(next.state)) { forgetDraft(storageKey); return; }
      restore(next);
      if (remembered.reviewName) setName(remembered.reviewName);
    }).catch(reason => { if (!cancelled) { forgetDraft(storageKey); setError(reasonText(reason, L)); } });
    return () => { cancelled = true; };
  }, []); // The server, not browser storage, supplies the resumed choices and access evidence.
  const resuming = useRef<Promise<string> | null>(null);
  const editing = useRef<Promise<Draft> | null>(null);
  const editRestored = useRef(false);
  const oauthRestored = useRef(false);
  const initializedPlans = useRef(false);
  const initializedTargets = useRef(false);
  useEffect(() => {
    if (!existing || remembered || editRestored.current) return;
    let cancelled = false;
    editing.current ??= send<Draft>(`provider-connections/${existing.id}/targets/draft`, "POST", {
      browser_key: browserKey, expected_revision: existing.revision });
    void editing.current.then(next => {
      if (cancelled || editRestored.current) return;
      editRestored.current = true;
      setDraft(next); setEdition(existing.edition); setMethod(existing.auth_method); setName(existing.name);
      const active = (Object.keys(next.previous_plans ?? existing.plans) as Purpose[]).filter(p => (next.feature_enabled ?? existing.feature_enabled)?.[p] !== false);
      setContext(valuesOf(d.target ?? [], next.context ?? {})); setPurposes(active);
      setSelectedFeatures([...new Set([...active, ...(initialPurposes ?? [])])]);
    }).catch(reason => { if (!cancelled) setError(reasonText(reason, L)); });
    return () => { cancelled = true; };
  }, [existing, browserKey, d, L]);
  useEffect(() => {
    if (!resumeOauth || oauthRestored.current) return;
    let cancelled = false;
    resuming.current ??= completeDraftSignIn(resumeOauth);
    void resuming.current.then(id => send<Draft>(`${BASE}/${id}/read`, "POST", { browser_key: browserKey })).then(next => {
      if (!cancelled && !oauthRestored.current) { oauthRestored.current = true; restore(next); }
    }).catch(reason => { if (!cancelled) setError(reasonText(reason, L)); });
    return () => { cancelled = true; };
  }, [resumeOauth, browserKey, L]);
  useEffect(() => {
    if (draft?.state !== "WORKING") return;
    let cancelled = false;
    const timer = window.setTimeout(async () => {
      try {
        const next = await send<Draft>(`${BASE}/${draft.id}/read`, "POST", { browser_key: browserKey });
        if (!cancelled && live.current) {
          setDraft(next);
          if (next.state === "AUTHENTICATED") setStep(2);
          if (next.state === "CHECKED" && next.editing) {
            setResources(next.selected_resources ?? []);
            setRowIds(Object.fromEntries((next.selected_roots ?? []).map(r => [r.resource_id, r.descendant_ids ?? []])));
          }
          if (next.state === "LISTED") { setStep(3);
            const wasInitialized = initializedTargets.current;
            initializedTargets.current = true;
            setTargets(previous => wasInitialized ? previous.filter(id => next.roots?.some(root => root.id === id))
              : next.previous_target_ids?.length ? next.previous_target_ids : next.roots?.length === 1 ? [next.roots[0].id] : []);
            if (next.previous_plans && !initializedPlans.current) {
              initializedPlans.current = true;
              setPlans(Object.fromEntries(Object.entries(next.previous_plans).map(([p, values]) => {
                const roots = (next.roots ?? []).filter(r => (!next.previous_target_ids?.length || next.previous_target_ids.includes(r.id))
                  && (!r.purposes || r.purposes.includes(p as Purpose)));
                return [p, valuesOf(selectedPlanFields(d, p as Purpose, next.edition ?? edition, roots), values)];
              })));
            } }
          if (next.error) setError(detailText(next.error, L));
        }
      } catch (reason) { if (!cancelled && live.current) setError(reasonText(reason, L)); }
    }, 1500);
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [draft, browserKey, L, pollRetry, d, edition]);

  const request = <T = Draft,>(action: string, extra: object = {}) => send<T>(`${BASE}/${draft!.id}/${action}`, "POST", {
    browser_key: browserKey, expected_revision: draft!.revision, ...extra,
  });
  async function act(action: () => Promise<void>) {
    setBusy(true); setError(null);
    try { await action(); } catch (reason) {
      // The server found access missing: show what each feature lacks from the draft read again, not a bare refusal.
      if (draft && reason instanceof Error && reason.message.split(/[\s:]/, 1)[0] === "REQUIRED_PERMISSIONS_NOT_GRANTED") {
        try {
          const next = await send<Draft>(`${BASE}/${draft.id}/read`, "POST", { browser_key: browserKey });
          if (live.current) { setDraft(next); setStep(3); }
          return;
        } catch { /* The refusal below still says why. */ }
      }
      setError(reasonText(reason, L));
    } finally { if (live.current) setBusy(false); }
  }
  async function close() {
    await act(async () => {
      if (draft && draft.state !== "COMPLETED") await request("cancel");
      forgetDraft(storageKey);
      onClose();
    });
  }
  async function authenticate() {
    if (working || idBlocked) return;
    await act(async () => {
      if (approving) {
        try {
          identity.replace(await send<AwsIdentityView>(IDENTITY_PATH, "PUT", {
            confirm: true, ...(roleArn.trim() ? { role_arn: roleArn.trim() } : {}), ...(ssoRegion.trim() ? { sso_region: ssoRegion.trim() } : {}),
          }));
          saved();
        } catch (reason) {
          setError(refusalText(reason instanceof Error ? reason.message : "", L, idView?.identity_source) ?? reasonText(reason, L));
          return;
        }
      }
      if (appSetup && !reusable) {
        // The card it began from comes back with the draft after GitHub (a content card skips the feature step again).
        await startGitHubApp({ onboarding: true, edition, installation_purposes: installationPurposes,
          target: payload(registrationFields, context), ...(entry ? { entry } : {}) });
        return;
      }
      // A new identity approval invalidates the revision bound to an earlier AWS draft.
      if (reusable && !approving) {
        if (method.flow === "gcp_oauth" && draft?.state === "AWAITING_OAUTH") {
          await startSignIn(draft.id, locale, browserKey); return;
        }
        if (draft?.authentication?.status === "GRANTED") { setStep(contentOnly && draft.roots?.length ? 3 : 2); return; }
        setDraft(await request("authenticate")); return;
      }
      if (draft) await request("cancel");
      const next = await send<Draft>(BASE, "POST", { provider: d.provider, edition, auth_method: method.id,
        browser_key: browserKey, context: payload(contextFields, context), credential,
        credential_purpose: initialPurposes?.length === 1 && initialPurposes[0] === "remediation" ? "remediator" : "collector" });
      setCredential(all => Object.fromEntries(Object.entries(all).filter(([key]) => method.fields?.some(f => f.name === key && f.public))));
      setAuthConfig(config); setCredentialsChanged(false); setDraft(next); setPurposes([]); setTargets([]); setResources([]); setRowIds({}); setPlans({}); setCheckedChoices("");
      if (method.flow === "gcp_oauth") await startSignIn(next.id, locale, browserKey);
    });
  }
  /** Check access for ``ids`` and ``keep``: the current choice, or only the ready features or the passing targets. */
  async function inspect(ids = targetIds, keep = purposes) {
    await act(async () => {
      const body = bodyFor(ids, keep);
      setResources([]); setCheckedChoices(""); setAdvancingCheck(false);
      const scoped = keep.includes("exposure") ? ids.filter(id => scanOnlyIds.includes(id)) : [];
      const next = await request("inspect", { target_ids: ids, plans: body,
        ...(scoped.length ? { target_purposes: Object.fromEntries(scoped.map(id => [id, ["exposure"]])) } : {}) });
      if (keep.length < purposes.length) {
        setHeldDetails(all => ({ ...all, ...Object.fromEntries(heldNow.filter(o => !keep.includes(o.purpose))
          .map(o => [o.purpose, { missing: o.missing, targets: targetsFor(o.purpose) }])) }));
        setPurposes(keep);
      }
      setTargets(ids); setCheckedChoices(JSON.stringify([ids, body])); setDraft(next); setAdvancingCheck(true);
    });
  }
  async function discover() {
    await act(async () => {
      const chosen = contentOnly ? contentFeatures : existing ? selectedFeatures : supplemental ? initialPurposes ?? selectedFeatures : selectedFeatures;
      if (chosen.some(p => !purposesForEdition(d, edition).includes(p))) {
        setError(L("선택한 기능의 인증 방식이 제공되지 않습니다.", "No sign-in method is offered for a selected feature.")); return;
      }
      const groups = existing ? [{ method: method.id, edition, purposes: chosen }] : setupGroups(d, chosen, edition, method.id);
      const needsRemediatorSignIn = !existing && !supplemental
        && groups[0]?.purposes.length === 1 && groups[0].purposes[0] === "remediation";
      const current = !needsRemediatorSignIn && groups[0]?.method === method.id && groups[0]?.edition === edition ? groups[0] : undefined;
      if (!current && onDeferred) {
        if (draft) await request("cancel");
        forgetDraft(storageKey); onDeferred(edition, chosen, groups); return;
      }
      if (!current) return;
      setPurposes(current.purposes);
      onSelection?.(edition, chosen, current, groups.slice(1));
      initializedTargets.current = false;
      const next = await request("discover", { purposes: current.purposes }); setDraft(next);
      if (next.state === "AWAITING_OAUTH") await startSignIn(next.id, locale, browserKey);
    });
  }
  // A content-scan card lists its targets as soon as the sign-in is confirmed: the scan is the only feature. Google's
  // cloud consent leaves the page, so there it stays the admin's click.
  const autoList = contentOnly && method.flow !== "gcp_oauth";
  useEffect(() => { if (step !== 2) autoListed.current = false; }, [step]);
  useEffect(() => {
    if (!autoList || step !== 2 || busy || draft?.state !== "AUTHENTICATED" || autoListed.current) return;
    autoListed.current = true; // a failed listing waits for the retry below instead of looping
    void discover();
  });
  useEffect(() => { if (error) errorBox.current?.scrollIntoView({ block: "nearest" }); }, [error]);
  const steps: [number, string][] = contentOnly
    ? [[1, L("인증", "Sign in")], [3, L("권한 확인", "Access check")], [4, L("검사 범위", "Scan scope")], [5, L("최종 확인", "Review")]]
    : [[1, L("인증", "Sign in")], [2, L("기능", "Features")], [3, L("권한 확인", "Access check")], [4, L("수집 범위", "Collection scope")], [5, L("최종 확인", "Review")]];
  // Listing a content card's targets right after sign-in belongs to its access check.
  const shownStep = contentOnly && step === 2 ? 3 : step;
  const keptChips = keptShown.length ? <div className="ig-section"><span className="ig-sub">{L("이 계정에서 계속 수집하는 기능", "Features this account keeps collecting")}</span>
    <div className="ig-perms">{keptShown.map(p => <span key={p} className="tag" data-tip={L("이 화면에서는 바꾸지 않습니다.", "Not changed here.")}>
      {featureName(p, L)} · {L("유지", "Kept")}</span>)}</div></div> : null;
  const heldSection = heldPurposes.length ? <div className="ig-section"><div className="ig-section-head"><h3>{L("보류된 기능", "Held features")}</h3></div>
    {heldPurposes.map(p => <div className="ig-perm-group" key={p}><span className="ig-sub">{featureName(p, L)}</span>
      {heldDetails[p]?.missing.length ? <MissingList d={d} purpose={p} method={method.id} missing={heldDetails[p]!.missing} targets={heldDetails[p]!.targets} />
        : <p className="ig-hint">{L("필요한 권한이 확인되지 않아 이번에는 켜지 않습니다.", "Not turned on this time: its required access was not verified.")}</p>}
      {completed && canAddHeld ? <button type="button" className="ghost-btn" disabled={busy} onClick={() => setAdding(p)}>{L("보류된 기능 추가", "Add the held feature")}</button> : null}
    </div>)}
    <p className="ig-hint">{completed && !canAddHeld ? L("권한을 부여한 뒤 연동 현황의 ‘수집 범위·인증 설정’에서 이 기능을 추가하세요.", "Grant the access, then add this feature from ‘Collection scope and sign-in’ in the integration list.")
      : L("보류된 기능은 저장 후 권한을 부여하고 이 연동에 기능을 추가하면 켤 수 있습니다.", "Turn a held feature on later: grant its access, then add it to this integration.")}</p></div> : null;
  if (machineOpen) return <MachineIdentityModal onClose={() => { setMachineOpen(false); identity.reload(); }} />;
  if (completed && adding) return <AuthFirstWizard descriptor={d} existing={completed} admin={admin} schedulesAllowed={schedulesAllowed}
    initialPurposes={[adding]} entry={adding === "exposure" ? "exposure" : entry} onComplete={onComplete} onClose={onClose} onAdvanced={() => setAdding(null)} />;
  if (completed) {
    const done = () => { if (onComplete) onComplete(completed); else onClose(); };
    return <Modal onClose={done} labelledBy="auth-first-done" className="integ" dismissable={!busy}>
      <h2 id="auth-first-done">{L("연동 설정을 저장했습니다", "Integration settings saved")}</h2>
      <p>{completed.checks.authentication_only ? L("계정 연결을 저장했습니다. 콘텐츠 연결에서 읽기 권한과 검사 위치를 선택하세요.", "Account connection saved. Select read access and scan locations under content connections.")
        : busy ? L("최초 수집을 요청하고 있습니다…", "Requesting initial collection…")
        : L("주기를 설정한 기능은 브라우저를 닫아도 서버에서 수집합니다. 수집 완료 여부는 아래 실행 상태에서 확인하세요.", "Features with a schedule collect on the server after the browser closes. Check run status below for completion.")}</p>
      <CollectionProgress requests={requests} />
      {heldSection}
      {requests.some(r => r.error) ? <button type="button" className="ghost-btn" disabled={busy} onClick={() => void act(async () => {
        const retried = await collectConnection(completed, new Set(requests.filter(r => r.error).map(r => r.key)));
        setRequests(all => [...all.filter(r => !r.error), ...retried]); saved();
      })}>{L("시작하지 못한 수집 재시도", "Retry collections that did not start")}</button> : null}
      <div className="modal-foot"><button type="button" className="primary-btn" disabled={busy} onClick={done}>{L("확인·계속", "Done · continue")}</button></div>
    </Modal>;
  }
  return <Modal onClose={() => void close()} labelledBy="auth-first-title" className="integ" dismissable={!busy}>
    <h2 id="auth-first-title"><Logo id={d.provider} size={26} />{label(d, L)} <small>{L("연동하기", "Connect")}</small></h2>
    {progress ? <Banner icon="info">{progress}</Banner> : null}
    <ol className="ig-steps">{steps.map(([n, text], i) => <li key={n} aria-current={shownStep === n ? "step" : undefined}>
      <span className="n">{i + 1}</span>{text}</li>)}</ol>
    <div ref={errorBox}>{error ? <Banner tone="bad" icon="alert">{error}{draft?.state === "WORKING" ? <button type="button" className="link-btn"
      onClick={() => { setError(null); setPollRetry(n => n + 1); }}>{L("다시 확인", "Retry")}</button> : null}</Banner> : null}</div>
    {/* A sign-in that works but whose organization listing GitHub will refuse: shown on every step, since the wizard
        moves on to listing as soon as the sign-in is granted. */}
    {draft?.authentication?.status === "GRANTED" && draft.authentication.detail ? <Banner tone="warn" icon="info">{detailText(draft.authentication.detail, L)}</Banner> : null}
    {working ? <p role="status" className="ig-hint">{L("인증된 접근 권한과 목록을 확인하고 있습니다…", "Checking authenticated access and available targets…")}</p> : null}
    {step === 1 && existing ? <div className="ig-section"><p>{L("저장된 인증정보로 접근을 다시 확인합니다.", "Checking access with the saved sign-in.")}</p>
      {draft?.state === "FAILED" || draft?.state === "AUTH_FAILED" || error ? <><Banner tone="warn" icon="info">{L("연결 설정에서 기능 상태와 인증정보를 확인한 뒤 다시 열어 주세요.", "Check feature status and sign-in in connection settings, then reopen this window.")}</Banner>
        {draft ? <button type="button" className="ghost-btn" onClick={() => void act(async () => setDraft(await request("authenticate")))}>{L("다시 확인", "Retry")}</button> : null}
        <button type="button" className="link-btn" onClick={() => void act(async () => { if (draft) await request("cancel"); onAdvanced(method.id, edition); })}>{L("연결 설정으로 돌아가기", "Back to connection settings")}</button></> : null}</div> : null}
    {step === 1 && !existing ? <fieldset className="ig-section" disabled={working} style={{ border: 0, padding: 0, minWidth: 0 }}>
      {editions.length > 1 && !supplemental ? <SelectField label={L("제품", "Edition")} value={edition} options={editions.map(e => ({ id: e.id, label: label(e, L) }))}
        onChange={v => { setEdition(v); setCredential({}); setContext(defaults(d.target ?? [])); }} /> : null}
      <SelectField label={L("인증 방식", "Sign-in method")} value={method.id} options={methods.map(m => ({ id: m.id, label: label(m, L) }))}
        tip={methodHint(d.provider, method, L) ?? undefined}
        onChange={v => { setMethod(v); setCredential({}); }} />
      <p className="ig-hint">{awsIdentity ? methodHint(d.provider, method, L) : L("서버에서 지속 수집할 인증을 설정합니다. 역할·워크로드 신원은 실행 환경에서 갱신하며, 앱·토큰 방식은 공급자의 만료와 교체 조건을 따릅니다.", "Configure sign-in for continuous server collection. Role and workload credentials refresh in the runtime; apps and tokens follow the provider's expiry and renewal rules.")}</p>
      {awsIdentity ? <div className="ig-section">
        {identity.loading ? <p role="status" className="ig-hint">{L("서버의 AWS 신원을 확인하고 있습니다…", "Checking the server's AWS identity…")}</p> : null}
        {idView && identityText(idView, L) ? <>
          <p className="ig-hint">{identityText(idView, L)}</p>
          <p className="ig-hint" style={{ overflowWrap: "anywhere" }}>{shownIdentity?.principal_arn ?? (approving ? idView.api.caller_arn : null)}</p>
          <p className="ig-hint">{approving
            ? L("아래 버튼을 누르면 이 설치가 AWS 수집에 사용할 신원을 승인하고 인증을 확인합니다.", "The button below approves this identity for this installation's AWS collection, then checks authentication.")
            : L("이 설치에서 승인한 AWS 신원으로 인증을 확인합니다.", "Authentication uses this installation's approved AWS identity.")}</p>
        </> : null}
        {idNeeds === "ROLE_ARN" ? <details><summary>{L("역할 ARN 직접 입력 (고급)", "Enter the role ARN manually (advanced)")}</summary>
          <TextField label={L("이 신원이 쓰는 IAM 역할 ARN(경로 포함)", "IAM role ARN this identity uses (with its path)")}
            value={roleArn} onChange={setRoleArn} placeholder="arn:aws:iam::111111111111:role/path/RoleName" /></details> : null}
        {idNeeds === "IDENTITY_CENTER_REGION" ? <SelectField label={L("IAM Identity Center 리전", "IAM Identity Center Region")}
          value={ssoRegion} onChange={setSsoRegion} options={[{ id: "", label: L("리전을 선택하세요", "Select a region") },
            ...(d.purposes.inventory?.plan?.find(f => f.name === "cloudtrail_regions")?.options ?? []).map(o => ({ id: o.id, label: label(o, L) }))]} /> : null}
        {identity.error ? <Banner tone="bad" icon="alert">{reasonText(identity.error, L)}</Banner> : null}
        {idIssue ? <Banner tone="bad" icon="alert">{idIssue.text}{idIssue.fix ? <p>{idIssue.fix}</p> : null}</Banner> : null}
        {approving && !admin ? <Banner tone="warn" icon="info">{L("관리자가 서버 AWS 신원을 승인해야 합니다.", "An administrator must approve the server's AWS identity.")}</Banner> : null}
        <button type="button" className="link-btn" disabled={identity.loading} onClick={() => { setError(null); identity.reload(); }}>{L("AWS 신원 다시 확인", "Refresh AWS identity")}</button>
      </div> : null}
      {method.auth_first ? <>
        {d.provider === "github" && method.id === "github_app" ? <div className="ig-section">
          <span className="ig-sub" id="ig-app-mode">{L("연결 방식", "Setup method")}</span>
          <div className="re-scope" role="radiogroup" aria-labelledby="ig-app-mode">{[false, true].map(manual => <button type="button" role="radio" key={String(manual)}
            aria-checked={manualApp === manual} tabIndex={manualApp === manual ? 0 : -1} onClick={() => setManualApp(manual)}
            onKeyDown={event => {
              if (!["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(event.key)) return;
              event.preventDefault(); setManualApp(!manualApp);
              (event.currentTarget.parentElement?.querySelector('[role="radio"][aria-checked="false"]') as HTMLElement | null)?.focus();
            }}>{manual ? L("이미 만든 App 정보 입력", "Enter an App you already made") : L("새 App 자동 설정", "Set up a new App automatically")}</button>)}</div>
        </div> : null}
        <FieldGrid fields={shownFields.slice(0, appSplit)} values={context} onChange={(k, v) => setContext(all => ({ ...all, [k]: v }))} />
        {appSetup && !reusable ? <div className="ig-test">
          <button type="button" id="ig-app-start" className="primary-btn" disabled={authDisabled} aria-describedby={appStartReason ? "ig-app-start-reason" : undefined}
            onClick={() => void authenticate()}>{L("GitHub에서 App 만들기·설치", "Create and install App on GitHub")}</button>
          {appStartReason ? <span id="ig-app-start-reason" className="subtle" role="status">{appStartReason}</span> : null}
        </div> : null}
        {appSplit < shownFields.length ? <FieldGrid fields={shownFields.slice(appSplit)} values={context} onChange={(k, v) => setContext(all => ({ ...all, [k]: v }))} /> : null}
        {appSetup ? <>
          <p className="ig-hint">{L("조직 주소의 이름을 입력하고 ‘GitHub에서 App 만들기·설치’를 누르세요. 조직 소유자가 GitHub에서 만들기와 설치를 승인하면 App ID·설치 ID·개인 키를 자동으로 받습니다.", "Enter the organization name from its GitHub address, then use ‘Create and install App on GitHub’. After the organization owner approves creation and installation, GitHub supplies the App ID, installation ID, and private key.")}</p>
          {supplemental && initialPurposes?.includes("remediation") ? <Banner tone="warn" icon="alert">{L("조치 전용 App을 새로 만듭니다. GitHub에서 조직 토큰 접근을 취소할 쓰기 권한을 확인하고 승인하세요. 수집 App의 인증정보는 재사용하지 않습니다.", "Create a separate acting App. Review and approve its write permission to revoke organization token access on GitHub. Collection credentials are not reused.")}</Banner>
            : contentOnly ? <p className="ig-hint">{L("GitHub에는 평문 노출 검사에 필요한 읽기 권한만 요청합니다. 검사 범위는 권한 확인 뒤에 고릅니다.", "GitHub is asked only for the read access the plaintext exposure scan needs. The scan scope is chosen after the access check.")}</p>
            : <details className="ig-section"><summary>{L("App 설치 권한 선택", "Choose App installation permissions")}</summary>
              <p className="ig-hint">{L("아무 항목도 고르지 않으면 기본 인증만 요청합니다. 아래는 GitHub에 요청할 읽기 권한이며 수집 기능이나 범위를 켜지 않습니다. 나중에 선택한 기능에 권한이 부족하면 GitHub App 설정에서 추가한 뒤 다시 확인합니다.", "With no selection, request basic authentication only. These are read permissions requested from GitHub; they do not enable collection or approve scope. If a later feature needs more access, add it in the App settings and check again.")}</p>
              <div className="ig-feats">{(["exposure", "inventory", "vault", "identity"] as Purpose[]).filter(p => methodsFor(d, [p], edition).some(m => m.id === method.id)).map(p => <button type="button" key={p} className="ig-feat-card" role="checkbox" aria-checked={installationPurposes.includes(p)}
                onClick={() => setInstallationPurposes(all => all.includes(p) ? all.filter(x => x !== p) : [...all, p])}><Check on={installationPurposes.includes(p)} /><span>{featureName(p, L)}{L(" 읽기 권한", " read access")}</span></button>)}</div>
            </details>}
        </> : (method.fields ?? []).map(f => <CredentialField key={f.name} field={f} value={credential[f.name] ?? ""} stored={false}
          onChange={v => { setCredentialsChanged(true); setCredential(all => ({ ...all, [f.name]: v })); }} />)}
        {googleOAuth ? <>
          {googleClient.data && !googleClient.data.locked && (!googleClient.data.configured || editGoogleClient)
            ? <GoogleClientSetup current={googleClient.data} onSaved={() => { setError(null); setEditGoogleClient(false); googleClient.reload(); }}
                onCancel={googleClient.data.configured ? () => setEditGoogleClient(false) : undefined} />
            : googleClient.data?.configured === false ? <Banner tone="bad" icon="alert">{L("서버에 고정된 Google 로그인 앱 설정이 올바르지 않습니다. API 서버의 GCP_OAUTH_CLIENT_ID·GCP_OAUTH_CLIENT_SECRET·GCP_OAUTH_REDIRECT_URI를 확인하세요.",
              "The server's pinned Google sign-in app is invalid. Check GCP_OAUTH_CLIENT_ID, GCP_OAUTH_CLIENT_SECRET and GCP_OAUTH_REDIRECT_URI on the API server.")}</Banner>
            : googleClient.data?.configured ? <p className="ig-hint">{L("Google 로그인 앱이 준비됐습니다. 하단 ‘인증 확인’에서 Google로 이동해 승인합니다.", "The Google sign-in app is ready. Use ‘Authenticate’ below to continue to Google for approval.")}</p> : null}
          {googleClient.data?.configured && googleClient.data.source === "DASHBOARD" && !editGoogleClient
            ? <button type="button" className="link-btn" onClick={() => setEditGoogleClient(true)}>{L("Google 로그인 앱 변경", "Change the Google sign-in app")}</button> : null}
          {googleClient.loading ? <p role="status">{L("Google 로그인 앱 설정 확인 중", "Checking the Google sign-in app")}</p> : null}
          {googleClient.error ? <Banner tone="bad" icon="alert">{L("Google 로그인 앱 설정을 확인하지 못했습니다.", "Could not check the Google sign-in app.")}
            <button type="button" className="link-btn" onClick={googleClient.reload}>{L("다시 확인", "Retry")}</button></Banner> : null}
        </> : null}
        {previewPurposes.length ? <div className="ig-section"><div className="ig-section-head"><h3>{L("기능별 필요한 권한", "Permissions each feature needs")}</h3></div>
          <PermissionPreview d={d} method={method} edition={edition} purposes={previewPurposes} collapsed /></div> : null}
        <SetupGuide steps={guideSteps(d, method, draft?.generated && reusable ? { target: { ...context, auth: draft.public_auth, generated: draft.generated }, children: [], purposes: [] } : null,
          { target: context, aws: idView, openMachine: admin ? () => setMachineOpen(true) : undefined }, L)} onCopy={text => { void navigator.clipboard.writeText(text).then(() => toast(L("복사했습니다", "Copied")),
            () => toast(L("복사하지 못했습니다", "Could not copy"), "bad")); }} />
        <p className="ig-hint">{contentOnly ? L("인증을 확인하면 검사할 대상을 불러와 권한을 확인합니다.", "After authentication, scan targets are listed and their access is checked.")
          : L("인증을 확인한 다음 사용할 기능과 수집 대상을 선택합니다.", "Choose features and collection targets after authentication.")}</p>
        {draft?.authentication && draft.authentication.status !== "GRANTED" ? <Banner tone="bad" icon="alert">{detailText(draft.authentication.detail ?? "AUTHENTICATION_REQUIRED", L)}</Banner> : null}
      </> : <Banner tone="warn" icon="info">{L("이 인증 방식의 자동 대상 조회는 아직 지원하지 않습니다.", "Automatic target discovery is not supported for this sign-in method yet.")}
        <button type="button" className="link-btn" onClick={() => void act(async () => { if (draft) await request("cancel"); onAdvanced(method.id, edition); })}>{L("이 인증 방식으로 계속", "Continue with this sign-in")}</button></Banner>}
      {!authenticationOnly ? <button type="button" className="link-btn" onClick={() => void act(async () => { if (draft) await request("cancel"); onAdvanced(method.id, edition); })}>
        {d.provider === "aws" && method.id === "role" ? L("계정 ID로 직접 연결", "Connect by account ID")
          : L("다른 인증·기존 설정", "Other sign-in and existing setup")}</button> : null}
    </fieldset> : null}
    {step === 2 && authenticationOnly ? <div className="ig-section"><h3>{L("계정 인증 완료", "Account authenticated")}</h3>
      <p>{L("계정 연결을 저장하세요. 콘텐츠 읽기 권한·검사 위치·실행 주기는 이후 콘텐츠 연결에서 확인합니다.", "Save the account connection. Content read access, locations and schedule are configured under content connections.")}</p>
      <TextField label={L("연동 이름", "Integration name")} value={name} onChange={setName} />
    </div> : null}
    {step === 2 && contentOnly ? <div className="ig-section"><p className="ig-hint">{L("인증을 확인했습니다. 검사할 대상을 불러옵니다.", "Authenticated. Listing what can be scanned.")}</p>
      {!working && (error || !autoList || draft?.state !== "AUTHENTICATED") ? <button type="button" className={autoList ? "ghost-btn" : "primary-btn"} onClick={() => void discover()}>
        {method.flow === "gcp_oauth" ? L("Cloud 접근 동의·대상 불러오기", "Approve Cloud access and list targets") : L("대상 다시 불러오기", "List targets again")}</button> : null}</div> : null}
    {step === 2 && !authenticationOnly && !contentOnly ? <div className="ig-section"><h3>{L("사용할 기능", "Features to use")}</h3><div className="ig-feats">
      {(supplemental ? initialPurposes ?? [] : existing ? method.purposes.filter(p => serves(method, p, edition) && (draft?.feature_enabled ?? existing.feature_enabled)?.[p] !== false) : purposesForEdition(d, edition)).map(p => {
        const requiredEdition = d.editions.find(e => e.id === edition && methodsFor(d, [p], e.id).length);
        const available = requiredEdition ? methodsFor(d, [p], requiredEdition.id) : [];
        const extra = requiredEdition?.id !== edition || !serves(method, p, edition) || (p === "remediation"
          && (selectedFeatures.some(x => x !== p) || (d.provider === "github" && method.id === "github_app" && !supplemental)));
        return <div key={p} style={{ display: "grid", gap: 6, minWidth: 0, alignContent: "start" }}><button type="button" className="ig-feat-card" role="checkbox" aria-checked={selectedFeatures.includes(p)}
          data-tip={featureText(p, label(d, L), L, d.provider)}
          disabled={working || Boolean(existing?.plans[p]) || supplemental || Boolean(existing && (p === "remediation" || existing.plans.remediation))}
          onClick={() => {
            if (!available.length) {
              setError(L("이 기능의 인증 방식은 현재 제공되지 않습니다.", "No sign-in method is currently offered for this feature.")); return;
            }
            if (!existing) setPlans({});
            const next = selectedFeatures.includes(p) ? selectedFeatures.filter(x => x !== p) : [...selectedFeatures, p];
            setSelectedFeatures(next); onIntent?.(edition, next);
          }}>
          <Check on={selectedFeatures.includes(p)} /><span className="ig-feat-text"><span className="t">{featureName(p, L)}</span>
            <span className="d">{featureText(p, label(d, L), L, d.provider)}</span>
            <span className="d">{!available.length ? L("현재 제공되는 인증 방식 없음", "No sign-in method currently available")
              : extra ? L(`추가 인증: ${requiredEdition?.id !== edition ? `${label(requiredEdition!, L)} · ` : ""}${label(available[0], L)}${p === "remediation" ? " · 조치 전용 연결" : ""}`,
                `Additional sign-in: ${requiredEdition?.id !== edition ? `${label(requiredEdition!, L)} · ` : ""}${label(available[0], L)}${p === "remediation" ? " · separate acting connection" : ""}`)
                : L("현재 인증으로 권한 확인", "Check access with this sign-in")}</span></span></button>
          <PermissionPreview d={d} method={serves(method, p, edition) ? method : available[0] ?? method} edition={edition} purposes={[p]} collapsed /></div>;
      })}
    </div>{!existing && !supplemental ? <p className="ig-hint">{L("필요한 기능을 함께 고르세요. 다른 인증이 필요한 기능은 현재 설정을 저장한 뒤 같은 흐름에서 이어서 인증합니다.", "Select all needed features. Features requiring another credential continue in this setup after the current selection is saved.")}</p> : null}</div> : null}
    {step === 2 && awsIdentity && draft?.error === "AWS_REGIONS_ACCESS_DENIED" ? <SetupGuide
      steps={guideSteps(d, method, null, { target: context, aws: idView }, L)}
      onCopy={text => { void navigator.clipboard.writeText(text).then(() => toast(L("복사했습니다", "Copied")), () => toast(L("복사하지 못했습니다", "Could not copy"), "bad")); }} /> : null}
    {step === 3 ? <>
      {draft?.discovery_notice ? <Banner tone="warn" icon="info">{detailText(draft.discovery_notice, L)}</Banner> : null}
      <fieldset className="ig-section" disabled={working} style={{ border: 0, padding: 0, minWidth: 0 }}>
        {keptChips}
        <MultiSelectField label={L(contentOnly ? "검사 대상" : "연동 대상", contentOnly ? "Scan targets" : "Targets")} value={targetIds.filter(id => listedTargets.some(t => t.id === id))}
          options={listedTargets.map(t => ({ id: t.id, label: t.label + (t.purposes && !contentOnly ? ` · ${t.purposes.map(p => featureName(p, L)).join(", ")}` : "")
            + (fixedTargets.includes(t.id) ? L(" · 유지", " · Kept") : "") }))}
          tip={L("인증된 신원으로 조회한 계정·조직입니다. 수집할 대상을 고른 뒤 실제 읽기 권한을 확인합니다.", "Accounts or organizations listed using the authenticated identity. Select collection targets, then verify actual read access.")}
          onChange={v => {
            const keep = targetIds.filter(id => !listedTargets.some(t => t.id === id) || fixedTargets.includes(id));
            setTargets([...keep, ...v.filter(id => !keep.includes(id))]); setCheckedChoices(""); setResources([]);
          }} />
        {fixedTargets.length ? <p className="ig-hint">{L("‘유지’ 대상은 이 계정에서 계속 수집하는 기능이 쓰므로 여기서 빠지지 않습니다. 빼려면 계정 연결 설정에서 바꾸세요.",
          "Targets marked ‘Kept’ stay: this account's other features collect from them. Remove them in the account connection's settings.")}</p> : null}
        {targetIds.length > 100 ? <Banner tone="warn" icon="info">{L("한 번에 대상 100개까지 선택할 수 있습니다.", "Choose up to 100 targets per integration.")}</Banner> : null}
        {!listedTargets.length && !working ? <Banner tone="warn" icon="info">{L("조회된 대상이 없습니다. 공유 범위와 목록 조회 권한을 확인하세요.", "No targets were returned. Check sharing and list permissions.")}</Banner> : null}
        {d.provider === "github" && method.id === "github_app" ? <p className="ig-hint">{L("App이 설치된 조직을 여러 개 선택할 수 있습니다. 중지된 설치와 개인 계정은 이 목록에 포함하지 않습니다. 미설치 조직은 GitHub에서 App을 설치한 뒤 목록을 다시 조회하세요. 엔터프라이즈 일괄 설치는 이 연결 저장 후 이어서 설정할 수 있습니다.",
          "Select multiple organizations where this App is installed. Suspended installations and personal accounts are excluded. Install the App on missing organizations in GitHub, then refresh the list. Enterprise bulk installation is available after saving this connection.")}</p> : null}
        {draft?.completeness === "PARTIAL" ? <Banner tone="warn" icon="info">{L("일부 목록만 조회했습니다. 전체 선택은 조회된 항목에만 적용됩니다.", "The list is partial. Select all applies only to loaded items.")}</Banner> : null}
        {draft?.has_more ? <button type="button" className="ghost-btn" disabled={working} onClick={() => void act(async () => setDraft(await request("discover", { more: true })))}>{L("다음 목록 불러오기", "Load more targets")}</button> : null}
        {optionGroups.map(({ purpose: p, fields: options }) => <div className="ig-section" key={p}>
          <div className="ig-section-head"><h3>{optionGroups.length > 1 ? L(`${featureName(p, L)} 옵션`, `${featureName(p, L)} options`) : L("수집 옵션", "Collection options")}</h3></div>
          <FieldGrid fields={options} values={plan(p)} valueReading onChange={(k, v) => { setCheckedChoices(""); setPlans(all => ({ ...all, [p]: { ...plan(p), [k]: v } })); }} /></div>)}
        {gating.some(p => !targetsFor(p).length) ? <p className="ig-hint">{L("선택한 기능마다 대상을 하나 이상 고르세요.", "Choose at least one target for each selected feature.")}</p> : null}
        {unlisted ? <Banner tone="warn" icon="alert">{L(`이 연결이 지금 수집하는 대상 ${unlisted}개가 이번 목록에 없어 계속할 수 없습니다(목록에 없다고 지운 것으로 보지 않습니다). ${draft?.has_more ? "대상을 더 불러오거나 " : ""}공급자에서 설치·권한을 확인하세요. 그 대상을 그만 수집하려면 연동 현황의 '수집 범위·인증 설정' → '유지할 기존 대상'에서 직접 빼세요.`,
          `${unlisted} target${unlisted === 1 ? "" : "s"} this integration collects from ${unlisted === 1 ? "is" : "are"} not in this listing, so this cannot continue (a missing target is not taken as removed). ${draft?.has_more ? "Load more targets, or check" : "Check"} the installation and access at the provider. To stop collecting one, remove it yourself under 'Collection scope and sign-in' → 'Existing targets to keep'.`)}</Banner> : null}
        <p className="ig-hint">{L("하단 버튼을 누르면 선택한 대상·옵션의 권한을 확인하고 목록을 조회합니다. 필수 권한이 확인되면 수집 범위 선택으로 넘어갑니다.", "The button below checks access for the selected targets and options, then lists resources. Collection scope opens once required access is verified.")}</p>
      </fieldset>
      {checkedNow && !working ? <div className="ig-section"><div className="ig-section-head"><h3>{L("필수 권한", "Required access")}</h3></div>
        {outcomes.map(o => <div className="ig-perm-group" key={o.purpose}>
          <span className={cls("ig-result", o.ok ? "ok" : "none")}><Ic name={o.ok ? "checkCircle" : "pause"} size={16} />
            {featureName(o.purpose, L)} · {o.ok ? L("준비됨", "Ready") : L("보류 · 권한 부족", "Held · access missing")}</span>
          <div style={{ marginTop: 6 }}><PermissionPreview d={d} method={method} edition={edition} purposes={[o.purpose]} targets={{ [o.purpose]: targetsFor(o.purpose) }}
            plans={{ [o.purpose]: plan(o.purpose) }} results={draft!.checks!.results} /></div>
          {!o.ok ? <MissingList d={d} purpose={o.purpose} method={method.id} missing={o.missing} targets={targetsFor(o.purpose)} /> : null}
        </div>)}
        {heldNow.length ? <Banner tone="warn" icon="alert">{ready.length
          ? L("일부 기능만 필요한 권한이 확인됐습니다. 준비된 기능만 계속하거나, 권한을 부여한 뒤 다시 확인하세요. 보류된 기능은 나중에 추가할 수 있습니다.",
            "Only some features have their required access. Continue with the ready ones, or grant the access and check again. Held features can be added later.")
          : L("선택한 기능의 필수 권한이 확인되지 않았습니다. 권한을 부여한 뒤 다시 확인하세요.", "Required access for the selected features is not verified. Grant it and check again.")}</Banner> : null}
        {keptHeld.map(o => <div className="ig-perm-group" key={o.purpose}>
          <span className="ig-result none"><Ic name="pause" size={16} />{featureName(o.purpose, L)} · {L("유지 · 권한 부족", "Kept · access missing")}</span>
          <MissingList d={d} purpose={o.purpose} method={method.id} missing={o.missing} targets={targetsFor(o.purpose)} />
        </div>)}
        {keptHeld.length ? <Banner tone="warn" icon="alert">{L("이 계정에서 계속 수집하는 기능의 권한이 확인되지 않아 저장할 수 없습니다. 위 권한을 부여한 뒤 다시 확인하거나, 계정 연결 설정에서 그 대상을 빼세요.",
          "Access for a feature this account keeps collecting is not verified, so this cannot be saved. Grant the access above and check again, or remove that target in the account connection's settings.")}</Banner> : null}
        {heldNow.length || keptHeld.length ? <div className="ig-test">
          {canNarrow ? <button type="button" className="primary-btn" disabled={busy} onClick={() => void inspect(narrowIds, purposes.filter(p => !heldIds.includes(p)))}>
            {L("준비된 기능만 계속", "Continue with ready features")}</button> : null}
          {canPassTargets ? <button type="button" className={canNarrow ? "ghost-btn" : "primary-btn"} disabled={busy} onClick={() => void inspect(passIds)}>
            {L("통과한 대상만 계속", "Continue with passing targets")}</button> : null}
          <button type="button" className="ghost-btn" disabled={busy} onClick={() => void inspect()}>{L("권한 부여 후 다시 확인", "Check again after granting")}</button>
        </div> : null}
      </div> : draft?.checks?.results && !working ? <p className="ig-hint">{L("대상이나 옵션이 바뀌었습니다. 하단 버튼으로 권한을 다시 확인하세요.", "Targets or options changed. Check access again with the button below.")}</p> : null}
      {/* What an admin grants for the chosen features: a credential CreMore made, or the worker's own identity. */}
      {draft?.generated || method.id === "workload_identity" ? <SetupGuide steps={guideSteps(d, method, { target: { ...context, ...targetsFor(purposes[0])[0]?.target,
        auth: draft?.public_auth, generated: draft?.generated ? { ...draft.generated, ...(Array.isArray(draft.generated.aws_roles) ? {
          aws_roles: draft.generated.aws_roles.filter((role: { account_id: string }) => targets.some(t => targetIds.includes(t.id)
            && (t.target.accounts as string[] | undefined)?.includes(role.account_id))) } : {}) } : undefined }, children: [], purposes,
        roots: targets.filter(t => targetIds.includes(t.id)).map(t => ({ purposes: (t.purposes ?? purposes).filter(p => purposes.includes(p)), target: t.target })) },
        { target: context, aws: idView, plans: Object.fromEntries(purposes.map(p => [p, plan(p)])) }, L)}
        onCopy={text => { void navigator.clipboard.writeText(text).then(() => toast(L("복사했습니다", "Copied")), () => toast(L("복사하지 못했습니다", "Could not copy"), "bad")); }} /> : null}
    </> : null}
    {step === 4 ? <>
      {draft?.completeness === "PARTIAL" ? <Banner tone="warn" icon="info">{L("일부 목록만 조회했습니다. 조회된 항목 중에서 수집 범위를 선택하세요.", "Only part of the list was retrieved. Choose scope from the loaded resources.")}</Banner> : null}
      {accessReady && purposes.includes("exposure") ? <div className="ig-section">
        <MultiSelectField label={L(`조회된 검사 대상 ${rows.length}개`, `${rows.length} loaded resources`)} value={resources}
          tip={L("여기서 선택한 리소스만 검사 범위로 승인합니다. 모두 선택은 조회된 항목에만 적용됩니다.", "Only selected resources are approved for scanning. Select all applies only to loaded items.")}
          options={rows.filter(r => pickable(r).ok).map(r => ({ id: r.id, label: r.display_name || r.provider_resource_id }))} onChange={setResources} />
        {selectedRows.filter(r => r.resource_type === "NOTION_DATA_SOURCE").map(database => <MultiSelectField key={database.id}
          label={L(`${database.display_name} · 검사할 행`, `${database.display_name} · rows to scan`)} value={rowIds[database.id] ?? []}
          options={rows.filter(r => r.resource_type === "NOTION_PAGE" && r.source_key === database.source_key
            && r.parent_id === database.provider_resource_id && pickable(r).ok).map(r => ({ id: r.provider_resource_id, label: r.display_name }))}
          onChange={ids => setRowIds(all => ({ ...all, [database.id]: ids }))} />)}
        <p className="ig-hint">{existing ? L("기존 항목의 세부 범위·제외·실행 설정은 유지합니다. 세부 변경은 검사 대상 설정에서 할 수 있습니다.", "Existing scope rules, exclusions and run settings are preserved. Use scan target settings to edit those details.")
          : d.provider === "notion" ? L("선택한 페이지만 검사하며 하위 페이지는 별도로 선택합니다.", "Only selected pages are scanned. Select child pages separately.")
          : L("선택한 항목만 검사 대상으로 저장합니다.", "Only selected items are saved as scan targets.")}</p>
        {!rows.some(r => pickable(r).ok) ? <Banner tone="warn" icon="info">{L("선택할 검사 항목이 없습니다. 서비스의 공유 설정과 리소스 상태를 확인한 뒤 이전 단계에서 대상을 다시 조회하세요.", "No scan resources are available to select. Check sharing and resource status in the service, then return to the previous step to list targets again.")}</Banner> : null}
      </div> : null}
      {!purposes.includes("exposure") ? <div className="ig-section"><h3>{L("수집 대상", "Collection targets")}</h3>
        <p>{targets.filter(t => targetIds.includes(t.id)).map(t => t.label).join(", ")}</p>
        <p className="ig-hint">{L("선택한 계정·조직과 앞 단계의 옵션으로 수집합니다.", "Collection uses the selected accounts or organizations and the options from the previous step.")}</p>
      </div> : null}
      {!accessReady ? <Banner tone="warn" icon="alert">{L("권한 확인이 필요합니다. 이전 단계에서 다시 확인하세요.", "Access needs to be checked. Return to the previous step and check again.")}</Banner> : null}
    </> : null}
    {step === 5 ? <div className="ig-section">
      <TextField label={L("연동 이름", "Integration name")} value={name} onChange={setName}
        tip={L("목록에서 이 연결을 구분할 표시 이름입니다. 공급자의 리소스 이름은 바꾸지 않습니다.", "A display name to identify this integration. It does not rename provider resources.")} />
      <dl className="kv"><dt>{L("기능", "Features")}</dt><dd>{gating.map(p => featureName(p, L)).join(", ")}</dd>
        <dt>{L("대상", "Targets")}</dt><dd>{targets.filter(t => targetIds.includes(t.id)).map(t => t.label).join(", ")}</dd>
        <dt>{L("검사 항목", "Scan resources")}</dt><dd>{resources.length}</dd></dl>
      {keptChips}
      {heldSection}
      {investigationOptions.length ? <div className="ig-section">
        <h3>{L("발견한 자격증명 조사", "Investigate discovered credentials")}</h3>
        <p className="ig-hint">{L("연동 저장 시 적용하며, 이 설치의 모든 AWS 연결에 공통으로 적용됩니다. 기능 사용을 허용하는 설정으로, 계정별 AWS 읽기 권한은 실제 조사 시 확인합니다. 비밀값은 읽지 않습니다.", "Applied when you save, across all AWS connections in this installation. These switches allow investigation features; account-specific AWS read access is checked when an investigation runs. No secret values are read.")}</p>
        {investigations.data ? <AwsInvestigationFields data={investigations.data} keys={investigationOptions} edits={investigationEdits} disabled={working}
          onChange={(key, enabled) => setInvestigationEdits(all => {
            const expected = all[key]?.expected ?? investigations.data![key].switch;
            const next = { ...all };
            if (enabled === expected) delete next[key]; else next[key] = { enabled, expected };
            return next;
          })} /> : !investigations.error ? <p role="status">{L("조사 설정 불러오는 중", "Loading investigation settings")}</p> : null}
        {investigations.error ? <Banner tone="bad" icon="alert">{L("조사 설정을 불러오지 못했습니다.", "Could not load investigation settings.")}
          </Banner> : null}
        <button type="button" className="ghost-btn" disabled={working} onClick={() => { setInvestigationEdits({}); investigations.reload(); }}>
          {L("변경 취소·현재 설정 불러오기", "Discard changes and reload settings")}</button>
      </div> : null}
      {scheduledPurposes.length ? <div className="ig-section"><h3>{L("실행 설정", "Collection settings")}</h3>
        {awsIdentity ? <p className="ig-hint">{L("아래 주기는 이 연결에서 선택한 계정·기능에만 적용됩니다. 새 계정은 수집 대상으로 추가하고 권한을 확인한 뒤 수집합니다. 수동 수집을 선택하면 해당 기능의 자동 수집을 끕니다.", "Schedules below apply only to this connection's selected accounts and features. Add new accounts to its targets and verify access before collecting them. Choose manual collection to turn off a feature's schedule.")}</p> : null}
        {!schedulesAllowed ? <Banner tone="warn" icon="info">{detailText("SCAN_SCHEDULES_DISABLED", L)}</Banner> : null}
        {scheduledPurposes.includes("exposure") ? <SelectField label={L("전체 범위 검사 주기", "Full scope scan schedule")}
          tip={L("브라우저를 닫아도 서버가 선택한 전체 범위를 확인합니다. 변경 없는 파일은 결과를 재사용합니다. 설치 기본값은 환경 설정 > 스캔 시작 조건의 기본 주기와 시작 시각을 따르고, 범위마다 정해진 시각에 시작 시각부터 최대 4시간 뒤(주기가 8시간보다 짧으면 주기의 절반) 사이에 시작합니다.",
            "The server checks the selected scope after the browser closes, reusing results for unchanged files. The installation default follows the default cadence and start time in Settings > What starts a scan; each scope starts at its own fixed time between the start time and up to 4 hours later (half the interval when it is shorter than 8 hours).")}
          value={String(fullSchedule)} onChange={value => setSchedules(all => ({ ...all, "exposure.full_scan_minutes": Number(value) }))}
          options={[...new Set([...(existing ? [-1] : []), INSTALLATION_DEFAULT, ...(schedulesAllowed ? FULL_SCHEDULES : [0]), fullSchedule])].map(minutes => ({
            id: String(minutes), label: minutes === -1 ? L("기존 주기 유지", "Keep existing schedule") : minutes === INSTALLATION_DEFAULT
              ? defaultText(triggers.data?.schedules.enabled === false ? 0 : triggers.data?.schedules.full_scan_default_minutes,
                triggers.data?.schedules.full_scan_start_minute, zone, L)
              : fullScanText(minutes, L) }))} /> : null}
        {scheduledPurposes.map(p => <SelectField key={p} label={p === "exposure" ? L("변경분 검사 주기", "Incremental scan schedule") : L(`${featureName(p, L)} · 수집 주기`, `${featureName(p, L)} · schedule`)}
          tip={L("서버가 이 기능을 자동 수집하는 주기입니다. 수동 수집은 자동 실행을 끕니다. 브라우저를 닫아도 서버의 예약 수집은 계속됩니다.", "How often the server collects this feature. Manual collection turns off its schedule. Scheduled collection continues after the browser closes.")}
          value={String(scheduleOf(p))} onChange={value => setSchedules(all => ({ ...all, [p]: Number(value) }))}
          options={[...new Set([...(existing ? [-1] : []), 0, ...(schedulesAllowed ? [5, 15, 30, 60, 360, 1440, 10080] : []), scheduleOf(p)])].map(minutes => ({
            id: String(minutes), label: minutes === -1 ? L("기존 주기 유지", "Keep existing schedule") : minutes === 0 ? L("수동 수집", "Manual collection")
              : L(`${minutes}분마다`, `Every ${minutes} minutes`) }))} />)}
        {scheduledPurposes.flatMap(p => extraSchedules(p).map(field => <SelectField key={`${p}.${field.name}`}
          label={label(field, L)} tip={field.description ? L(field.description_ko ?? field.description, field.description)
            : L("이 수집만 독립적으로 예약합니다. 0이면 직접 실행할 때만 수집합니다.", "Schedules this collection independently. Zero means manual collection only.")}
          value={String(extraScheduleOf(p, field))} onChange={value => setSchedules(all => ({ ...all, [`${p}.${field.name}`]: Number(value) }))}
          options={[...new Set([0, ...(schedulesAllowed ? [5, 15, 30, 60, 360, 1440, 10080] : []), extraScheduleOf(p, field)])]
            .map(minutes => ({ id: String(minutes), label: minutes === 0 ? L("수동 수집", "Manual collection") : L(`${minutes}분마다`, `Every ${minutes} minutes`) }))} />))}
        {needsScheduleSwitch ? <Banner tone="warn" icon="info">
          {L("설치의 예약 검사 전체 스위치가 꺼져 있습니다. 켜면 주기가 설정된 기존 검사 범위도 자동 실행됩니다.", "The installation's scan schedule switch is off. Enabling it also runs existing scopes with saved schedules.")}
          <button type="button" className="ghost-btn" disabled={busy || !schedulesAllowed} onClick={() => void act(async () => {
            await send("settings/scan-triggers", "PUT", { schedules_enabled: true }); triggers.reload(); saved();
          })}>{L("예약 검사 켜기", "Enable scheduled scans")}</button>
        </Banner> : null}
        {triggers.error ? <Banner tone="bad" icon="alert">{L("예약 검사 설정을 확인하지 못했습니다.", "Could not check the schedule switch.")}</Banner> : null}
        {changeScanChoice ? <label className="set-check"><input type="checkbox" checked={changeScans} onChange={event => setChangeScans(event.target.checked)} />
          <span>{existing ? L("새로 추가한 대상은 변경되면 검사: 변경 감지·큐 알림·웹훅이 알린 바뀐 곳만 검사합니다. 기존 대상은 검사 대상 설정의 값을 그대로 씁니다.",
            "Scan new targets when they change: only what a change feed, a queue notification or a webhook reports as changed is scanned. Existing targets keep the setting in Scan targets.")
            : L("변경되면 검사: 변경 감지·큐 알림·웹훅이 알린 바뀐 곳만 검사합니다", "Scan when it changes: only what a change feed, a queue notification or a webhook reports as changed is scanned")}</span></label> : null}
        <label className="set-check"><input type="checkbox" checked={startNow} onChange={event => setStartNow(event.target.checked)} />
          <span>{L("저장 후 선택한 기능의 최초 수집 실행", "Start initial collection for selected features after saving")}</span></label>
        <p className="ig-hint">{L("자동 수집을 설정하면 최초 실행은 서버의 다음 스케줄 확인 때 시작될 수 있습니다. 이 선택은 저장 직후 수집 요청을 추가합니다. 요청 접수까지 창을 열어 두세요.", "Schedules may start their first run on the next server poll. This option also requests collection immediately after saving. Keep this window open until the request is accepted.")}</p>
      </div> : null}
      {existing ? <Banner tone="warn" icon="info">{L("기존 연동의 대상을 이 선택으로 바꿉니다. 선택에서 빠진 대상의 수집은 중지하고 과거 이력은 보존합니다.", "This selection replaces the integration’s targets. Removed targets stop collecting; their history is kept.")}</Banner> : null}
    </div> : null}
    <div className="modal-foot">
      <button type="button" className="ghost-btn" disabled={busy} data-tip={L("현재 설정 초안을 닫습니다. 이미 저장한 연동은 유지합니다.", "Closes this setup draft. Previously saved integrations are kept.")} onClick={() => void close()}>{L("취소", "Cancel")}</button>
      {step > (existing ? (contentOnly ? 3 : 2) : 1) ? <button type="button" className="ghost-btn" disabled={working} data-tip={L("앞 단계의 설정을 확인하거나 수정합니다. 대상·옵션이 바뀌면 권한을 다시 확인합니다.", "Review or edit the previous step. Changed targets or options require a new access check.")} onClick={() => { setError(null); setStep(contentOnly && step === 3 ? 1 : step - 1); }}>{L("이전", "Back")}</button> : null}
      {step === 1 && !existing ? <button type="button" className="primary-btn" disabled={authDisabled}
        data-tip={L("선택한 방식으로 서버의 연동 신원을 인증합니다. 기능·수집 범위는 다음 단계에서 정합니다.", "Authenticates the server's integration identity using the selected method. Features and collection scope are selected in the following steps.")} onClick={() => void authenticate()}>
        {approving ? L("신원 승인·인증 확인", "Approve identity and authenticate") : appSetup && !reusable ? L("GitHub에서 App 만들기·설치", "Create and install App on GitHub") : method.generated && !reusable ? L("인증키 만들기", "Create sign-in key") : draft?.state === "SETUP_REQUIRED" && reusable
          ? L("키 등록 완료·인증 확인", "Key registered · authenticate") : L("인증 확인", "Authenticate")}</button> : null}
      {step === 2 && authenticationOnly ? <button type="button" className="primary-btn" disabled={working || !name.trim() || draft?.state !== "AUTHENTICATED"}
        onClick={() => void act(async () => { const connection = await request<ProviderConnection>("complete", { name, authentication_only: true });
          forgetDraft(storageKey); saved(); setCompleted(connection);
        })}>{L("계정 연결 저장", "Save account connection")}</button> : null}
      {step === 2 && !authenticationOnly && !contentOnly ? <button type="button" className="primary-btn" disabled={working || !selectedFeatures.length}
        data-tip={L("선택한 기능에 연결할 계정·조직 목록을 조회합니다. 아직 연결을 저장하거나 콘텐츠를 검사하지 않습니다.", "Lists accounts or organizations for the selected features. It does not save the integration or scan content yet.")}
        onClick={() => void discover()}>{method.flow === "gcp_oauth" ? L("Cloud 접근 동의·대상 불러오기", "Approve Cloud access and list targets") : L("대상 불러오기", "List targets")}</button> : null}
      {step === 3 ? <button type="button" className="primary-btn" disabled={working || !targetIds.length || targetIds.length > 100 || unlisted > 0
        || gating.some(p => !targetsFor(p).length || missingRequired(fields(p), plan(p)))}
        data-tip={L("필수 권한을 확인하고 검사 가능한 리소스를 조회합니다. 거절·미확인 권한이 있으면 이 단계에 머뭅니다.", "Checks required access and lists scannable resources. Missing or unverified access keeps you on this step.")}
        onClick={() => void inspect()}>{L("권한 확인·다음", "Check access and continue")}</button> : null}
      {step === 4 ? <button type="button" className="primary-btn" disabled={working || !accessReady || (purposes.includes("exposure") && !resourcesReady)}
        data-tip={L("선택한 범위를 검토하고 다음 단계에서 이름·주기·최초 실행을 설정합니다.", "Review the selected scope, then configure the name, schedule and first collection.")}
        onClick={() => void act(async () => { setDraft(await request("select", { snapshot_id: draft?.snapshot_id, resource_ids: resources, selected_roots: selectedRoots })); setStep(5); })}>{L("선택 검토", "Review selection")}</button> : null}
      {step === 5 ? <button type="button" className="primary-btn" disabled={working || !accessReady || !name.trim() || needsScheduleSwitch || Boolean(investigationOptions.length && (!investigations.data || investigations.error))}
        data-tip={L("선택한 범위와 실행 설정으로 연동을 저장합니다. 최초 수집을 선택했으면 저장 후 서버에 수집을 요청합니다.", "Saves the integration with its selected scope and schedule. If initial collection is selected, requests it after saving.")}
        onClick={() => void act(async () => { const connection = await request<ProviderConnection>("complete", { name, schedules: scheduleBody,
          ...(changeScanChoice ? { change_scans: changeScans } : {}),
          ...(investigationOptions.length ? { aws_investigations: investigationRequest(investigationEdits, purposes) } : {}) }); forgetDraft(storageKey); saved();
          setCompleted(connection);
          if (startNow && scheduledPurposes.length) { setRequests(await collectConnection(connection)); saved(); }
        })}>{startNow && scheduledPurposes.length ? L("연동 저장·수집 시작", "Save integration and collect") : L("연동 저장", "Save integration")}</button> : null}
    </div>
  </Modal>;
}
