"""The provider connection wizard (design 4.4): what, how, permission check, scope and first run.

1. What -- a provider, its edition and the purposes (``exposure``, ``inventory``, ``vault``,
   ``identity``).
2. How -- an auth method in the provider's recommended order, where the connection points
   (``target``) and the credential. Secret fields are sealed on arrival into one envelope
   every purpose shares; a ``vault://`` reference may stand in for it. Records that must exist before the
   check (AWS accounts and their ExternalIds) are created here.
3. Check -- the worker asks the provider, per purpose, whether the credential holds each
   permission that purpose needs (``provider-check`` job); results are stored on the
   connection and never include a secret or a response body.
4. Scope and first run -- ``activate`` creates the records each purpose runs on in the
   stores that already run them; their schedules make the first run (content scope is
   then chosen and approved in the existing catalog and scope screens).

A credential change re-points every owned record at the new envelope and asks for a new
check; disabling stops every owned record.
"""

from __future__ import annotations

import re
import uuid

from cremore.onboarding import catalog, children, sign_in, targets
from cremore.onboarding.store import (
    ProviderConnectionConflict,
    ProviderConnectionStore,
    active_plans,
    atomic,
)

CHECK_JOB = "provider-check"
_TEXT = re.compile(r"[^\x00-\x1f\x7f]{1,120}")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]{0,255}")
_PATH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]{0,255}(?:/[A-Za-z0-9][A-Za-z0-9._~-]{0,255}){0,20}")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")
_VAULT_REF = re.compile(r"vault://[A-Za-z0-9_./-]+")
# Control characters other than tab, line feed and carriage return.
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# One entry of a list field: a name, an ID or a path (a leading or trailing slash kept).
_LIST_ITEM = re.compile(r"/?[A-Za-z0-9._~@+=:-]{1,256}(?:/[A-Za-z0-9._~@+=:-]{1,256}){0,40}/?")
MAX_LIST = 500


class OnboardingError(ValueError):
    """A stable code the wizard can show; ``status`` is the HTTP status it maps to."""

    def __init__(self, code: str, status: int = 422):
        super().__init__(code)
        self.code, self.status = code, status


def _store(repo):
    return ProviderConnectionStore(repo)


def check_digest(record) -> str:
    """Bind access evidence to the edition, credential, targets and requested plans."""
    import hashlib
    import json

    from cremore.onboarding.permissions import access_plan

    subject = [record["provider"], record["edition"], record["auth_method"], record["secret_refs"],
               sorted(record["purposes"]), record["target"],
               {p: access_plan(plan, record=record, purpose=p) for p, plan in (record.get("checks") or {}).get("requested_plans", {}).items()}]
    # Keep legacy evidence valid until an individual feature is paused.
    if record.get("disabled_purposes"):
        subject.append(sorted(record["disabled_purposes"]))
    return hashlib.sha256(json.dumps(subject, sort_keys=True, default=str).encode()).hexdigest()


def _audit(repo, connection_id, actor, action, note=None):
    from cremore.domain.models import FindingEvent

    repo.record_finding_event(FindingEvent(target_type="provider_connection", target_id=uuid.UUID(str(connection_id)),
                                           actor=actor, event_type=action, note=note))


def _field_value(field, value):
    """One target or plan field, shape-checked by its kind; the provider checks meaning."""
    kind = field.get("kind", "text")
    if kind == "bool":
        if not isinstance(value, bool):
            raise OnboardingError(f"FIELD_INVALID:{field['name']}")
        return value
    if kind == "number":
        if type(value) is not int or not field.get("min", 0) <= value <= field.get("max", 10_000_000):
            raise OnboardingError(f"FIELD_INVALID:{field['name']}")
        return value
    if kind == "list":
        values = value if isinstance(value, list) else [v for v in re.split(r"[\s,]+", str(value or "")) if v]
        if len(values) > MAX_LIST or any(not isinstance(v, str) or not _LIST_ITEM.fullmatch(v) for v in values):
            raise OnboardingError(f"FIELD_INVALID:{field['name']}")
        return list(dict.fromkeys(values))
    if kind == "choices":
        allowed = [option["id"] for option in field.get("options") or []]
        if not isinstance(value, list) or any(v not in allowed for v in value):
            raise OnboardingError(f"FIELD_INVALID:{field['name']}")
        return [v for v in allowed if v in value]
    if kind == "multiline":
        # A public certificate or similar block; the provider checks what it must be.
        if not isinstance(value, str) or len(value) > 16384 or _CONTROL.search(value):
            raise OnboardingError(f"FIELD_INVALID:{field['name']}")
        return value.strip()
    if not isinstance(value, str):
        raise OnboardingError(f"FIELD_INVALID:{field['name']}")
    value = value.strip()
    if kind == "choice":
        if value not in [option["id"] for option in field.get("options") or []]:
            raise OnboardingError(f"FIELD_INVALID:{field['name']}")
        return value
    pattern = {"name": _NAME, "id": _ID, "url": None, "text": _TEXT}.get(kind, _PATH)
    if kind == "url":
        from cremore.sources.validation import https_base

        try:
            return https_base(value)
        except ValueError:
            raise OnboardingError(f"FIELD_INVALID:{field['name']}") from None
    if pattern is None or not pattern.fullmatch(value):
        raise OnboardingError(f"FIELD_INVALID:{field['name']}")
    return value


def _fields(fields, given, edition=None, *, what="TARGET", target=None):
    """The declared fields of ``given``: unknown names refused, required ones present.

    A field with ``when`` applies only when the target has one of the named values: plan
    fields are matched against the connection's ``target``, target fields against the
    target fields given before them without ``when`` (``scope`` before ``project``).
    """
    if not isinstance(given, dict):
        raise OnboardingError(f"{what}_INVALID")
    wanted = [field for field in fields if not field.get("editions") or edition in field["editions"]]
    out = {}
    for field in sorted(wanted, key=lambda item: "when" in item):
        if field.get("when") and not catalog.applies(field, target if target is not None else out):
            continue
        value = given.get(field["name"])
        if value in (None, "", []):
            if field.get("required"):
                raise OnboardingError(f"{what}_FIELD_REQUIRED:{field['name']}")
            if "default" in field:
                out[field["name"]] = (field.get("edition_defaults") or {}).get(edition, field["default"])
            continue
        out[field["name"]] = _field_value(field, value)
    unknown = set(given) - {field["name"] for field in wanted}
    unused = {name for name in set(given) - unknown - set(out) if given.get(name) not in (None, "", [])}
    if unknown or unused:
        raise OnboardingError(f"{what}_FIELD_UNKNOWN:{min(unknown | unused)}")
    return out


def _credential(settings, provider, method, given, target=None, *, purposes=()):
    """Seal the declared credential fields or retain a Vault reference."""
    from cremore.secretstore.isolation import credential_binding
    from cremore.secretstore.sealed import SealedSecretError, seal_fields

    binding = credential_binding(provider, target or {}, purposes=purposes, auth_method=method["id"]) \
        if settings.isolated_deployment else None

    given = given if isinstance(given, dict) else {}
    ref = given.get("vault_ref")
    fields = {key: value for key, value in given.items() if key != "vault_ref"}
    declared = {field["name"]: field for field in method.get("fields") or []}
    if ref is not None:
        if method.get("reference") is False:
            # The value would be sent to a server the connection names; a reference could
            # make it any secret the installation stores, so it is sealed on arrival instead.
            raise OnboardingError("CREDENTIAL_REFERENCE_NOT_ALLOWED")
        # The reference stands for the secret fields; public ones (an account e-mail) still come along.
        if (any(not declared.get(name, {}).get("public") for name in fields) or not isinstance(ref, str)
                or not _VAULT_REF.fullmatch(ref) or any(part in (".", "..") for part in ref[8:].split("/"))):
            raise OnboardingError("CREDENTIAL_REFERENCE_INVALID")
        if settings.isolated_deployment:
            try:
                return {"credential": seal_fields(settings.credential_sealing_keys, {"vault_ref": ref}, binding=binding)}
            except SealedSecretError:
                raise OnboardingError("CREDENTIAL_INVALID") from None
        return {"credential": ref}
    if set(fields) - set(declared):
        raise OnboardingError("CREDENTIAL_FIELD_UNKNOWN")
    for name, field in declared.items():
        if not field.get("optional") and not fields.get(name):
            raise OnboardingError(f"CREDENTIAL_FIELD_REQUIRED:{name}")
    if any(not isinstance(value, str) or len(value) > 65536 for value in fields.values()):
        raise OnboardingError("CREDENTIAL_FIELD_INVALID")
    if not declared:
        return {}
    try:
        envelopes = catalog.module(provider).credential(provider, method["id"], dict(fields))
    except ValueError as exc:
        raise OnboardingError(getattr(exc, "code", None) or str(exc).split(":")[0] or "CREDENTIAL_INVALID") from None
    try:
        sealed = {role: seal_fields(settings.credential_sealing_keys, envelope, binding=binding)
                  for role, envelope in (envelopes or {}).items()}
    except SealedSecretError:
        raise OnboardingError("CREDENTIAL_INVALID") from None
    finally:
        for envelope in (envelopes or {}).values():
            envelope.clear()
    return sealed


def _public_fields(method, given) -> dict:
    """Credential fields a method marks ``public`` (an account e-mail): kept in the clear as well,
    for records whose own configuration names them."""
    given = given if isinstance(given, dict) else {}
    out = {}
    for field in method.get("fields") or []:
        value = given.get(field["name"])
        if field.get("public") and isinstance(value, str) and value.strip():
            if not _TEXT.fullmatch(value.strip()):
                raise OnboardingError(f"CREDENTIAL_FIELD_INVALID:{field['name']}")
            out[field["name"]] = value.strip()
    return out


def _method(provider, purposes, method_id, edition=None, *, new_setup=False):
    if new_setup and any(e["id"] == edition and e.get("new_setup") is False
                         for e in catalog.descriptor(provider)["editions"]):
        raise OnboardingError("EDITION_RETIRED_FOR_NEW_CONNECTIONS", 409)
    method = next((m for m in catalog.methods_for(provider, purposes, edition) if m["id"] == method_id), None)
    if method is None:
        raise OnboardingError("AUTH_METHOD_NOT_FOR_PURPOSES")
    if new_setup and method.get("new_setup") is False:
        raise OnboardingError("AUTH_METHOD_RETIRED_FOR_NEW_CONNECTIONS", 409)
    return method


def _purposes(descriptor, given):
    if (not isinstance(given, list) or not given
            or any(not isinstance(p, str) or p not in descriptor["purposes"] for p in given)):
        raise OnboardingError("PURPOSES_INVALID")
    purposes = list(dict.fromkeys(given))
    if "remediation" in purposes and len(purposes) > 1:
        raise OnboardingError("REMEDIATION_NEEDS_ITS_OWN_CONNECTION")
    return purposes


def create(repo, settings, body, actor) -> dict:
    """Steps 1 and 2: a DRAFT provider connection with a sealed credential."""
    body = body if isinstance(body, dict) else {}
    provider = body.get("provider")
    try:
        descriptor = catalog.descriptor(provider)
    except catalog.CatalogError:
        raise OnboardingError("PROVIDER_UNKNOWN") from None
    edition = body.get("edition") or descriptor["editions"][0]["id"]
    if edition not in [item["id"] for item in descriptor["editions"]]:
        raise OnboardingError("EDITION_UNKNOWN")
    purposes = _purposes(descriptor, body.get("purposes"))
    method = _method(provider, purposes, body.get("auth_method"), edition, new_setup=True)
    target = _fields(descriptor.get("target") or [], body.get("target") or {}, edition)
    module = catalog.module(provider)
    validate_target = getattr(module, "target", None)
    if callable(validate_target):
        try:
            target = validate_target(provider, edition, target)
        except ValueError as exc:
            raise OnboardingError(getattr(exc, "code", None) or str(exc).split(":")[0] or "TARGET_INVALID") from None
    refused = sign_in.problem(settings, provider, target, purposes, repo=repo)
    if refused:
        raise OnboardingError(refused, 409)
    name = body.get("name") or _default_name(descriptor, edition, target)
    if not isinstance(name, str) or not _TEXT.fullmatch(str(name).strip()[:120] or "x"):
        raise OnboardingError("NAME_INVALID")
    secret_refs = _credential(settings, provider, method, body.get("credential"), target, purposes=purposes)
    public = _public_fields(method, body.get("credential"))
    if public:
        target = {**target, "auth": public}
    candidate = {"provider": provider, "edition": edition, "name": str(name).strip()[:120], "target": target,
                 "auth_method": method["id"], "secret_refs": secret_refs, "purposes": purposes}
    ready = getattr(module, "ready", None)
    if callable(ready):
        try:
            for root in targets.records_of(candidate):
                ready(repo, settings, root)
        except ValueError as exc:
            raise OnboardingError(getattr(exc, "code", None) or "PROVIDER_NOT_READY", 409) from None
    prepare = getattr(module, "prepare", None)
    try:
        with atomic(repo) as bound:
            record = _store(bound).create(candidate, actor)
            _audit(bound, record["id"], actor, "PROVIDER_CONNECTION_CREATED", provider)
            if callable(prepare):
                for purpose, child in _children_of(prepare(record)):
                    children.create(bound, settings, record, purpose, child, actor)  # records, not views
    except children.ChildError as exc:
        raise OnboardingError(exc.code, exc.status) from None
    return view(repo, _store(repo).get(record["id"]))


def _children_of(described):
    for child in described or []:
        purpose = child.get("purpose")
        if purpose not in catalog.PURPOSES:
            raise children.ChildError("CHILD_PURPOSE_UNKNOWN")
        yield purpose, child


def _default_name(descriptor, edition, target) -> str:
    """"GitHub · acme", "Amazon Web Services · 222222222222 +1": the first thing the target names."""
    for value in target.values():
        if isinstance(value, str) and value:
            return f"{descriptor['label']} · {value}"[:120]
        if isinstance(value, list) and value:
            more = f" +{len(value) - 1}" if len(value) > 1 else ""
            return f"{descriptor['label']} · {value[0]}{more}"[:120]
    label = next((item["label"] for item in descriptor["editions"] if item["id"] == edition), edition)
    return f"{descriptor['label']} · {label}"[:120]


def get(repo, connection_id) -> dict:
    try:
        record = _store(repo).get(connection_id)
    except (ValueError, TypeError):
        record = None
    if record is None or record["provider"] not in catalog.providers():
        raise OnboardingError("PROVIDER_CONNECTION_NOT_FOUND", 404)
    return record


def request_check(repo, connection_id, actor, body=None) -> dict:
    """Step 3: queue the worker's permission check of every purpose."""
    with atomic(repo) as bound:
        return _request_check(bound, connection_id, actor, body)


def _request_check(repo, connection_id, actor, body=None) -> dict:
    from cremore.domain.models import ScanJob

    record = get(repo, connection_id)
    if record["status"] == "DISABLED":
        raise OnboardingError("PROVIDER_CONNECTION_DISABLED", 409)
    if not record["purposes"]:
        # An authentication-only owner has no collection permission to check.
        # Adding content reauthenticates it through the bound onboarding session.
        raise OnboardingError("PURPOSES_INVALID")
    given = (body or {}).get("plans")
    if given is None:
        given = dict(record.get("plans") or {})
        for purpose in record["purposes"]:
            if purpose not in given:
                try:
                    given[purpose] = targets.normalize_plan(record, purpose, {})
                except OnboardingError:
                    pass  # missing choices: inspect access, but do not authorize activation
    if not isinstance(given, dict) or set(given) - set(record["purposes"]):
        raise OnboardingError("PURPOSES_INVALID")
    plans = {purpose: targets.normalize_plan(record, purpose, plan) for purpose, plan in given.items()}
    expected = _expected(body or {}, record)
    if expected != record["revision"]:
        raise OnboardingError("PROVIDER_CONNECTION_CHANGED", 409)
    if plans != (record.get("checks") or {}).get("requested_plans"):
        record = {**record, "checks": {**record["checks"], "requested_plans": plans, "stale": True}}
    running = _running_check(repo, record)
    if running is not None:
        return view(repo, record)
    job = repo.enqueue_job(ScanJob(kind=CHECK_JOB, payload={"provider_connection_id": str(record["id"]),
                                                             "digest": check_digest(record)}))
    checks = {**record["checks"], "job_id": str(job.id), "requested_at": job.created_at.isoformat()}
    status = "CHECKING" if record["status"] in ("DRAFT", "CHECKED", "CHECKING") else record["status"]
    record = _store(repo).update(record["id"], record["revision"], actor, checks=checks, status=status)
    _audit(repo, record["id"], actor, "PROVIDER_CONNECTION_CHECK_REQUESTED", str(job.id))
    return view(repo, record)


def _running_check(repo, record):
    job_id = (record.get("checks") or {}).get("job_id")
    if not job_id:
        return None
    job = repo.get_job(uuid.UUID(job_id))
    return job if (job is not None and job.status in ("QUEUED", "RUNNING")
                   and job.payload.get("digest") == check_digest(record)) else None


def update_purposes(repo, settings, connection_id, body, actor) -> dict:
    """Revise the features to check with this identity; active plans and their records keep running."""
    record = get(repo, connection_id)
    if record["status"] == "DISABLED":
        raise OnboardingError("PROVIDER_CONNECTION_DISABLED", 409)
    body = body if isinstance(body, dict) else {}
    expected = _expected(body, record)
    if expected != record["revision"]:
        raise OnboardingError("PROVIDER_CONNECTION_CHANGED", 409)
    purposes = _purposes(catalog.descriptor(record["provider"]), body.get("purposes"))
    if set(record["plans"]) - set(purposes):
        raise OnboardingError("ACTIVE_PURPOSE_CANNOT_BE_REMOVED", 409)
    _method(record["provider"], purposes, record["auth_method"], record["edition"])
    refused = sign_in.problem(settings, record["provider"], record["target"], purposes,
                              repo=repo, excluding=record["id"])
    if refused:
        raise OnboardingError(refused, 409)
    candidate = {**record, "purposes": purposes}
    ready = getattr(catalog.module(record["provider"]), "ready", None)
    if callable(ready):
        try:
            for root in targets.records_of(candidate):
                ready(repo, settings, root)
        except ValueError as exc:
            raise OnboardingError(getattr(exc, "code", None) or "PROVIDER_NOT_READY", 409) from None
    if set(purposes) == set(record["purposes"]):
        return view(repo, record)
    try:
        with atomic(repo) as bound:
            record = _store(bound).update(record["id"], expected, actor, purposes=purposes,
                status="ACTIVE" if record["plans"] else "DRAFT",
                checks={**record["checks"], "stale": True, "job_id": None, "requested_at": None})
            _audit(bound, record["id"], actor, "PROVIDER_CONNECTION_PURPOSES_CHANGED", ",".join(purposes))
    except ProviderConnectionConflict as exc:
        raise OnboardingError(str(exc), 409) from None
    return view(repo, record)


def activate(repo, settings, connection_id, body, actor) -> dict:
    """Step 4: create what each chosen purpose runs on; schedules then make the first run."""
    record = get(repo, connection_id)
    if record["status"] not in ("CHECKED", "ACTIVE"):
        raise OnboardingError("PROVIDER_CONNECTION_NOT_CHECKED", 409)
    checks = record["checks"] or {}
    if checks.get("stale") or (checks.get("digest") and checks["digest"] != check_digest(record)):
        raise OnboardingError("PROVIDER_CONNECTION_NOT_CHECKED", 409)
    plans = (body or {}).get("purposes") if isinstance(body, dict) else None
    if not isinstance(plans, dict) or not plans or set(plans) - set(record["purposes"]):
        raise OnboardingError("PURPOSES_INVALID")
    active = set(record.get("plans") or {})
    for purpose in plans:
        if purpose in active:
            raise OnboardingError(f"PURPOSE_ALREADY_ACTIVE:{purpose}", 409)
    # A draft made before people began signing in through the company IdP meets the rule here.
    refused = sign_in.problem(settings, record["provider"], record["target"], list(plans), repo=repo, excluding=record["id"])
    if refused:
        raise OnboardingError(refused, 409)
    plans = {purpose: targets.normalize_plan(record, purpose, plan) for purpose, plan in plans.items()}
    from cremore.onboarding.permissions import require

    require(record, plans)
    module = catalog.module(record["provider"])
    created, saved = [], {}
    # Every purpose's records, or none: a retry never meets half of an earlier attempt.
    try:
        with atomic(repo) as bound:
            before = _described(module, record, active_plans(record))
            for purpose, plan in plans.items():
                # Each purpose sees the ones activated before it in this same call, and every
                # plan this call asks for (one record may serve two purposes).
                current = {**record, "plans": {**active_plans(record), **saved}, "activating": plans}
                described = targets.described(module, current, purpose, plan)
                for child_purpose, child in _children_of(described):
                    if child["kind"] not in ("metadata", "coverage"):
                        created.extend(children.create(bound, settings, record, child_purpose, child, actor))
                saved[purpose] = plan
            after = _described(module, record, {**active_plans(record), **saved})
            reconciled = children.update(bound, settings, record, before, after, actor)
            created.extend(item for item in reconciled if "enabled" not in item)
            record = _store(bound).update(record["id"], record["revision"], actor, status="ACTIVE",
                                          plans={**(record.get("plans") or {}), **saved})
            _audit(bound, record["id"], actor, "PROVIDER_CONNECTION_ACTIVATED", ",".join(sorted(plans)))
    except children.ChildError as exc:
        raise OnboardingError(exc.code, exc.status) from None
    except ProviderConnectionConflict as exc:
        raise OnboardingError(str(exc), 409) from None
    except ValueError as exc:
        raise OnboardingError(getattr(exc, "code", None) or str(exc).split(":")[0] or "PLAN_INVALID") from None
    return {**view(repo, record), "created": created}


def update_plan(repo, settings, connection_id, purpose, body, actor) -> dict:
    """Change an active purpose's plan (types, options, schedule); its collections follow from their next run."""
    record = get(repo, connection_id)
    if record["status"] != "ACTIVE":
        raise OnboardingError("PROVIDER_CONNECTION_NOT_ACTIVE", 409)
    plans = record.get("plans") or {}
    if purpose not in plans:
        raise OnboardingError(f"PURPOSE_NOT_ACTIVE:{purpose}", 409)
    body = body if isinstance(body, dict) else {}
    expected = _expected(body, record)
    plan = targets.normalize_plan(record, purpose, body.get("plan"))
    if expected != record["revision"]:
        raise OnboardingError("PROVIDER_CONNECTION_CHANGED", 409)
    if plan == plans[purpose]:
        return {**view(repo, record), "changed": []}
    from cremore.onboarding.permissions import reductions_only, require

    if not reductions_only(plans[purpose], plan, record=record, purpose=purpose):
        require(record, {purpose: plan})
    changed_plans = {**plans, purpose: plan}
    module = catalog.module(record["provider"])
    try:
        before = _described(module, record, active_plans(record))
        after = _described(module, record, active_plans({**record, "plans": changed_plans}))
        with atomic(repo) as bound:
            record = _store(bound).update(record["id"], expected, actor, plans=changed_plans)
            changed = children.update(bound, settings, record, before, after, actor)
            _audit(bound, record["id"], actor, "PROVIDER_CONNECTION_PLAN_CHANGED", purpose)
    except children.ChildError as exc:
        raise OnboardingError(exc.code, exc.status) from None
    except ProviderConnectionConflict as exc:
        raise OnboardingError(str(exc), 409) from None
    except ValueError as exc:
        raise OnboardingError(getattr(exc, "code", None) or str(exc).split(":")[0] or "PLAN_INVALID") from None
    return {**view(repo, record), "changed": changed}


def _described(module, record, plans):
    """What choosing every purpose of ``plans`` in one step 4 describes, so a record two
    purposes share (one GCP project collection) is described once, with both plans."""
    out, saved = [], {}
    for purpose, plan in plans.items():
        # Validate target-v2 against all configured purposes before narrowing
        # provider-facing capabilities to features that currently run.
        for root in targets.records_of(record, purpose):
            current = {**root, "purposes": [p for p in root["purposes"] if p in plans],
                       "plans": saved, "activating": plans}
            out.extend(_children_of(targets.described(module, current, purpose, plan)))
        saved = {**saved, purpose: plan}
    return out


def set_feature(repo, settings, connection_id, purpose, body, actor):
    """Pause or resume one configured feature without discarding its plan or evidence."""
    from cremore.coverage.errors import CoverageError

    body = body if isinstance(body, dict) else {}
    if type(body.get("enabled")) is not bool:
        raise OnboardingError("ENABLED_INVALID")
    if type(body.get("expected_revision")) is not int:
        raise OnboardingError("EXPECTED_REVISION_INVALID")
    try:
        with atomic(repo) as bound:
            record = get(bound, connection_id)
            if body["expected_revision"] != record["revision"]:
                raise OnboardingError("PROVIDER_CONNECTION_CHANGED", 409)
            if purpose not in record["plans"]:
                raise OnboardingError(f"PURPOSE_NOT_ACTIVE:{purpose}", 409)
            disabled = set(record.get("disabled_purposes") or [])
            enabled = body["enabled"]
            if enabled == (purpose not in disabled):
                return view(bound, record)
            if enabled:
                if record["status"] == "DISABLED":
                    raise OnboardingError("PROVIDER_CONNECTION_DISABLED", 409)
                from cremore.onboarding.permissions import require

                require(record, {purpose: record["plans"][purpose]})
                refused = sign_in.problem(settings, record["provider"], record["target"], [purpose],
                                          repo=bound, excluding=record["id"])
                if refused:
                    raise OnboardingError(refused, 409)
                disabled.remove(purpose)
            else:
                disabled.add(purpose)
            candidate = {**record, "disabled_purposes": sorted(disabled)}
            checks = {**record["checks"], "job_id": None, "requested_at": None}
            checks["stale"] = not enabled
            if enabled:
                checks["digest"] = check_digest(candidate)
            saved = _store(bound).update(record["id"], record["revision"], actor,
                disabled_purposes=sorted(disabled), checks=checks)
            changed = children.reconcile_features(bound, settings, record, saved, actor)
            _audit(bound, record["id"], actor,
                "PROVIDER_CONNECTION_FEATURE_ENABLED" if enabled else "PROVIDER_CONNECTION_FEATURE_DISABLED", purpose)
            return {**view(bound, saved), "changed": changed}
    except children.ChildError as exc:
        raise OnboardingError(exc.code, exc.status) from None
    except CoverageError as exc:
        raise OnboardingError(str(exc), 409) from None
    except ProviderConnectionConflict as exc:
        raise OnboardingError(str(exc), 409) from None


def replace_targets(repo, settings, record, candidate, plans, actor, *, reduction=False):
    """One credential owner keeps its history while selected roots change atomically."""
    if record["provider"] == "aws" or record["status"] != "ACTIVE":
        raise OnboardingError("TARGET_EDIT_NOT_SUPPORTED", 409)
    if set(active_plans(record)) - set(plans):
        raise OnboardingError("TARGET_EDIT_KEEP_FEATURES", 409)
    disabled = set(record.get("disabled_purposes") or [])
    selected_plans = {p: plan for p, plan in plans.items() if p not in disabled}
    if not reduction:
        from cremore.onboarding.permissions import require

        require(candidate, selected_plans)
    candidate, plans = _retain_paused_targets(record, candidate, selected_plans)
    refused = sign_in.problem(settings, record["provider"], candidate["target"], list(selected_plans), repo=repo, excluding=record["id"])
    if refused:
        raise OnboardingError(refused, 409)
    module = catalog.module(record["provider"])
    before = _described(module, record, active_plans(record))
    after = _described(module, candidate, active_plans({**record, "plans": plans}))
    try:
        with atomic(repo) as bound:
            saved = _store(bound).update(record["id"], record["revision"], actor, target=candidate["target"],
                name=candidate.get("name", record["name"]), plans=plans, purposes=list(plans),
                checks={**candidate["checks"], **({"stale": True} if reduction else {})})
            changed = children.reconcile_targets(bound, settings, saved, before, after, actor)
            _audit(bound, record["id"], actor, "PROVIDER_CONNECTION_TARGETS_CHANGED")
            return {**view(bound, saved), "changed": changed}
    except children.ChildError as exc:
        raise OnboardingError(exc.code, exc.status) from None


def _retain_paused_targets(record, candidate, plans):
    """Merge unchanged paused targets with freshly checked active selections.

    Target IDs may change when a single target becomes explicit roots. Only the
    already checked active root's answers move to its equivalent new ID.
    """
    disabled = set(record.get("disabled_purposes") or []) & set(record["plans"])
    if not disabled:
        return candidate, plans
    roots, remap = {}, {}
    for source, purposes in ((record, disabled), (candidate, set(plans))):
        for root in targets.records_of(source):
            chosen = [p for p in root["purposes"] if p in purposes]
            if not chosen:
                continue
            target = {k: v for k, v in root["target"].items() if k not in {"auth", "generated"}}
            rid = targets.target_id(target)
            entry = roots.setdefault(rid, {"id": rid, "target": target, "purposes": []})
            entry["purposes"] = list(dict.fromkeys([*entry["purposes"], *chosen]))
            if source is candidate:
                remap[root.get("target_id")] = rid
    if not roots or len(roots) > 100:
        raise OnboardingError("ONBOARDING_TARGETS_INVALID")
    merged_plans = {**{p: plan for p, plan in record["plans"].items() if p in disabled}, **plans}
    target = {k: v for k, v in record["target"].items() if k in {"auth", "generated"}}
    target.update(version=2, roots=list(roots.values()))
    checks = dict(candidate.get("checks") or {})
    checks["results"] = {purpose: {**result, "items": [
        {**item, "target_id": remap[item.get("target_id")]} if item.get("target_id") in remap else dict(item)
        for item in result.get("items") or []]}
        for purpose, result in checks.get("results", {}).items() if purpose in plans}
    merged = {**candidate, "target": target, "purposes": list(merged_plans), "plans": merged_plans,
              "disabled_purposes": sorted(disabled), "checks": checks}
    if checks.get("digest"):
        checks["digest"] = check_digest(merged)
    return merged, merged_plans


def remove_targets(repo, settings, connection_id, body, actor):
    """Removing selected roots needs no provider access, but never adds a root."""
    record = get(repo, connection_id)
    if _expected(body, record) != record["revision"]:
        raise OnboardingError("PROVIDER_CONNECTION_CHANGED", 409)
    roots = record["target"].get("roots") if record["target"].get("version") == 2 else None
    ids = body.get("target_ids")
    if (not roots or not isinstance(ids, list) or not ids or any(not isinstance(i, str) for i in ids)
            or len(ids) != len(set(ids)) or set(ids) - {r["id"] for r in roots}):
        raise OnboardingError("ONBOARDING_TARGETS_INVALID")
    candidate = {**record, "target": {**record["target"], "roots": [r for r in roots if r["id"] in ids]}}
    return replace_targets(repo, settings, record, candidate, record["plans"], actor, reduction=True)


def set_credential(repo, settings, connection_id, body, actor) -> dict:
    """A new credential for every purpose: owned records are re-pointed and a check is queued."""
    record = get(repo, connection_id)
    body = body if isinstance(body, dict) else {}
    method_id = body.get("auth_method") or record["auth_method"]
    method = _method(record["provider"], record["purposes"], method_id, record["edition"],
                     new_setup=method_id != record["auth_method"])
    target = {key: value for key, value in record["target"].items() if key != "auth"}
    secret_refs = _credential(settings, record["provider"], method, body.get("credential"), target,
                              purposes=record["purposes"])
    public = _public_fields(method, body.get("credential"))
    if public:
        target["auth"] = public
    note = method["id"]
    if ((method["id"] != record["auth_method"] or target.get("auth") != record["target"].get("auth"))
            and _store(repo).children(record["id"])):
        # What the records were built for (access mode, login role, auth type) is fixed once they
        # exist; a new connection takes them over from this one after it is disabled.
        raise OnboardingError("AUTH_SETTINGS_FIXED_WHILE_IN_USE", 409)
    try:
        # The earlier credential's renewal (a certificate's, a token's rotation) says nothing about this one.
        checks = {**(record["checks"] or {}), "stale": True, "renewal": None}
        record = _store(repo).update(record["id"], _expected(body, record), actor, secret_refs=secret_refs,
                                     auth_method=method["id"], target=target, checks=checks)
    except ProviderConnectionConflict as exc:
        raise OnboardingError(str(exc), 409) from None
    failed = children.repoint(repo, record, actor)
    _audit(repo, record["id"], actor, "PROVIDER_CONNECTION_CREDENTIAL_CHANGED", note)
    view_ = request_check(repo, record["id"], actor)
    return {**view_, "not_updated": failed}


def _expected(body, record):
    expected = body.get("expected_revision")
    if expected is None:
        return record["revision"]
    if type(expected) is not int:
        raise OnboardingError("EXPECTED_REVISION_INVALID")
    return expected


def rename(repo, connection_id, body, actor) -> dict:
    record = get(repo, connection_id)
    name = (body or {}).get("name") if isinstance(body, dict) else None
    if not isinstance(name, str) or not _TEXT.fullmatch(name.strip() or "\x00"):
        raise OnboardingError("NAME_INVALID")
    try:
        record = _store(repo).update(record["id"], _expected(body, record), actor, name=name.strip())
    except ProviderConnectionConflict as exc:
        raise OnboardingError(str(exc), 409) from None
    return view(repo, record)


def set_enabled(repo, connection_id, enabled: bool, actor, settings=None) -> dict:
    record = get(repo, connection_id)
    if enabled:
        wanted = "ACTIVE" if record.get("plans") else "CHECKED" if (
            (record["checks"] or {}).get("results") or (record["checks"] or {}).get("authentication_only")) else "DRAFT"
    else:
        wanted = "DISABLED"
    if enabled and record["status"] != "DISABLED":
        return view(repo, record)
    # A people directory stopped before people began signing in through the company IdP meets the rule again.
    refused = sign_in.problem(settings, record["provider"], record["target"], list(active_plans(record)),
                              repo=repo, excluding=record["id"]) if enabled and settings is not None else None
    if refused:
        raise OnboardingError(refused, 409)
    failed = children.set_enabled(repo, record, enabled, actor)
    record = _store(repo).update(record["id"], record["revision"], actor, status=wanted)
    _audit(repo, record["id"], actor, "PROVIDER_CONNECTION_ENABLED" if enabled else "PROVIDER_CONNECTION_DISABLED")
    return {**view(repo, record), "not_updated": failed}


def delete(repo, connection_id, actor) -> None:
    record = get(repo, connection_id)
    try:
        _store(repo).delete(record["id"])
    except ProviderConnectionConflict as exc:
        raise OnboardingError(str(exc), 409) from None
    _audit(repo, record["id"], actor, "PROVIDER_CONNECTION_DELETED")


def _iso(value):
    return value.isoformat() if hasattr(value, "isoformat") else value


def _marks(record) -> set:
    """What the last check of this very credential says it is (cremore.onboarding.check.credential_marks)."""
    checks = record.get("checks") or {}
    if checks.get("stale") or checks.get("digest") != check_digest(record):
        return set()  # a check of an earlier credential says nothing about this one
    return set(checks.get("credential_marks") or [])


def shared_credentials(records) -> dict:
    """Connection id -> the running connections on the other side that hold its credential: a remediation
    connection and one that scans or collects with the same credential. Shown, never refused (as AWS shows
    ``same_as_scanner``): the daily collection would open a credential that may revoke."""
    running = [(record, _marks(record)) for record in records if record["status"] != "DISABLED"]
    out = {}
    for acting, marks in running:
        if "remediation" not in acting["purposes"] or not marks:
            continue
        for other, theirs in running:
            if "remediation" not in other["purposes"] and marks & theirs:
                out.setdefault(acting["id"], []).append({"id": str(other["id"]), "name": other["name"]})
                out.setdefault(other["id"], []).append({"id": str(acting["id"]), "name": acting["name"]})
    return out


def view(repo, record, *, expand=True, shared=None) -> dict:
    """The API view: never a secret reference, only which roles hold a credential."""
    from cremore.onboarding.permissions import blockers

    if shared is None:  # a connection without marks shares with nobody: no need to read the others
        shared = shared_credentials(_store(repo).list()) if _marks(record) else {}
    descriptor = catalog.descriptor(record["provider"])
    method = next((m for m in descriptor["auth_methods"] if m["id"] == record["auth_method"]), {})
    links = _store(repo).children(record["id"])
    checks = dict(record.get("checks") or {})
    status = record["status"]
    if status == "CHECKING" and checks.get("job_id"):
        status, checks = _ended_check(repo, record, checks)
    return {
        "id": str(record["id"]), "provider": record["provider"], "edition": record["edition"],
        "name": record["name"], "status": status, "revision": record["revision"],
        "purposes": list(record["purposes"]),
        "feature_enabled": {purpose: purpose in active_plans(record) for purpose in record.get("plans") or {}},
        "target": dict(record["target"]),
        "plans": {purpose: dict(plan) for purpose, plan in (record.get("plans") or {}).items()},
        "auth_method": record["auth_method"], "renewal": method.get("renewal"),
        "credential": {"roles": sorted(record["secret_refs"]),
                       "reference": any(str(ref).startswith("vault://") for ref in record["secret_refs"].values()),
                       # Connections on the other side (acting / collecting) that hold the same credential.
                       "shared_with": shared.get(record["id"], [])},
        "checks": {"results": checks.get("results") or {}, "checked_at": checks.get("checked_at"),
                   "authentication_only": checks.get("authentication_only") is True and not record["plans"],
                   "blockers": blockers(record, checks.get("requested_plans") or record.get("plans") or {}),
                   "requested_plans": checks.get("requested_plans") or {},
                   "requested_at": checks.get("requested_at"), "job_id": checks.get("job_id"),
                   "stale": bool(checks.get("stale")) or (bool(checks.get("digest"))
                                                           and checks.get("digest") != check_digest(record)),
                   "error": checks.get("error"),
                   # A credential the worker renews itself (cremore.onboarding.renewal): how the last attempt went.
                   "renewal": {key: value for key, value in (checks.get("renewal") or {}).items() if key != "keep"}
                   or None},
        "children": [children.describe(repo, link) for link in links] if expand
        else [{"kind": link["kind"], "id": link["child_id"], "purpose": link["purpose"]} for link in links],
        "created_by": record["created_by"], "created_at": _iso(record["created_at"]),
        "updated_by": record["updated_by"], "updated_at": _iso(record["updated_at"]),
    }


def _ended_check(repo, record, checks):
    """A check whose job ended without storing an answer (failed, withdrawn, or lost) reads as a failed
    check, the way a check that could not open its credential is stored, never as checking for ever."""
    from cremore.domain.models import ACTIVE_JOB_STATUSES
    from cremore.onboarding.check import evaluate
    from cremore.scanning.scope import job_error_code

    job = repo.get_job(uuid.UUID(checks["job_id"]))
    if job is not None and job.status in ACTIVE_JOB_STATUSES:
        return "CHECKING", checks
    error = (job_error_code(job) if job is not None else None) or "PROVIDER_CHECK_ENDED_WITHOUT_RESULT"
    try:
        results = evaluate(record, None, None, error=error)
    except Exception:  # noqa: BLE001 -- the permissions could not be listed: say only that the check ended
        results = {}
    ended = job.finished_at if job is not None and job.finished_at else None
    return "CHECKED", {**checks, "results": results, "error": error, "stale": False, "digest": check_digest(record),
                       "checked_at": ended.isoformat() if ended else checks.get("requested_at")}


def list_views(repo) -> list[dict]:
    supported = catalog.providers()
    records = [record for record in _store(repo).list() if record["provider"] in supported]
    shared = shared_credentials(records)
    return [view(repo, record, expand=False, shared=shared) for record in records]
