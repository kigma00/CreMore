"""The providers the connection wizard offers, from each provider library's onboarding module.

A module listed in ``MODULES`` defines:

``DESCRIPTORS``: one dict per wizard provider --
    ``provider`` (unique id), ``label``/``label_ko``, ``category`` (code, cloud, saas, vault, identity),
    ``editions`` [{id, label, label_ko, origin?: bool}],
    ``target`` [{name, label, label_ko, kind, required?, editions?, hint?}] -- where the connection points,
    never secret,
    ``purposes`` {exposure|inventory|vault|identity|remediation: {permissions: [{id, label, label_ko, methods?, option?,
    unless?}], plan?: [{name, kind, label, label_ko, ...}]}} -- what each use needs (``methods``: only for these auth
    methods; ``option``: only while that bool plan choice is on, ``unless``: only while it is off or not offered --
    the check still answers it) and what step 4 asks (a plan field's ``edition_defaults`` {edition: value} replaces
    its ``default`` in those editions),
    ``auth_methods`` [{id, label, label_ko, renewal, purposes, fields, advanced?, editions?, purpose_editions?,
    reference?, reference_keys?, new_setup?}] in recommended order: the first method that serves a purpose
    (in the chosen edition) is the one the wizard recommends; ``purpose_editions`` {purpose: [edition]} narrows the
    editions a method serves one of its purposes in. ``reference: False`` refuses a ``vault://`` reference in place
    of the fields; otherwise ``reference_keys`` names the keys that KV entry holds (``["token"]`` unless given).
    ``replaced_by`` (optional): the provider new connections are made with instead; existing ones keep running.
``credential(provider, method, fields) -> {role: envelope}``: the credential fields as the envelope(s) to
    seal; ``"credential"`` is the one every use shares.
``check(connection, purpose, secrets, context) -> [{permission, status, detail?}]``: runs in the worker.
``credential_identity(connection, secrets, context) -> [str] | None`` (optional, runs in the worker's check): what
    acts, when that is not the stored token itself -- a GitHub App, a Google account, the worker's own ADC -- so one
    credential that both collects and acts is told (cremore.onboarding.check.credential_marks); None: the token.
``children(connection, purpose, plan) -> [child]``: the records a purpose needs (``cremore.onboarding.children``);
    ``connection["activating"]`` holds every plan the same step 4 call asks for. A collection's name comes
    from the target alone: a changed plan finds the collections it describes by kind, provider and name.
A target or plan field, a permission, an inventory type or a scan location may carry ``when: {target field:
    [values]}``: it applies only to a target whose field has one of those values (a GitLab instance, a GCP
    organization); ``"*"`` stands for any value (an Azure DevOps organization named at all).
``purposes.inventory.types`` (optional): the credential types the inventory lists --
    [{id, label, label_ko, description?, description_ko?, permission? (a permission id of the purpose),
    credential_type? (the code a listed item takes when nothing more specific names it), editions?,
    support, reasons, match}]. ``support`` is one of Y (the collector keeps the value the API returns),
    P (only under a condition) or N (the API does not return it) for each of ``INVENTORY_FIELDS`` in order;
    ``reasons`` {field: [ko, en]} says why for every P and N. ``match`` lists alternatives, each a set of
    conditions on a listed item -- ``provider`` (the collection's provider, one or a list), ``prefix`` or
    ``contains`` (of the object id), ``kind`` (object kind), ``fact`` + ``in`` (a fact, dotted into objects, equal to or a list
    containing one of the values), ``credential_type`` (codes) -- that must all hold.
    A type may carry ``when`` (target conditions, as a field) and ``plan``: the ways it is collected, the first one that
    applies deciding -- ``{always: true, when?, editions?}`` (always listed there), ``{field}`` (a bool plan field turns it
    on, or a list plan field lists what to read) or ``{field, option}`` (an option of a choices plan field). A type with
    ``plan`` and no binding that applies is not listed for that target.
``purposes.exposure.scans`` (optional): what an exposure scan reads -- [{id, label, label_ko, description?,
    description_ko?, editions?}], shown as the scan's locations.
``prepare(connection) -> [child]`` (optional): records that must exist before the check (AWS ExternalIds).
``plan_problem(roots, purpose, plan) -> code | None`` (optional): a refusal of a normalized plan judged against every
    target at once (cremore.onboarding.targets.normalize_plan), such as AWS secret ARNs outside all the accounts;
    ``children`` sees one target at a time.
``collection_identity_purpose(spec, purpose)`` (optional): canonical purpose when several features share
    one durable collection (GCP project inventory and vault). Other target coordinates remain unchanged.
``ready(repo, settings, connection)`` (optional): refuses, before anything is stored, a connection the
    installation cannot take yet (AWS without an approved scanner identity).
``sign_in_target(provider, issuer) -> dict | None`` (an IdP that reads people): the target fields the console's
    sign-in issuer names, as ``target`` normalizes them, or None when it is not this IdP's. On a team install a
    people directory must be that target (cremore.onboarding.sign_in).

Registration is explicit, as for metadata collectors: a provider library is never discovered.
"""

from __future__ import annotations

import re
from importlib import import_module

# remediation: a credential that may change what the inventory lists (disable, revoke), used only by an approved
# action plan (cremore.remediation.provider_actions); it creates no collection.
PURPOSES = ("exposure", "inventory", "vault", "identity", "remediation")
CATEGORIES = ("code", "cloud", "saas", "vault", "identity")
# How a credential stays valid: minted per use from a key or workload identity (AUTOMATIC), a token
# with an expiry (EXPIRES), one CreMore replaces itself before it expires (ROTATES), an OAuth refresh
# token (REFRESH), or nothing that expires (NONE).
RENEWALS = ("AUTOMATIC", "EXPIRES", "ROTATES", "REFRESH", "NONE")
FIELD_KINDS = ("text", "name", "url", "id", "list", "secret", "multiline", "choice", "choices", "number", "bool")
CHECK_STATUSES = ("GRANTED", "MISSING", "NOT_REPORTED", "ERROR")
# The key metadata of an issued credential, in the order a type's ``support`` string gives them.
INVENTORY_FIELDS = ("id", "name", "created", "expires", "scopes", "creator", "owner", "last_used", "state")
_MATCH_KEYS = {"provider", "prefix", "contains", "kind", "fact", "in", "credential_type"}
_CODE = re.compile(r"[A-Z][A-Z0-9_]{2,80}")

MODULES = (
    "cremore_github_provider.onboarding",
    "cremore_aws_provider.onboarding",
    "cremore_notion_provider.onboarding",
    "cremore_slack_provider.onboarding",
)
_ID = re.compile(r"[a-z][a-z0-9_]{1,40}")
# A permission is named as its provider names it (``storage.buckets.list``, ``admin:org``).
# A choice value: GitLab source names, "1" and "2" for a KV version.
_OPTION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}")
_PERMISSION = re.compile(r"[a-z][A-Za-z0-9_.:-]{1,80}")


class CatalogError(ValueError):
    pass


def _labelled(item, where, pattern=_ID):
    if not isinstance(item, dict) or not pattern.fullmatch(str(item.get("id") or item.get("name") or "")):
        raise CatalogError(f"{where}: id")
    if not item.get("label") or not item.get("label_ko"):
        raise CatalogError(f"{where}: labels")


def _when(item, where):
    when = item.get("when")
    if when is not None and (not isinstance(when, dict) or not when or any(
            not isinstance(values, list) or not values for values in when.values())):
        raise CatalogError(f"{where}: when")


def applies(item, target) -> bool:
    """Whether a field or permission with ``when: {target field: [values]}`` applies to ``target``;
    ``"*"`` among the values stands for any value that is set."""
    return all((target.get(name) if target.get(name) is not None else "") in values
               or ("*" in values and target.get(name) not in (None, "", []))
               for name, values in (item.get("when") or {}).items())


def _fields(fields, where):
    names = set()
    for field in fields:
        _labelled(field, where)
        _when(field, f"{where} {field['name']}")
        if field.get("kind", "text") not in FIELD_KINDS or field["name"] in names:
            raise CatalogError(f"{where}: {field.get('name')}")
        if "schedule" in field and (type(field["schedule"]) is not bool or field.get("kind") != "number"):
            raise CatalogError(f"{where}: {field['name']} schedule")
        if field.get("kind") in ("choice", "choices") or (field.get("kind") == "list" and "options" in field):
            options = field.get("options") or []
            if not options:
                raise CatalogError(f"{where}: {field['name']} options")
            for option in options:
                _labelled(option, f"{where} {field['name']} option", _OPTION)
        names.add(field["name"])


def schedule_fields(provider, purpose):
    """Declared cadence fields; changing these alone acquires no provider access."""
    return [field for field in descriptor(provider)["purposes"][purpose].get("plan") or []
            if field["name"] == "schedule_minutes" or field.get("schedule") is True]


def _text_pair(value) -> bool:
    return (isinstance(value, (list, tuple)) and len(value) == 2
            and all(isinstance(item, str) and item.strip() for item in value))


def _binding(binding, plan, edition_ids, where):
    if not isinstance(binding, dict) or not binding:
        raise CatalogError(f"{where}: plan binding")
    if binding.get("always") is True:
        if set(binding) - {"always", "when", "editions"} or set(binding.get("editions") or []) - edition_ids:
            raise CatalogError(f"{where}: plan binding")
        _when(binding, where)
        return
    field = next((f for f in plan if f.get("name") == binding.get("field")), None)
    if field is None or set(binding) - {"field", "option"}:
        raise CatalogError(f"{where}: plan binding {binding.get('field')}")
    kind = field.get("kind", "text")
    if "option" in binding:
        if kind != "choices" or binding["option"] not in {o["id"] for o in field.get("options") or []}:
            raise CatalogError(f"{where}: plan binding {field['name']}:{binding['option']}")
    elif kind not in ("bool", "list"):
        raise CatalogError(f"{where}: plan binding {field['name']} must be a bool or list field")


def _scans(spec, edition_ids, where):
    seen = set()
    for item in spec.get("scans") or []:
        _labelled(item, f"{where} scan")
        _when(item, f"{where} scan {item['id']}")
        if item["id"] in seen or bool(item.get("description")) != bool(item.get("description_ko")):
            raise CatalogError(f"{where} scan {item['id']}")
        if set(item.get("editions") or []) - edition_ids:
            raise CatalogError(f"{where} scan {item['id']}: editions")
        seen.add(item["id"])


def _types(spec, permissions, edition_ids, where):
    seen = set()
    for item in spec.get("types") or []:
        _labelled(item, f"{where} type")
        name = f"{where} type {item['id']}"
        if item["id"] in seen:
            raise CatalogError(f"{name}: registered twice")
        seen.add(item["id"])
        _when(item, name)
        bindings = item.get("plan")
        if bindings is not None and (not isinstance(bindings, list) or not bindings):
            raise CatalogError(f"{name}: plan")
        for binding in bindings or []:
            _binding(binding, spec.get("plan") or [], edition_ids, name)
        if bool(item.get("description")) != bool(item.get("description_ko")):
            raise CatalogError(f"{name}: description")
        if item.get("permission") is not None and item["permission"] not in permissions:
            raise CatalogError(f"{name}: permission")
        if item.get("credential_type") is not None and not _CODE.fullmatch(str(item["credential_type"])):
            raise CatalogError(f"{name}: credential_type")
        if "snapshot_only" in item and type(item["snapshot_only"]) is not bool:
            raise CatalogError(f"{name}: snapshot_only")
        if "export_type" in item and (not item.get("snapshot_only") or not _ID.fullmatch(str(item["export_type"]))):
            raise CatalogError(f"{name}: export_type")
        if set(item.get("editions") or []) - edition_ids:
            raise CatalogError(f"{name}: editions")
        support = item.get("support")
        if not isinstance(support, str) or len(support) != len(INVENTORY_FIELDS) or set(support) - set("YPN"):
            raise CatalogError(f"{name}: support")
        reasons = item.get("reasons") or {}
        if not isinstance(reasons, dict) or set(reasons) - set(INVENTORY_FIELDS):
            raise CatalogError(f"{name}: reasons")
        for field, state in zip(INVENTORY_FIELDS, support, strict=True):
            if (state != "Y") != (field in reasons) or (field in reasons and not _text_pair(reasons[field])):
                raise CatalogError(f"{name}: reason for {field}")
        match = item.get("match")
        if not isinstance(match, list) or not match:
            raise CatalogError(f"{name}: match")
        for rule in match:
            if (not isinstance(rule, dict) or not rule or set(rule) - _MATCH_KEYS
                    or ("fact" in rule) != ("in" in rule)
                    or ("in" in rule and (not isinstance(rule["in"], list) or not rule["in"]))):
                raise CatalogError(f"{name}: match rule")


def _fact(facts, path):
    value = facts
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _matches(rule, item) -> bool:
    provider = rule.get("provider")
    if provider is not None and item.get("provider") not in ([provider] if isinstance(provider, str) else provider):
        return False
    if "prefix" in rule and not str(item.get("object_id") or "").startswith(rule["prefix"]):
        return False
    if "contains" in rule and rule["contains"] not in str(item.get("object_id") or ""):
        return False
    if "kind" in rule and item.get("object_kind") != rule["kind"]:
        return False
    if "credential_type" in rule and item.get("credential_type") not in rule["credential_type"]:
        return False
    if "fact" in rule:
        value = _fact(item.get("facts") or {}, rule["fact"])
        values = value if isinstance(value, list) else [value]
        if not any(entry in rule["in"] for entry in values if isinstance(entry, (str, int))):
            return False
    return True


def inventory_type(provider: str, item: dict) -> dict | None:
    """The declared inventory type of one listed item of ``provider`` (a catalog provider).

    ``item``: ``provider`` (the collection's provider), ``object_id``, ``object_kind``, ``facts``
    (unpacked) and ``credential_type`` when known."""
    try:
        spec = descriptor(provider)["purposes"].get("inventory") or {}
    except CatalogError:
        return None
    return next((kind for kind in spec.get("types") or []
                 if any(_matches(rule, item) for rule in kind["match"])), None)


def validate(descriptor) -> dict:
    """A descriptor the wizard can show; raises CatalogError naming what is wrong."""
    provider = descriptor.get("provider")
    if not isinstance(provider, str) or not _ID.fullmatch(provider):
        raise CatalogError("provider")
    where = provider
    if not descriptor.get("label") or not descriptor.get("label_ko") or descriptor.get("category") not in CATEGORIES:
        raise CatalogError(f"{where}: label or category")
    if descriptor.get("replaced_by") is not None and (not _ID.fullmatch(str(descriptor["replaced_by"]))
                                                      or descriptor["replaced_by"] == provider):
        raise CatalogError(f"{where}: replaced_by")
    editions = descriptor.get("editions") or []
    if not editions:
        raise CatalogError(f"{where}: editions")
    for edition in editions:
        _labelled(edition, f"{where} edition")
    _fields(descriptor.get("target") or [], f"{where} target")
    purposes = descriptor.get("purposes") or {}
    if not purposes or set(purposes) - set(PURPOSES):
        raise CatalogError(f"{where}: purposes")
    for purpose, spec in purposes.items():
        if set(spec.get("editions") or []) - {e["id"] for e in editions}:
            raise CatalogError(f"{where} {purpose}: editions")
        choices = {field.get("name") for field in spec.get("plan") or [] if field.get("kind") == "bool"}
        for permission in spec.get("permissions") or []:
            _labelled(permission, f"{where} {purpose} permission", _PERMISSION)
            _when(permission, f"{where} {purpose} permission {permission['id']}")
            for key in ("option", "unless"):
                if permission.get(key) is not None and permission[key] not in choices:
                    raise CatalogError(f"{where} {purpose} permission {permission['id']}: {key}")
            if "required" in permission and type(permission["required"]) is not bool:
                raise CatalogError(f"{where} {purpose} permission {permission['id']}: required")
            if permission.get("nonempty") is not None and permission["nonempty"] not in {
                    f["name"] for f in spec.get("plan") or [] if f.get("kind") in ("list", "choices")}:
                raise CatalogError(f"{where} {purpose} permission {permission['id']}: nonempty")
        _fields(spec.get("plan") or [], f"{where} {purpose} plan")
        for field in spec.get("plan") or []:
            source = field.get("target_default")
            if source is not None:
                original = next((f for f in descriptor.get("target") or [] if f["name"] == source), None)
                if (original is None or original.get("kind", "text") != field.get("kind", "text")
                        or "default" not in field):
                    raise CatalogError(f"{where} {purpose} plan {field['name']}: target_default")
            given = field.get("edition_defaults")
            if given is not None and (not isinstance(given, dict) or "default" not in field
                                      or set(given) - {edition["id"] for edition in editions}
                                      or any(type(value) is not type(field["default"]) for value in given.values())):
                raise CatalogError(f"{where} {purpose} plan {field['name']}: edition_defaults")
        if spec.get("types") is not None and purpose != "inventory":
            raise CatalogError(f"{where} {purpose}: types belong to the inventory")
        if spec.get("scans") is not None and purpose != "exposure":
            raise CatalogError(f"{where} {purpose}: scans belong to the exposure scan")
        _scans(spec, {e["id"] for e in editions}, f"{where} {purpose}")
        _types(spec, {p["id"] for p in spec.get("permissions") or []}, {e["id"] for e in editions}, f"{where} {purpose}")
    methods = descriptor.get("auth_methods") or []
    method_ids = {method.get("id") for method in methods}
    for purpose, spec in purposes.items():
        for permission in spec.get("permissions") or []:
            if set(permission.get("methods") or []) - method_ids:
                raise CatalogError(f"{where} {purpose} permission {permission['id']}: methods")
    seen = set()
    for method in methods:
        _labelled(method, f"{where} auth method")
        if method["id"] in seen or method.get("renewal") not in RENEWALS:
            raise CatalogError(f"{where} auth method {method['id']}")
        seen.add(method["id"])
        if "new_setup" in method and type(method["new_setup"]) is not bool:
            raise CatalogError(f"{where} auth method {method['id']}: new_setup")
        served = method.get("purposes") or []
        if not served or set(served) - set(purposes):
            raise CatalogError(f"{where} auth method {method['id']}: purposes")
        if set(method.get("editions") or []) - {edition["id"] for edition in editions}:
            raise CatalogError(f"{where} auth method {method['id']}: editions")
        narrowed = method.get("purpose_editions", {})
        if not isinstance(narrowed, dict) or set(narrowed) - set(served) or any(
                not isinstance(ids, list) or not ids or set(ids) - {edition["id"] for edition in editions}
                for ids in narrowed.values()):
            raise CatalogError(f"{where} auth method {method['id']}: purpose_editions")
        _fields(method.get("fields") or [], f"{where} auth method {method['id']}")
        support = method.get("auth_first")
        if support is not None and (not isinstance(support, dict) or set(support) != {"context"}
                or not isinstance(support.get("context"), list)
                or any(not isinstance(key, str) for key in support["context"])
                or len(set(support["context"])) != len(support["context"])
                or set(support["context"]) - {f["name"] for f in descriptor.get("target") or []}):
            raise CatalogError(f"{where} auth method {method['id']}: auth_first")
        keys = method.get("reference_keys", ["token"])
        if not isinstance(keys, list) or not keys or any(not isinstance(key, str) or not key for key in keys):
            raise CatalogError(f"{where} auth method {method['id']}: reference_keys")
        if method.get("generated"):
            raise CatalogError(f"{where} auth method {method['id']}: generated")
    for purpose in purposes:
        if not any(purpose in method["purposes"] for method in methods):
            raise CatalogError(f"{where}: no auth method for {purpose}")
    return descriptor


def _load():
    providers, modules = {}, {}
    for name in MODULES:
        module = import_module(name)
        for function in ("credential", "check", "children"):
            if not callable(getattr(module, function, None)):
                raise CatalogError(f"{name}: {function}")
        for descriptor in module.DESCRIPTORS:
            validate(descriptor)
            if any(method.get("auth_first") is not None for method in descriptor["auth_methods"]):
                for function_name in ("authenticate", "discover"):
                    if not callable(getattr(module, function_name, None)):
                        raise CatalogError(f"{descriptor['provider']}: {function_name}")
            if descriptor["provider"] in providers:
                raise CatalogError(f"{descriptor['provider']}: registered twice")
            providers[descriptor["provider"]] = descriptor
            modules[descriptor["provider"]] = module
    for descriptor in providers.values():
        if descriptor.get("replaced_by") is not None and descriptor["replaced_by"] not in providers:
            raise CatalogError(f"{descriptor['provider']}: replaced_by")
    return providers, modules


_CACHE: dict = {}


def providers() -> dict:
    if not _CACHE:
        _CACHE["providers"], _CACHE["modules"] = _load()
    return _CACHE["providers"]


def descriptor(provider: str) -> dict:
    found = providers().get(provider)
    if found is None:
        raise CatalogError("PROVIDER_UNKNOWN")
    return found


def module(provider: str):
    descriptor(provider)
    return _CACHE["modules"][provider]


def methods_for(provider: str, purposes, edition: str | None = None) -> list[dict]:
    """The auth methods that serve every one of ``purposes`` in ``edition``, in recommended order."""
    wanted = set(purposes)
    specs = descriptor(provider)["purposes"]
    if edition is not None and any(specs.get(p, {}).get("editions")
                                  and edition not in specs[p]["editions"] for p in wanted):
        return []
    return [method for method in descriptor(provider)["auth_methods"] if wanted <= set(method["purposes"])
            and (edition is None or not method.get("editions") or edition in method["editions"])
            and (edition is None or all(edition in method.get("purpose_editions", {}).get(purpose, [edition])
                                        for purpose in wanted))]


def permissions_for(provider: str, purpose: str, method: str, target: dict | None = None) -> list[dict]:
    """The checklist a purpose shows for an auth method (and a target, when one is chosen)."""
    return [permission for permission in descriptor(provider)["purposes"][purpose].get("permissions") or []
            if (not permission.get("methods") or method in permission["methods"])
            and (target is None or applies(permission, target))]


def _method_view(method) -> dict:
    """What a vault:// reference must hold, for a method that has a secret and takes one."""
    view = dict(method)
    secret = any(field.get("secret") for field in method.get("fields") or [])
    if secret and method.get("reference") is not False:
        view["reference_keys"] = list(method.get("reference_keys", ["token"]))
    else:
        view.pop("reference_keys", None)
        view["reference"] = False
    return view


def public() -> list[dict]:
    """The catalog as the wizard reads it: descriptors only, no functions."""
    return [{**item, "auth_methods": [_method_view(method) for method in item["auth_methods"]]}
            for item in providers().values()]
