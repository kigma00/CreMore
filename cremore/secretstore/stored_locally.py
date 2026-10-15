"""Configured credential sources, including displaced and previous openers.

Every item in ``docs/CREDENTIAL_ROOTS.md`` can be configured three or four
different ways, and an operator who has done the work has no way to confirm it
took. "I set SEALING_KMS_KEY_ID" and "the master is in KMS" are not the same
sentence, and the difference only shows up when someone copies the .env.

So this reports what is actually true of the running process, read from the
settings it booted with. Two rules:

*It never reports a secret.* A value is a boolean -- set, or not. The one
exception is the sealing key identifier, which is an HKDF output over the
master and is already printed in the error that says which key is missing.

*It never claims about what it cannot see.* ``OIDC_CLIENT_SECRET`` belongs to
oauth2-proxy and this process is never given it, so it is not listed. An
inventory that quietly lists only some of what is held is worse than one that
says which parts it can speak for.

That second rule is why the question is ``held_here`` and not "on disk". An
environment variable is an environment variable; whether it arrived from a
file, from an operator's shell or from a secrets manager is not something this
process can see. What it can say is whether the installation holds the value
itself or only a reference that is useless without something else.
"""

from __future__ import annotations

# Where the master that seals stored connection credentials comes from, best
# first. The order matches cremore.config.Settings.sealing_keys.
VAULT = "VAULT"
KMS = "KMS"
PASSPHRASE = "PASSPHRASE"
ENVIRONMENT = "ENVIRONMENT"
FINGERPRINT_KEY = "FINGERPRINT_KEY"
SCOPED_PUBLIC_KEY = "SCOPED_PUBLIC_KEY"


def sealing_root(settings) -> str:
    if settings.isolated_deployment:
        return SCOPED_PUBLIC_KEY
    if settings.sealing_key_vault_path.strip():
        return VAULT
    if settings.sealing_key_ciphertext.strip():
        return KMS
    if settings.sealing_passphrase.strip():
        return PASSPHRASE
    if settings.sealing_key.strip():
        return ENVIRONMENT
    return FINGERPRINT_KEY


def _item(name, where, held_here, rotatable, reason):
    """``held_here``: this installation holds the value, not just a pointer to it."""
    return {"name": name, "where": where, "held_here": held_here, "rotatable": rotatable, "reason": reason}


def local_credentials(settings) -> dict:
    """Report configured material without inferring disk persistence or locality."""
    if settings.isolated_deployment:
        return {
            "basis": "PROCESS_CONFIGURATION", "disk_persistence": "UNKNOWN",
            "sealing": {"root": "SCOPED_PUBLIC_KEY", "held_here": bool(settings.sealing_private_keys_file),
                        "key_id": None, "openers": None, "unreachable": None},
            "items": [
                _item("connector public recipient policy", "FILE", False, True,
                      "deployment-owned purpose/provider/authority groups select public encryption keys"),
                _item("connector private keys", "FILE", bool(settings.sealing_private_keys_file), True,
                      "a configured private-key file grants this process decryption of its assigned groups"),
                _item("CONTROL_SEALING_KEY", ENVIRONMENT, bool(settings.control_sealing_key), True,
                      "opens only control and unfinished OAuth/App setup secrets"),
                _item("FINGERPRINT_KEY", ENVIRONMENT, bool(settings.fingerprint_key), False,
                      "retained for fingerprint compatibility; never used to open connector envelopes"),
            ],
            "reasons": ["RECIPIENT_GROUP_IS_THE_DECRYPTION_BOUNDARY", "DEPLOYMENT_PERMISSIONS_NOT_ATTESTED"],
        }
    root = sealing_root(settings)
    held_here = root in (PASSPHRASE, ENVIRONMENT, FINGERPRINT_KEY)

    items = [_item(
        "sealing master", root, held_here,
        root != FINGERPRINT_KEY,
        {
            VAULT: "SEALING_KEY_VAULT_PATH: configuration contains a reference; the resolved master is used in process memory",
            KMS: "SEALING_KEY_CIPHERTEXT: configuration contains ciphertext; opening it needs kms:Decrypt and uses process memory",
            PASSPHRASE: "SEALING_PASSPHRASE: configured passphrase derives the master in process memory; "
                        "this process cannot determine whether its source was persisted",
            ENVIRONMENT: "SEALING_KEY: the master itself is in this installation's environment, "
                         "wherever that environment got it",
            FINGERPRINT_KEY: "no sealing source set, so the master is derived from FINGERPRINT_KEY, "
                             "which cannot rotate without orphaning every stored fingerprint",
        }[root])]

    # Settings keeps displaced current sources and previous roots as openers.
    # A remote current root does not remove those configured local values.
    for name, where in (("SEALING_KEY", ENVIRONMENT), ("SEALING_PASSPHRASE", PASSPHRASE),
                        ("SEALING_KEY_CIPHERTEXT", KMS), ("SEALING_KEY_PREVIOUS", ENVIRONMENT),
                        ("SEALING_PASSPHRASE_PREVIOUS", PASSPHRASE),
                        ("SEALING_KEY_CIPHERTEXT_PREVIOUS", KMS), ("SEALING_KEY_VAULT_PATH_PREVIOUS", VAULT)):
        if not getattr(settings, name.lower(), "").strip() or (not name.endswith("_PREVIOUS") and where == root):
            continue
        local = where in (ENVIRONMENT, PASSPHRASE)
        items.append(_item(name, where, local, True,
                           "configured opening material remains available for older credentials; disk persistence is unknown"
                           if local else "configured external opener; resolved material is used in process memory"))

    items.append(_item(
        "FINGERPRINT_KEY", ENVIRONMENT, True, False,
        "keys stored fingerprints; rotating it orphans every recorded match, so it stays"))

    if settings.auth_mode == "local":
        items.append(_item(
            "API_TOKEN", ENVIRONMENT, True, False,
            "the shared token this installation authenticates with. Generate it per start and export it instead of writing it down, or AUTH_MODE=oidc removes it entirely"))

    if settings.database_url.strip():
        items.append(_item(
            "DATABASE_URL", ENVIRONMENT, True, False,
            "configured database connection string; it may contain credentials and does not establish network locality"))

    if settings.secret_store_url.strip():
        kubernetes = settings.secret_store_auth_mode == "kubernetes"
        items.append(_item(
            "SECRET_STORE_TOKEN", "WORKLOAD_IDENTITY" if kubernetes else ENVIRONMENT,
            not kubernetes, True,
            "exchanged for a lease from a projected service-account token" if kubernetes
            else "a static store token; SECRET_STORE_AUTH_MODE=kubernetes removes it"))

    reasons = sorted({
        item["name"].upper().replace(" ", "_") + "_HELD_HERE"
        for item in items if item["held_here"] and item["rotatable"]
    })
    if root == FINGERPRINT_KEY:
        reasons.append("SEALING_MASTER_CANNOT_ROTATE")

    # Naming the key means resolving it, which for a vault or KMS root is a
    # call out. This is a status view, so a store that cannot be reached is
    # reported as exactly that rather than failing the request or, worse,
    # showing the installation as though it had no sealing key at all.
    key_id, openers, unreachable = None, None, None
    try:
        keys = settings.sealing_keys
        key_id, openers = keys.current_id, len(keys.known_ids())
    except Exception as exc:  # noqa: BLE001 -- the code, never the backend's text
        unreachable = type(exc).__name__
        reasons.append("SEALING_ROOT_UNREACHABLE")

    return {
        "basis": "PROCESS_CONFIGURATION",
        "disk_persistence": "UNKNOWN",
        "sealing": {
            "root": root,
            "held_here": held_here,
            # An HKDF output over the master, not the master and not a hash of
            # it. The refusal that cannot open a credential already names it.
            "key_id": key_id,
            "openers": openers,
            "unreachable": unreachable,
        },
        "items": items,
        "reasons": reasons,
    }
