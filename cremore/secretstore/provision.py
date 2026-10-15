"""Offline generation of separate connector, control and external approval keys.

Run on an operator machine, never in an API/worker. Input contains planned
authentication contexts, not credentials. Existing output is never overwritten.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from cremore.secretstore.isolation import RecipientKeys, binding_for_record


def bindings_for(plan):
    if not isinstance(plan, dict) or plan.get("version") != 1:
        raise ValueError("PROVISION_PLAN_INVALID")
    records = plan.get("connections")
    if not isinstance(records, list) or not 1 <= len(records) <= 256:
        raise ValueError("PROVISION_PLAN_INVALID")
    bindings = []
    for record in records:
        if not isinstance(record, dict):
            raise TypeError("PROVISION_PLAN_INVALID")
        if record.get("provider") == "machine_identity":
            from cremore.identity.machine import machine_binding, validate

            normalized = validate({"idp": record.get("idp"), "aws": {}, "gcp": {}, "azure": {}}, None)
            binding = machine_binding(normalized)
        else:
            from cremore.onboarding import catalog, service

            descriptor = catalog.descriptor(record.get("provider"))
            edition = record.get("edition") or descriptor["editions"][0]["id"]
            if edition not in {item["id"] for item in descriptor["editions"]}:
                raise ValueError("PROVISION_EDITION_INVALID")
            purposes = ["remediation"] if record.get("credential_purpose") == "remediator" else record.get("purposes", [])
            method = service._method(record["provider"], purposes, record.get("auth_method"), edition)
            target = record.get("target") or {}
            support = method.get("auth_first")
            module = catalog.module(record["provider"])
            if isinstance(support, dict):
                fields = [field for field in descriptor.get("target", []) if field["name"] in support.get("context", [])]
                target = service._fields(fields, target, edition)
                normalize = getattr(module, "auth_context", None)
                if callable(normalize):
                    target = normalize(record["provider"], edition, target)
            else:
                target = module.target(record["provider"], edition,
                                       service._fields(descriptor.get("target", []), target, edition))
            binding = binding_for_record({**record, "target": target})
        if binding not in bindings:
            bindings.append(binding)
    return bindings


def _write(path, content):
    # Exclusive creation plus a private directory avoids replacing an existing
    # key or following a pre-existing file symlink. Do not weaken the OS umask.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def _json_file(path, value):
    _write(path, json.dumps(value, indent=2, ensure_ascii=True) + "\n")


def provision(plan, output):
    bindings = bindings_for(plan)
    output = Path(output)
    # An existing directory, including a symlink, is an error. On Windows the
    # operator must first ensure the parent has a private inherited DACL.
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    recipients, private = [], {"collector": [], "remediator": []}
    for binding in bindings:
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        recipients.append({**binding, "public_keys": [key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")]})
        private[binding["purpose"]].append(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode("ascii"))
    RecipientKeys(recipients)  # Validate the exact policy before publishing files.
    _json_file(output / "recipients.json", {"version": 1, "recipients": recipients})
    for role, keys in private.items():
        if keys:
            _json_file(output / f"{role}-private.json", {"version": 1, "private_keys": keys})
    _write(output / "control-key.txt", os.urandom(32).hex() + "\n")
    signer = ed25519.Ed25519PrivateKey.generate()
    _write(output / "approval-public.pem", signer.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii"))
    external = output / "KEEP-OFF-SERVER"
    external.mkdir(mode=0o700)
    _write(external / "approval-private.pem", signer.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode("ascii"))
    return {"groups": len(recipients), "roles": [role for role, keys in private.items() if keys]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        with args.plan.open("rb") as stream:
            raw = stream.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError("PROVISION_PLAN_TOO_LARGE")
        result = provision(json.loads(raw), args.output)
    except (OSError, ValueError, TypeError, KeyError):
        parser.exit(1, "Key provisioning failed; use a valid plan and a new private directory. Existing files were not replaced.\n")
    print(json.dumps(result))  # Counts only; no key or credential output.
    print("Keep KEEP-OFF-SERVER on the independent approver machine. Mount only each process's assigned files.")
    if os.name == "nt":
        print("Windows: mode bits do not verify DACLs. Restrict the parent directory and verify file ACLs before use.")


if __name__ == "__main__":
    main()
