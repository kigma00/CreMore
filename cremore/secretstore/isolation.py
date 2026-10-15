"""Public-key admission and authority-bound opening of connector credentials.

The deployment-owned recipient file, never a database row, selects the key for
one purpose/provider/authority group. Possessing a different group's private
key does not open its envelopes. Public-key encryption does not authorize a new
credential: existing onboarding, scope and action approval remain mandatory.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cremore.secretstore.sealed import SealedSecretError

V3_PREFIX = "sealed:v3:"
_INFO = b"cremore/connector-envelope/v3"
MAX_REFERENCE = 196608
_MAX_FILE = 4 * 1024 * 1024
_URL_KEYS = {"host", "address", "base_url", "organization"}


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _b64(value):
    return base64.urlsafe_b64encode(value).decode("ascii")


def _decode(value):
    return base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)


def credential_purpose(purposes=()):
    values = set(purposes or ())
    if "remediation" in values:
        if values != {"remediation"}:
            raise SealedSecretError("CREDENTIAL_PURPOSE_INVALID")
        return "remediator"
    return "collector"


def _authority_value(key, value):
    if not isinstance(value, str):
        raise SealedSecretError("CREDENTIAL_AUTHORITY_INVALID")
    if key in _URL_KEYS and ("://" in value or key == "host"):
        parts = urlsplit(value if "://" in value else "https://" + value)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
            raise SealedSecretError("CREDENTIAL_AUTHORITY_INVALID")
        port = parts.port
        host = parts.hostname.lower()
        if ":" in host:
            host = "[" + host + "]"
        authority = host + (f":{port}" if port and port != 443 else "")
        # host fields are origins; a base_url can intentionally include an API prefix.
        return urlunsplit(("https", authority, parts.path.rstrip("/"), "", ""))
    # Certificate trust itself belongs to the authority; do not put a long PEM in the header.
    if key == "tls_ca_pem":
        return "sha256:" + hashlib.sha256(value.encode()).hexdigest()
    return value


def credential_binding(provider, target, *, purposes=(), auth_method=""):
    """The stable authentication context; never the mutable collection selection.

    Context fields come from the existing provider descriptor. The API and
    worker must derive this from their current connection, not the envelope's
    unauthenticated header. Child jobs must also keep the owner's destination.
    """
    from cremore.onboarding import catalog

    descriptor = catalog.descriptor(provider)
    methods = descriptor["auth_methods"]
    method = next((item for item in methods if item["id"] == auth_method), None)
    if method is None:
        raise SealedSecretError("CREDENTIAL_AUTH_METHOD_INVALID")
    context = (method.get("auth_first") or {}).get("context")
    if context is None:
        # Older methods have no auth-first flow; URL target fields still pin their destination.
        context = [field["name"] for field in descriptor.get("target", []) if field.get("kind") == "url"]
        context += [key for key in ("tenant", "realm", "namespace") if key in target]
    authority = {key: _authority_value(key, target[key]) for key in sorted(set(context))
                 if target.get(key) not in (None, "")}
    if provider in ("github", "gitlab"):
        authority.setdefault("host", "https://" + ("github.com" if provider == "github" else "gitlab.com"))
    return {"purpose": credential_purpose(purposes), "provider": provider, "authority": authority}


def binding_for_record(record):
    from cremore.onboarding.targets import records_of

    purposes = record.get("purposes") or []
    if record.get("credential_purpose") == "remediator":
        purposes = ["remediation"]
    target = record.get("target") or {}
    binding = credential_binding(record["provider"], target, purposes=purposes, auth_method=record["auth_method"])
    if "version" in target:
        # Roots may narrow collection scope, but credentials must keep the
        # owner's authentication destination and trust configuration.
        for root in records_of({**record, "target": target, "purposes": record.get("purposes") or []}):
            if credential_binding(record["provider"], root["target"], purposes=purposes,
                                  auth_method=record["auth_method"]) != binding:
                raise SealedSecretError("CREDENTIAL_AUTHORITY_MISMATCH")
    return binding


def _key_id(key):
    return hashlib.sha256(key.public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()[:32]


def _read_json(path):
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(_MAX_FILE + 1)
        if len(raw) > _MAX_FILE:
            raise ValueError
        value = json.loads(raw)
        if not isinstance(value, dict) or type(value.get("version")) is not int or value["version"] != 1:
            raise ValueError
        return value
    except (OSError, ValueError, TypeError):
        raise SealedSecretError("SEALING_KEY_FILE_INVALID") from None


class RecipientKeys:
    """Deployment-owned public policy and only this process's private keys."""

    def __init__(self, recipients, private_keys=()):
        self.recipients = {}
        self.private = {}
        self.public = {}
        self.key_bindings = {}
        try:
            if not isinstance(recipients, list) or not 1 <= len(recipients) <= 4096:
                raise ValueError
            for entry in recipients:
                binding = {key: entry[key] for key in ("purpose", "provider", "authority")}
                if (binding["purpose"] not in ("collector", "remediator") or not isinstance(binding["provider"], str)
                        or not isinstance(binding["authority"], dict) or not all(isinstance(v, str) for v in binding["authority"].values())):
                    raise ValueError
                encoded = _json(binding)
                if encoded in self.recipients:
                    raise ValueError
                ids = []
                values = entry["public_keys"]
                if not isinstance(values, list) or not 1 <= len(values) <= 8:
                    raise ValueError
                for pem in values:
                    key = serialization.load_pem_public_key(pem.encode("ascii"))
                    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 3072:
                        raise ValueError
                    kid = _key_id(key)
                    # Reusing a private key across authorities would erase the intended boundary.
                    if kid in self.key_bindings and self.key_bindings[kid] != encoded:
                        raise ValueError
                    self.public[kid], self.key_bindings[kid] = key, encoded
                    ids.append(kid)
                self.recipients[encoded] = tuple(ids)
            if not isinstance(private_keys, (list, tuple)) or len(private_keys) > 4096:
                raise ValueError
            for pem in private_keys:
                key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
                if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 3072:
                    raise ValueError
                kid = _key_id(key.public_key())
                if kid not in self.public or kid in self.private:
                    raise ValueError
                self.private[kid] = key
        except (ValueError, TypeError, KeyError, AttributeError):
            raise SealedSecretError("SEALING_RECIPIENT_POLICY_INVALID") from None

    @classmethod
    def from_files(cls, public_file, private_file=""):
        public = _read_json(public_file)
        private = _read_json(private_file) if private_file else {}
        return cls(public.get("recipients"), private.get("private_keys", []))

    def seal(self, fields, binding):
        encoded = _json(binding)
        ids = self.recipients.get(encoded)
        if not ids:
            raise SealedSecretError("SEALING_RECIPIENT_NOT_CONFIGURED")
        kid = ids[0]
        header = _json({"key": kid, "binding": binding})
        key, nonce = AESGCM.generate_key(bit_length=256), os.urandom(12)
        wrapped = self.public[kid].encrypt(key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                           algorithm=hashes.SHA256(), label=_INFO + header))
        cipher = AESGCM(key).encrypt(nonce, _json(fields), _INFO + header + wrapped)
        ref = V3_PREFIX + ".".join(_b64(part) for part in (header, wrapped, nonce + cipher))
        if len(ref) > MAX_REFERENCE:
            raise SealedSecretError("CREDENTIAL_TOO_LARGE")
        return ref

    def can_open(self, binding):
        """Whether this process is assigned any private key for this exact group."""
        return any(kid in self.private for kid in self.recipients.get(_json(binding), ()))

    def group_id(self, binding):
        return hashlib.sha256(_json(binding)).hexdigest()[:32]

    def is_current(self, ref, binding):
        """For migration only, after ``open`` has authenticated this envelope."""
        try:
            header = json.loads(_decode(ref[len(V3_PREFIX):].split(".")[0]))
            return header["key"] == self.recipients[_json(binding)][0]
        except (ValueError, KeyError, TypeError, IndexError):
            return False

    def open(self, ref, binding):
        if binding is None:
            raise SealedSecretError("CREDENTIAL_BINDING_REQUIRED")
        try:
            if not isinstance(ref, str) or not ref.startswith(V3_PREFIX) or len(ref) > MAX_REFERENCE:
                raise ValueError
            header, wrapped, body = (_decode(part) for part in ref[len(V3_PREFIX):].split("."))
            subject = json.loads(header)
            encoded = _json(binding)
            kid = subject["key"]
            if _json(subject["binding"]) != encoded or kid not in self.recipients.get(encoded, ()):
                raise SealedSecretError("CREDENTIAL_BINDING_MISMATCH")
            key = self.private.get(kid)
            if key is None:
                raise SealedSecretError("CREDENTIAL_PRIVATE_KEY_UNAVAILABLE")
            aes = key.decrypt(wrapped, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                  algorithm=hashes.SHA256(), label=_INFO + header))
            data = json.loads(AESGCM(aes).decrypt(body[:12], body[12:], _INFO + header + wrapped))
            if not isinstance(data, dict) or not data:
                raise ValueError
            return data
        except SealedSecretError:
            raise
        except (ValueError, TypeError, KeyError, InvalidTag):
            raise SealedSecretError("CREDENTIAL_ENVELOPE_INVALID") from None


def seal_credential(settings, fields, binding):
    from cremore.secretstore.sealed import seal_fields

    return seal_fields(settings.credential_sealing_keys, fields, binding=binding)


def validate_process_keys(settings, process_role):
    """Explicit startup validation; settings construction never reads key files."""
    if not settings.isolated_deployment:
        return
    settings.validate_sealing()
    if process_role not in ("api", "control", "collector", "remediator", "siem"):
        raise ValueError("ISOLATED_PROCESS_ROLE_REQUIRED")
    if process_role in ("api", "control", "siem") and settings.sealing_private_keys_file:
        raise ValueError("CONTROL_PROCESS_CANNOT_HOLD_CONNECTOR_PRIVATE_KEYS")
    if process_role in ("collector", "remediator") and settings.control_sealing_key:
        raise ValueError("CONNECTOR_WORKER_CANNOT_HOLD_CONTROL_SEALING_KEY")
    if process_role in ("api", "control") and not settings.control_sealing_key:
        raise ValueError("CONTROL_SEALING_KEY_REQUIRED")
    ring = settings.credential_sealing_keys
    if process_role in ("collector", "remediator"):
        if not ring.private:
            raise ValueError("CONNECTOR_PRIVATE_KEY_REQUIRED")
        if any(json.loads(ring.key_bindings[kid])["purpose"] != process_role for kid in ring.private):
            raise ValueError("CONNECTOR_PRIVATE_KEY_ROLE_MISMATCH")
        if any(ring.recipients[ring.key_bindings[kid]][0] not in ring.private for kid in ring.private):
            raise ValueError("CONNECTOR_CURRENT_PRIVATE_KEY_REQUIRED")
        # The queue routes by execution role, not by individual authority group.
        # A role worker must be able to open every group's newly admitted jobs.
        if any(ids[0] not in ring.private for binding, ids in ring.recipients.items()
               if json.loads(binding)["purpose"] == process_role):
            raise ValueError("CONNECTOR_ROLE_PRIVATE_KEY_SET_INCOMPLETE")
