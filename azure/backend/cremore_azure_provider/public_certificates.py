"""Pure X.509 certificate evidence; never private-key or secret equality."""

import base64
import binascii
import hashlib
import re

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

EVIDENCE_CLASS = "X509_DER_SHA256"
MAX_CERTIFICATE_BYTES = 65536


def certificate_sha256(encoded):
    """Hash exactly one bounded, well-formed Base64 DER certificate."""
    if not isinstance(encoded, str) or not 1 <= len(encoded) <= 4 * ((MAX_CERTIFICATE_BYTES + 2) // 3):
        raise ValueError("INVALID_PUBLIC_CERTIFICATE")
    try:
        der = base64.b64decode(encoded, validate=True)
        if not 1 <= len(der) <= MAX_CERTIFICATE_BYTES:
            raise ValueError
        certificate = x509.load_der_x509_certificate(der)
        # Reject concatenated material, trailing bytes, and noncanonical BER.
        if certificate.public_bytes(Encoding.DER) != der:
            raise ValueError
    except (ValueError, TypeError, binascii.Error):
        raise ValueError("INVALID_PUBLIC_CERTIFICATE") from None
    return hashlib.sha256(der).hexdigest()


def certificate_evidence(record):
    """Return public-certificate evidence from explicit provider reads only.

    This intentionally ignores customKeyIdentifier and x5t. A matching public
    certificate proves neither private-key possession nor current authority.
    """
    if hasattr(record, "model_dump"):
        record = record.model_dump()
    if not isinstance(record, dict) or record.get("record_type") != "entity_observation" or record.get("value_match"):
        return None
    identity = record.get("identity") or {}
    operation = (record.get("provenance") or {}).get("operation")
    provider = identity.get("provider")
    expected = {"azure_entra": ("azure.entra.public_certificates", {"public_key"}, "issuer_inventory"),
                "azure_key_vault": ("azure.key_vault.public_certificates", {"vault_version"}, "vault_metadata")}
    if provider not in expected:
        return None
    source, kinds, purpose = expected[provider]
    if operation != source or identity.get("kind") not in kinds or record.get("purpose") != purpose:
        return None
    # Duplicate facts are ambiguous evidence, even if a generic exporter can
    # display them. Do not let the last value silently win.
    facts = {}
    for fact in record.get("facts", []):
        name = fact.get("name")
        if name in {"sha256_fingerprint", "evidence_class", "selection"}:
            if name in facts or fact.get("state") != "PRESENT" or fact.get("children"):
                return None
            facts[name] = fact.get("value")
    fingerprint = facts.get("sha256_fingerprint")
    if facts.get("evidence_class") != EVIDENCE_CLASS or not isinstance(fingerprint, str) or not re.fullmatch(r"[a-f0-9]{64}", fingerprint):
        return None
    return {"fingerprint": fingerprint, "evidence_class": EVIDENCE_CLASS,
            "current_version": facts.get("selection") == "current_public_certificate"}
