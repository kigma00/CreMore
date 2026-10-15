"""Read certificate bundles, retaining only a verified public DER fingerprint."""

from cremore.coverage.metadata_models import MetadataFact
from cremore_azure_provider.public_certificates import (
    EVIDENCE_CLASS,
    certificate_evidence,
    certificate_sha256,
)

from .normalization import report
from .resources import observation, resource_identity
from .transport import DEFERRED, ApiError


def _targets(context):
    spec = context["spec"]
    targets = set()
    for record in context["records"]:
        if (record.get("record_type") != "entity_observation"
                or record.get("provenance", {}).get("operation") not in {
                    "azure.key_vault.certificates", "azure.key_vault.certificate_versions"}):
            continue
        resource = record["provenance"].get("resource_id")
        parsed = resource_identity(spec, resource)
        if parsed and parsed[0] == "certificates" and record.get("identity", {}).get("object_id") == parsed[3]:
            targets.add(resource)
    return sorted(targets)


def collect_certificates(context, cursor):
    spec, run = context["spec"], context["run"]
    targets = _targets(context)
    errors = set(cursor.get("errors", []))
    if len(targets) > spec.options.max_targets:
        targets = targets[:spec.options.max_targets]
        errors.add("TARGET_LIMIT_REACHED")
    index, read = int(cursor.get("index", 0)), int(cursor.get("read", 0))
    if not 0 <= read <= index <= len(targets):
        raise ValueError("AZURE_KEY_VAULT_CHECKPOINT_MISMATCH")
    if run.status != "COMPLETE":
        errors.add("CERTIFICATE_DISCOVERY_INCOMPLETE")
    while index < len(targets):
        resource = targets[index]
        requested = resource_identity(spec, resource)
        records = []
        try:
            payload = context["transport"].get(resource[len(spec.origin):])
            returned = resource_identity(spec, payload.get("id"))
            if (not returned or returned[0] != "certificates" or returned[1] != requested[1]
                    or not returned[2] or requested[2] and returned[2] != requested[2]
                    or payload.get("nextLink")):
                raise ApiError("invalid_certificate_identifier")
            try:
                fingerprint = certificate_sha256(payload.get("cer"))
            except ValueError:
                raise ApiError("invalid_public_certificate") from None
            # Preserve list metadata projection, but never project cer/sid/key
            # or follow a certificate's backing secret/key URLs.
            safe = {key: value for key, value in payload.items() if key != "cer"}
            record = observation(spec, run.scope, safe, "certificate_versions")
            record.provenance.operation = "azure.key_vault.public_certificates"
            current = not requested[2] or any(
                item.get("provenance", {}).get("resource_id") == payload["id"]
                and (evidence := certificate_evidence(item)) and evidence["current_version"]
                for item in context["records"])
            record.facts.extend([MetadataFact(name="sha256_fingerprint", value=fingerprint),
                                 MetadataFact(name="evidence_class", value=EVIDENCE_CLASS),
                                 MetadataFact(name="selection", value="current_public_certificate" if current else "listed_public_certificate")])
            records.append(record)
            read += 1
        except ApiError as exc:
            if exc.code in DEFERRED:
                raise
            errors.add(exc.code.upper())
        index += 1
        finished = index == len(targets) or index >= spec.max_pages
        if index >= spec.max_pages and index < len(targets):
            errors.add("PAGE_LIMIT_REACHED")
        if finished:
            records.append(_report(context, index, read, errors))
        yield records, ({} if finished else {"index": index, "read": read, "errors": sorted(errors)})
        if finished:
            return
    if not targets:
        yield [_report(context, 0, 0, errors)], {}


def _report(context, total, read, errors):
    return report(context["spec"], context["run"].scope, "azure.key_vault.public_certificates",
                  status="PARTIAL" if errors else "COMPLETE", reasons=errors,
                  pages=total, received=total, saved=read, facts={"selection": "public_certificates_only"})
