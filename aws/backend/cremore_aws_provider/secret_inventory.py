"""Secrets Manager value fingerprints within exact account, region and ARN scope."""

from __future__ import annotations

import re

from cremore.coverage.collection import CollectionLimit
from cremore.coverage.models import Observation, in_scope

_ARN = re.compile(r"arn:(aws|aws-us-gov|aws-cn|aws-eusc):secretsmanager:([a-z0-9-]+):([0-9]{12}):secret:[A-Za-z0-9/_+=.@-]+-[A-Za-z0-9]{6}")


def pages(out, call, field, *, expected_arn=None, **kwargs):
    """A malformed/denied page is not an empty inventory."""
    seen = set()
    while True:
        response = out.call(call, **kwargs)
        if (not isinstance(response, dict) or not isinstance(response.get(field), list)
                or (expected_arn is not None and response.get("ARN") != expected_arn)):
            raise ValueError("SECRET_LIST_RESPONSE_MISMATCH")
        yield from response[field]
        token = response.get("NextToken")
        if token is None:
            return
        if not isinstance(token, str) or not token or len(token) > 4096:
            raise ValueError("SECRET_LIST_CURSOR_INVALID")
        if token in seen:
            raise CollectionLimit("PAGINATION_LOOP")
        seen.add(token)
        kwargs["NextToken"] = token


def _state(stages):
    return "CURRENT" if "AWSCURRENT" in stages else "PREVIOUS" if "AWSPREVIOUS" in stages else "UNKNOWN"


def _read(out, client, engine, location, **selection):
    location = dict(location)
    location.setdefault("version_state", "UNKNOWN")
    if selection.get("VersionId"):
        location.update(version=selection["VersionId"], version_state="UNKNOWN")
    try:
        response = out.call(client.get_secret_value, SecretId=location["reference"], **selection)
        if not isinstance(response, dict):
            raise TypeError("SECRET_RESPONSE_MISMATCH")
        version, stages = response.get("VersionId"), response.get("VersionStages", [])
        if (response.get("ARN") != location["reference"] or not isinstance(version, str) or not version
                or not isinstance(stages, list) or not all(isinstance(s, str) for s in stages)
                or ("VersionId" in selection and version != selection["VersionId"])
                or (stages and "VersionStage" in selection and selection["VersionStage"] not in stages)):
            out.unresolved(location, "SECRET_RESPONSE_MISMATCH")
            return None
        location.update(version=version, version_state=_state(stages))
        # boto3 already decodes SecretBinary to bytes. Never decode it a second
        # time or assume it contains an AWS key: the shared engine handles types.
        present = [key for key in ("SecretString", "SecretBinary") if key in response]
        if len(present) != 1:
            out.unresolved(location, "SECRET_VALUE_MISSING" if not present else "SECRET_RESPONSE_MISMATCH")
        elif (present[0] == "SecretString" and not isinstance(response[present[0]], str)) or (
                present[0] == "SecretBinary" and not isinstance(response[present[0]], bytes)):
            out.unresolved(location, "SECRET_RESPONSE_MISMATCH")
        else:
            out.value(engine, response[present[0]], location)
        return version
    except CollectionLimit:
        raise
    except Exception:  # noqa: BLE001 -- SDK exceptions can carry raw provider values.
        out.unresolved(location, "SECRET_READ_FAILED")
        return None


def collect_region(spec, client, engine, out, region):
    records = ([{"ARN": arn} for arn in spec.references if arn.split(":", 5)[3] == region]
               if spec.references else pages(out, client.list_secrets, "SecretList", MaxResults=100))
    seen = set()
    for record in records:
        arn = record.get("ARN") if isinstance(record, dict) else None
        match = _ARN.fullmatch(arn) if isinstance(arn, str) else None
        if not match or match[2] != region or match[3] != spec.account_id:
            out.reasons.add("PROVIDER_SCOPE_MISMATCH")
            continue
        location = {"reference": arn, "account_id": spec.account_id, "region": region}
        if not in_scope(spec, Observation(**location, evidence="UNRESOLVED", reason="CHECKING_SCOPE")):
            continue  # A valid resource excluded by the explicit name prefix.
        if arn in seen:
            out.reasons.add("DUPLICATE_SECRET_RECORD")
            continue
        seen.add(arn)
        current = _read(out, client, engine, location,
                        VersionStage="AWSCURRENT" if spec.version_selector == "latest" else spec.version_selector)
        if not spec.include_previous_versions:
            continue
        versions, count = set(), 1
        try:
            for entry in pages(out, client.list_secret_version_ids, "Versions", expected_arn=arn,
                               SecretId=arn, IncludeDeprecated=True, MaxResults=100):
                version = entry.get("VersionId") if isinstance(entry, dict) else None
                if not isinstance(version, str) or not re.fullmatch(r"[A-Za-z0-9-]{32,64}", version):
                    out.reasons.add("SECRET_VERSION_RESPONSE_MISMATCH")
                    continue
                if version in versions:
                    out.reasons.add("DUPLICATE_SECRET_VERSION")
                    continue
                versions.add(version)
                if version == current:
                    continue
                if count >= spec.max_versions_per_secret:
                    out.reasons.add("SECRET_VERSION_LIMIT")
                    break
                _read(out, client, engine, location, VersionId=version)
                count += 1
        except CollectionLimit:
            raise
        except Exception:  # noqa: BLE001 -- A failed history read cannot establish absence.
            out.reasons.add("SECRET_VERSION_LIST_FAILED")
