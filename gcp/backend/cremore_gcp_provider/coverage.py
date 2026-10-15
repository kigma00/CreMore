"""gcp bounded read-only inventory functions."""
from __future__ import annotations

import base64
import re

from cremore.coverage.collection import Collection, CollectionLimit
from cremore.coverage.models import Observation, in_scope
from cremore.http_client import bounded_request


def collect_gcp(spec, client, access_token, engine):
    out = Collection(spec)
    number = None  # the approved project's number, once its own Resource Manager record names it

    def request(path, params=None, base="https://secretmanager.googleapis.com/v1/"):
        response = bounded_request(client, "GET", base + path,
                                   params=params, headers={"Authorization": "Bearer " + access_token()},
                                   follow_redirects=False, retry_429=True, before_attempt=out.charge,
                                   max_response_bytes=spec.max_value_bytes * 2 + (64 << 10))
        if response.status_code != 200:
            raise ValueError("GCP_REQUEST_FAILED")
        return response.json()

    def canonical(name):
        """Google answers with the project number; only a number projects.get binds to the ID is rewritten."""
        nonlocal number
        match = re.fullmatch(r"projects/([1-9][0-9]{0,19})/(.+)", name) if isinstance(name, str) else None
        if match is None:
            return name
        if number is None:
            try:
                row = request(f"projects/{spec.project}", base="https://cloudresourcemanager.googleapis.com/v3/")
            except CollectionLimit:
                raise
            except ValueError:  # refused or unreadable: numeric names stay outside the scope
                row = {}
            bound = row.get("name") if isinstance(row, dict) and row.get("projectId") == spec.project else None
            number = bound.split("/")[1] if isinstance(bound, str) and re.fullmatch(
                r"projects/[1-9][0-9]{0,19}", bound) else ""
        return f"projects/{spec.project}/{match.group(2)}" if match.group(1) == number else name

    try:
        def records():
            if spec.references:
                yield from spec.references
                return
            seen, token = set(), ""
            while True:
                page = request(f"projects/{spec.project}/secrets", {"pageSize": 100, "pageToken": token})
                yield from (secret["name"] for secret in page.get("secrets", []))
                token = page.get("nextPageToken")
                if not token:
                    break
                if token in seen:
                    raise CollectionLimit("PAGINATION_LOOP")
                seen.add(token)

        for name in map(canonical, records()):
            location = {"reference": name}
            if not in_scope(spec, Observation(**location, evidence="UNRESOLVED", reason="CHECKING_SCOPE")):
                out.reasons.add("PROVIDER_SCOPE_MISMATCH")
                continue
            try:
                response = request(name + "/versions/" + spec.version_selector + ":access")
                version_path = canonical(response["name"])
                if not version_path.startswith(name + "/versions/") or not version_path.rsplit("/", 1)[1].isdigit():
                    raise ValueError("GCP_VERSION_MISMATCH")
                location.update(version=version_path.rsplit("/", 1)[1],
                                version_state="CURRENT" if spec.version_selector == "latest" else "UNKNOWN")
                value = base64.b64decode(response["payload"]["data"], validate=True)
                # TLS authenticates transport. The provider's optional CRC32C
                # is not treated as evidence of credential equality.
                out.value(engine, value, location)
            except CollectionLimit:
                raise
            except Exception:  # noqa: BLE001 -- SDK/secret parsing failures must produce fixed incomplete-collection reason codes.
                out.unresolved(location, "GCP_VERSION_READ_FAILED")
    except CollectionLimit as exc:
        out.reasons.add(str(exc))
    except Exception:  # noqa: BLE001 -- SDK/secret parsing failures must produce fixed incomplete-collection reason codes.
        out.reasons.add("GCP_SECRET_LIST_FAILED")
    return out
