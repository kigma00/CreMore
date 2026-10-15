"""Bounded CloudTrail identity observations, not a complete STS issuance registry."""

from __future__ import annotations

import gzip
import io
import json
import re
from datetime import UTC, datetime, timedelta
from time import sleep

from cremore.coverage.collection import Collection, CollectionLimit
from cremore.coverage.models import AWSSession, CollectionOperation, Observation, digest
from cremore_aws_provider.investigation.usage import event_outcome

_KEY = re.compile(r"(?:AKIA|ASIA)[A-Z0-9]{16}")
_ARN = re.compile(r"arn:(aws|aws-us-gov|aws-cn|aws-eusc):(iam|sts)::([0-9]{12}):[A-Za-z0-9/+=,.@_-]+")
_ISSUANCE = frozenset({"AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity", "GetSessionToken", "GetFederationToken", "AssumeRoot"})
_MONTHS = {name: index + 1 for index, name in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}
# CloudTrail's delivery layout (User Guide, "Finding your CloudTrail log files"):
#   <trail prefix>/AWSLogs/[<organization id>/]<account id>/<event type>/<region>/<YYYY>/<MM>/<DD>/<file>
# YYYY/MM/DD is the day the file was published. Management and data events are under
# "CloudTrail" and network activity events under "CloudTrail-NetworkActivity"; digest,
# Insights and aggregated files hold no per-call identity and are not read.
_EVENT_DIRECTORIES = ("CloudTrail", "CloudTrail-NetworkActivity")
_OTHER_EVENT_DIRECTORIES = ("CloudTrail-Digest", "CloudTrail-Insight", "CloudTrail-Aggregated")
_ORGANIZATION_DIRECTORY = re.compile(r"o-[a-z0-9]{10,32}")
_ACCOUNT_DIRECTORY = re.compile(r"[0-9]{12}")
_REGION_DIRECTORY = re.compile(r"[a-z]{2,4}(?:-[a-z]+)+-[0-9]+")


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _arn(value):
    return value if isinstance(value, str) and _ARN.fullmatch(value) else ""


def _account(arn):
    match = _ARN.fullmatch(arn)
    return match[3] if match else ""


def _history_pages(out, client, *, sleep_fn, **kwargs):
    def checked(**params):
        if params.get("NextToken"):
            sleep_fn(0.55)
            out.checkpoint()
        response = client.lookup_events(**params)
        if (not isinstance(response, dict) or not isinstance(response.get("Events"), list)
                or (response.get("NextToken") is not None and not isinstance(response["NextToken"], str))):
            raise ValueError("INVALID_EVENT_HISTORY_PAGE")
        return response
    return out.pages(checked, "Events", token_in="NextToken", token_out="NextToken", **kwargs)


def _time(value, *, legacy=False):
    if not value:
        return ""
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("INVALID_EVENT_TIME")
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))  # noqa: FURB162
    except ValueError:
        # The documented STS CloudTrail response uses this UTC representation,
        # unlike eventTime. Parse English months independently of process locale.
        match = re.fullmatch(r"([A-Z][a-z]{2}) ([0-9]{1,2}), ([0-9]{4}), ([0-9]{1,2}):([0-9]{2}):([0-9]{2}) (AM|PM)", value) if legacy else None
        if not match or match[1] not in _MONTHS or not 1 <= int(match[4]) <= 12:
            raise ValueError("INVALID_EVENT_TIME") from None
        hour = int(match[4]) % 12 + (12 if match[7] == "PM" else 0)
        stamp = datetime(int(match[3]), _MONTHS[match[1]], int(match[2]), hour, int(match[5]), int(match[6]), tzinfo=UTC)
    if stamp.tzinfo is None:
        raise ValueError("EVENT_TIMEZONE_REQUIRED")
    return stamp.astimezone(UTC).isoformat()


def event_observations(record, spec, *, event_id, region, source, start, end):
    """Allowlist facts from one event; returned objects never contain token bytes."""
    if not isinstance(record, dict):
        raise TypeError("EVENT_METADATA_MALFORMED")
    recipient = record.get("recipientAccountId")
    if not isinstance(recipient, str) or not re.fullmatch(r"[0-9]{12}", recipient):
        raise ValueError("EVENT_ACCOUNT_REQUIRED")
    if recipient != spec.account_id:
        return []
    event_region = record.get("awsRegion", region)
    if event_region not in spec.regions:
        return []
    stamp = _time(record.get("eventTime"))
    if not stamp:
        raise ValueError("EVENT_TIME_REQUIRED")
    if not start <= datetime.fromisoformat(stamp) <= end:
        return []
    identity = _mapping(record.get("userIdentity"))
    context = _mapping(identity.get("sessionContext"))
    issuer = _mapping(context.get("sessionIssuer"))
    attributes = _mapping(context.get("attributes"))
    event_name = record.get("eventName") or "UnknownEvent"
    if spec.cloudtrail_event_name and event_name != spec.cloudtrail_event_name:
        return []
    event_source = record.get("eventSource") or ""
    event_id = record.get("eventID") or event_id
    caller_arn = _arn(identity.get("arn"))
    caller_key = identity.get("accessKeyId")
    caller_key = caller_key if isinstance(caller_key, str) and _KEY.fullmatch(caller_key) else ""
    category = record.get("eventCategory", "Management" if source == "EVENT_HISTORY" else "Unknown")
    if category not in ("Management", "Data", "NetworkActivity", "Unknown"):
        raise ValueError("INVALID_EVENT_CATEGORY")
    common = {"recipient_account_id": spec.account_id, "event_id": event_id,
              "event_name": event_name, "event_source": event_source,
              "event_category": category, "evidence_source": source,
              "outcome": event_outcome(record.get("eventName"), record.get("errorCode"))}
    location = {"reference": ("event-history/" if source == "EVENT_HISTORY" else "trail-s3/") + str(event_id),
                "account_id": spec.account_id, "region": event_region, "credential_type": "AWS_ACCESS_KEY"}
    result = []
    if event_source == "iam.amazonaws.com" and event_name == "CreateAccessKey" and not record.get("errorCode"):
        # The created key is in the response, not userIdentity.accessKeyId (the caller's key).
        key = _mapping(_mapping(record.get("responseElements")).get("accessKey"))
        created_key = key.get("accessKeyId")
        if isinstance(created_key, str) and re.fullmatch(r"AKIA[A-Z0-9]{16}", created_key) and caller_arn:
            session = AWSSession(**common, caller_arn=caller_arn, issued_at=stamp)
            result.append(Observation(**location, evidence="KEY_CREATED", identifier=created_key,
                                      state="OBSERVED", created_at=stamp, session=session))
    if caller_key:
        session_arn = caller_arn if ":sts::" in caller_arn else ""
        issuer_arn = _arn(issuer.get("arn")) or (caller_arn if ":iam::" in caller_arn else "")
        session = AWSSession(**common, issuer_account_id=_account(session_arn or issuer_arn),
            issuer_arn=issuer_arn, session_arn=session_arn, caller_arn=caller_arn,
            source_identity=context.get("sourceIdentity") or "",
            session_name=session_arn.rsplit("/", 1)[-1] if session_arn else "",
            issued_at=_time(attributes.get("creationDate")), first_used_at=stamp, last_used_at=stamp)
        result.append(Observation(**location, evidence="USAGE", identifier=caller_key,
                                  principal_arn=caller_arn, state="OBSERVED", last_used_at=stamp, session=session))
    if event_source == "sts.amazonaws.com" and event_name in _ISSUANCE and not record.get("errorCode"):
        response = _mapping(record.get("responseElements"))
        credentials = _mapping(response.get("credentials"))
        issued_key = credentials.get("accessKeyId")
        if not isinstance(issued_key, str) or not re.fullmatch(r"ASIA[A-Z0-9]{16}", issued_key):
            return result  # Missing response evidence never establishes an issued key.
        request = _mapping(record.get("requestParameters"))
        principal = _mapping(response.get("assumedRoleUser")) or _mapping(response.get("federatedUser"))
        session_arn = _arn(principal.get("arn"))
        issuer_arn = _arn(request.get("roleArn"))
        if event_name in ("GetSessionToken", "GetFederationToken"):
            issuer_arn = caller_arn
        session = AWSSession(**common, issuer_account_id=_account(session_arn or issuer_arn),
            issuer_arn=issuer_arn, session_arn=session_arn, caller_arn=caller_arn, caller_access_key_id=caller_key,
            source_identity=response.get("sourceIdentity") or request.get("sourceIdentity") or "",
            session_name=request.get("roleSessionName") or (session_arn.rsplit("/", 1)[-1] if session_arn else ""),
            issued_at=stamp, expires_at=_time(credentials.get("expiration"), legacy=True))
        if session.expires_at and datetime.fromisoformat(session.expires_at) < datetime.fromisoformat(stamp):
            raise ValueError("INVALID_SESSION_EXPIRATION")
        result.append(Observation(**location, evidence="SESSION_ISSUED", identifier=issued_key,
            principal_arn=session_arn or issuer_arn, state="OBSERVED", created_at=stamp, session=session))
    return result


def _read_body(body, limit, checkpoint):
    chunks, size = [], 0
    try:
        while size <= limit:
            checkpoint()
            chunk = body.read(min(65536, limit + 1 - size))
            if not chunk:
                break
            if not isinstance(chunk, bytes):
                raise TypeError("INVALID_LOG_BODY")
            chunks.append(chunk)
            size += len(chunk)
        if size > limit:
            raise ValueError("LOG_SIZE_LIMIT")
        return b"".join(chunks)
    finally:
        body.close()


def _directories(out, client, prefix):
    """One level of layout evidence, including log files outside child directories."""
    names, loose_logs = [], False

    def listed(**kwargs):
        nonlocal loose_logs
        response = client.list_objects_v2(**kwargs)
        loose_logs |= any(isinstance(item, dict) and isinstance(item.get("Key"), str)
                          and item["Key"].endswith((".json", ".json.gz"))
                          for item in response.get("Contents", []))
        return response

    for entry in out.pages(listed, "CommonPrefixes", token_in="ContinuationToken",
                           token_out="NextContinuationToken", Bucket=out.spec.trail_bucket, Prefix=prefix,
                           Delimiter="/", MaxKeys=1000):
        value = entry.get("Prefix") if isinstance(entry, dict) else None
        name = value[len(prefix):-1] if isinstance(value, str) and value.startswith(prefix) and value.endswith("/") else ""
        if name and "/" not in name:
            names.append(name)
    return names, loose_logs


def _log_listings(out, client, prefix, start):
    """Where this account's logs for the window sit under a configured directory.

    Records are kept only for this account, its regions and the window (event_observations),
    so following the layout lists and downloads only those files: an organization-wide prefix
    no longer makes every account read every account's history, and no run re-reads the
    history before its window. Returns (prefix, StartAfter) listings, or None when the
    directory is not laid out by CloudTrail (nothing it names below AWSLogs), which is then
    read whole as before.
    """
    account, regions = out.spec.account_id, set(out.spec.regions)
    parts = [part for part in prefix.split("/") if part]
    at = parts.index("AWSLogs") if "AWSLogs" in parts else len(parts)
    base, rest = "/".join([*parts[:at], "AWSLogs"]) + "/", parts[at + 1:]
    if at == len(parts):
        children, loose_logs = _directories(out, client, prefix)
        if loose_logs or children != ["AWSLogs"]:
            return None  # A broad prefix can also hold imported or reorganized logs.
    organization = rest.pop(0) if rest and _ORGANIZATION_DIRECTORY.fullmatch(rest[0]) else None
    named = rest.pop(0) if rest else None
    kind = rest.pop(0) if rest else None
    region = rest.pop(0) if rest else None
    if (named is not None and not _ACCOUNT_DIRECTORY.fullmatch(named)
            or kind is not None and kind not in _EVENT_DIRECTORIES + _OTHER_EVENT_DIRECTORIES
            or region is not None and not _REGION_DIRECTORY.fullmatch(region)):
        return None  # Below AWSLogs, but not CloudTrail's layout: read it whole, as configured.
    if named not in (None, account) or kind in _OTHER_EVENT_DIRECTORIES or region not in (None, *regions):
        return []  # Another account's, event type's or region's files: no kept record is there.
    if organization is not None or named is not None:
        roots = [base + (organization + "/" if organization else "")]
    else:
        # An organization trail adds its organization id below AWSLogs; a single-account trail does not.
        children, loose_logs = _directories(out, client, base)
        if loose_logs or not children or not all(
                _ACCOUNT_DIRECTORY.fullmatch(child) or _ORGANIZATION_DIRECTORY.fullmatch(child) for child in children):
            return None
        roots = ([base] if account in children else []) + [
            base + child + "/" for child in children if _ORGANIZATION_DIRECTORY.fullmatch(child)]
    # The path date is the publication day, never earlier than the events in the file; one
    # day earlier also covers the time zone of that date.
    first = (start - timedelta(days=1)).strftime("%Y/%m/%d/")
    listings = []
    for root in roots:
        if named is None:
            children, loose_logs = _directories(out, client, root)
            # The shared AWSLogs root may also contain organization roots.
            if loose_logs or any(not (_ACCOUNT_DIRECTORY.fullmatch(child)
                    or root == base and _ORGANIZATION_DIRECTORY.fullmatch(child)) for child in children):
                return None
        home = root + account + "/"
        event_types, loose_logs = ([kind], False) if kind else _directories(out, client, home)
        if loose_logs or any(name not in _EVENT_DIRECTORIES + _OTHER_EVENT_DIRECTORIES for name in event_types):
            return None
        for event_type in [name for name in event_types if name in _EVENT_DIRECTORIES]:
            directory = home + event_type + "/"
            listed_regions, loose_logs = ([region], False) if region else _directories(out, client, directory)
            if loose_logs or any(not _REGION_DIRECTORY.fullmatch(name) for name in listed_regions):
                return None
            for listed_region in [name for name in listed_regions if name in regions]:
                listed = directory + listed_region + "/"
                # A prefix that already names a date keeps it and is read whole.
                listings.append((listed + "/".join(rest) + "/", None) if rest else (listed, listed + first))
    return listings


def _s3_events(out, client, start):
    seen = set()
    for prefix in out.spec.trail_prefixes:
        # Match the configured directory, not similarly named neighboring paths.
        prefix = prefix.rstrip("/") + "/"
        listings = _log_listings(out, client, prefix, start)
        for listing, after in [(prefix, None)] if listings is None else listings:
            yield from _listed_events(out, client, listing, after, seen)


def _listed_events(out, client, prefix, after, seen):
    """The records of the logs listed under one prefix (after a key, when given), within the object limit."""
    for obj in out.pages(client.list_objects_v2, "Contents", token_in="ContinuationToken",
                         token_out="NextContinuationToken", Bucket=out.spec.trail_bucket, Prefix=prefix, MaxKeys=1000,
                         **({"StartAfter": after} if after else {})):
        if not isinstance(obj, dict) or not isinstance(obj.get("Key"), str):
            out.reasons.add("CLOUDTRAIL_LOG_LIST_MALFORMED")
            continue
        key = obj["Key"]
        if not key.startswith(prefix) or any(part in (".", "..") for part in key.split("/")) or "\\" in key:
            out.reasons.add("CLOUDTRAIL_LOG_OUTSIDE_SCOPE")
            continue
        if not key.endswith((".json.gz", ".json")) or "/CloudTrail-Digest/" in key or key in seen:
            continue
        if len(seen) >= out.spec.max_records:
            raise CollectionLimit("LOG_OBJECT_LIMIT")
        seen.add(key)
        try:
            if type(obj.get("Size")) is not int or obj["Size"] < 0 or obj["Size"] > out.spec.max_value_bytes:
                raise ValueError("LOG_SIZE_LIMIT")
            response = out.call(client.get_object, Bucket=out.spec.trail_bucket, Key=key)
            body = response.get("Body")
            if body is None:
                raise ValueError("LOG_BODY_MISSING")
            raw = _read_body(body, out.spec.max_value_bytes, out.checkpoint)
            if key.endswith(".gz"):
                with gzip.GzipFile(fileobj=io.BytesIO(raw)) as archive:
                    raw = archive.read(out.spec.max_value_bytes + 1)
                if len(raw) > out.spec.max_value_bytes:
                    raise ValueError("LOG_SIZE_LIMIT")
            records = _mapping(json.loads(raw)).get("Records")
            if not isinstance(records, list):
                raise TypeError("LOG_RECORDS_MISSING")
            for record in records:
                out.checkpoint()
                yield record
        except CollectionLimit:
            raise
        except Exception:  # noqa: BLE001 -- Never expose SDK messages, event payloads or token fields.
            out.reasons.add("CLOUDTRAIL_LOG_READ_FAILED")


def collect_usage(spec, client_factory, *, checkpoint=None, now=None, s3_client=None, sleep_fn=sleep):
    out = Collection(spec, checkpoint=checkpoint)
    end = now or datetime.now(UTC)
    start = end - timedelta(days=spec.window_days)
    seen, reports = {}, []
    events_read = 0

    def charge_event():
        nonlocal events_read
        out.checkpoint()
        if events_read >= spec.max_records:
            raise CollectionLimit("EVENT_SCAN_LIMIT")
        events_read += 1

    def observe(record, event_id="", region=""):
        try:
            if (isinstance(record, dict) and record.get("eventSource") == "sts.amazonaws.com"
                    and record.get("eventName") in _ISSUANCE and not record.get("errorCode")
                    and record.get("recipientAccountId") == spec.account_id
                    and not re.fullmatch(r"ASIA[A-Z0-9]{16}", str(_mapping(_mapping(record.get("responseElements")).get("credentials")).get("accessKeyId", "")))):
                out.reasons.add("STS_ISSUANCE_METADATA_NOT_RETURNED")
            observations = event_observations(record, spec, event_id=event_id, region=region,
                source="EVENT_HISTORY" if spec.cloudtrail_source == "event_history" else "TRAIL_S3", start=start, end=end)
            for item in observations:
                key = (item.region, item.session.event_id, item.evidence, item.identifier)
                signature = digest(item.model_dump())
                if key in seen:
                    if seen[key] != signature:
                        out.reasons.add("CLOUDTRAIL_EVENT_CONFLICT")
                    continue
                out.add(item)
                seen[key] = signature
        except CollectionLimit:
            raise
        except Exception:  # noqa: BLE001 -- Only fixed reason codes cross the event parsing boundary.
            out.reasons.add("EVENT_METADATA_MALFORMED")

    scopes = spec.regions if spec.cloudtrail_source == "event_history" else [""]
    for region in scopes:
        before_requests, before_items = out.requests, len(out.items)
        before_reasons = set(out.reasons)
        out.reasons.clear()
        error = None
        limited = False
        try:
            if spec.cloudtrail_source == "s3":
                if s3_client is None:
                    raise ValueError("CLOUDTRAIL_LOG_CLIENT_REQUIRED")
                for record in _s3_events(out, s3_client, start):
                    charge_event()
                    observe(record)
            else:
                client = client_factory(region)
                selection = ({"LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": spec.cloudtrail_event_name}]}
                             if spec.cloudtrail_event_name else {})
                for event in _history_pages(out, client, sleep_fn=sleep_fn, StartTime=start, EndTime=end, MaxResults=50, **selection):
                    charge_event()
                    if not isinstance(event, dict):
                        out.reasons.add("EVENT_METADATA_MALFORMED")
                        continue
                    raw = event.get("CloudTrailEvent", "")
                    if not isinstance(raw, str) or len(raw.encode()) > spec.max_value_bytes:
                        out.reasons.add("EVENT_SIZE_LIMIT")
                        continue
                    try:
                        record = json.loads(raw)
                    except (ValueError, RecursionError):
                        out.reasons.add("EVENT_METADATA_MALFORMED")
                        continue
                    observe(record, event.get("EventId", ""), region)
        except CollectionLimit as exc:
            error = str(exc)
            limited = True
            out.reasons.add(error)
        except Exception as exc:  # noqa: BLE001 -- SDK failures must not leak credentials or raw logs.
            from cremore_aws_provider.aws_identity import error_code

            denied = error_code(exc) in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}
            error = ("EVENT_HISTORY_COLLECTION_DENIED" if denied else "EVENT_HISTORY_COLLECTION_FAILED") if region else "CLOUDTRAIL_LOG_COLLECTION_FAILED"
            out.reasons.add(error)
        reasons = set(out.reasons)
        out.reasons.update(before_reasons)
        count = len(out.items) - before_items
        status = "PARTIAL" if count else "FAILED"
        reports.append(Observation(reference="region/" + region if region else "account/" + spec.account_id,
            account_id=spec.account_id, region=region, evidence="OPERATION",
            operation=CollectionOperation(name="LOOKUP_EVENTS" if region else "READ_TRAIL_LOGS",
                status=status if error or reasons else "COMPLETE", requests=out.requests - before_requests,
                records=count, reason=error or next(iter(sorted(reasons)), None))))
        if limited:
            break
    for report in reports:
        try:
            out.add(report)
        except CollectionLimit:
            out.reasons.add("OPERATION_REPORT_LIMIT")
            break
    return out
