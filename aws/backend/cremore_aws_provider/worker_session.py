"""Account-bound clients for worker S3 reads and their credential checks."""

from __future__ import annotations

import threading
import time
import uuid
from contextlib import suppress

from cremore_aws_provider import aws_access
from cremore_aws_provider.aws_identity import AwsLoginRequired
from cremore_aws_provider.aws_readonly import readonly_client

# Re-proving the worker's own AWS identity builds a new SDK session and makes two AWS calls (STS and
# IAM) plus a settings write. Doing that before every S3 request tripled a bucket's AWS calls and added
# its latency to every object. A content read now re-proves it at most this often (and whenever role
# credentials are vended again), so an identity change stops reads within this window; the account,
# approval, revision and sign-in checks keep running on every request, around every streamed read and
# inside every fenced write. Keep it below JobWorker's identity cache (60 s): the fresh proof then keeps
# that cache warm, and concurrent readers' ordinary checks never find it expired and probe on their own.
FRESH_IDENTITY_SECONDS = 45.0
# A vend this soon after a proof needs no second one: nothing ran in between but the vend itself.
RECENT_PROOF_SECONDS = 5.0


class ContentSessions:
    """Pin one approved account per running job; never trust payload role fields.

    ``require_access`` is the platform's transaction-only authorization guard.
    A fenced write may check an existing pin, but cannot initialize a session
    or perform identity/credential I/O. Pins are discarded after each task.
    """

    def __init__(self, sessions, require_access, *, clock=time.monotonic):
        self.sessions, self.require_access = sessions, require_access
        self._clock = clock
        self._jobs = {}

    @staticmethod
    def _key(job):
        return job.id if job.id is not None else id(job)

    def _account_id(self, job, repo):
        p = job.payload or {}
        roots = [r for r in p.get("roots") or [] if r.get("resource_type") == "S3_BUCKET"]
        if not (job.kind == "s3" or (job.kind == "scope" and (p.get("connection_kind") == "aws" or roots))
                or (job.kind in ("catalog-refresh", "credential-check") and p.get("provider") == "aws")):
            return None
        account_id = str(p.get("account_id") or "")
        cid = job.connection_id or p.get("connection_id")
        if cid:
            try:
                cid = uuid.UUID(str(cid))
            except ValueError:
                raise aws_access.AccessBlocked("ACCOUNT_NOT_CONNECTED") from None
            if p.get("connection_kind") == "aws" or (job.kind == "s3" and repo.get_aws_account(cid) is not None):
                account = repo.get_aws_account(cid)
                registered_id = account.account_id if account else ""
            else:
                connection = repo.get_connection(cid)
                registered_id = (connection.config or {}).get("account_id", "") if connection and connection.provider == "aws" else ""
            if not registered_id:
                raise aws_access.AccessBlocked("ACCOUNT_NOT_CONNECTED")
            if account_id != registered_id:
                raise aws_access.AccessBlocked("ACCOUNT_MISMATCH")
        if not account_id:
            raise aws_access.AccessBlocked("ACCOUNT_OWNER_UNKNOWN")
        if any(r.get("account_id") and r["account_id"] != account_id for r in roots):
            raise aws_access.AccessBlocked("ACCOUNT_MISMATCH")
        return account_id

    def require_current(self, job, repo=None):
        account_id = self._account_id(job, repo if repo is not None else self.sessions.repo)
        if account_id is None:
            return
        key = self._key(job)
        owner = self._jobs.get(key)
        if owner is None:
            if repo is not None:
                raise aws_access.AccessBlocked("AWS_SESSION_UNAVAILABLE")
            owner = self._jobs[key] = _Account(self.sessions, account_id, clock=self._clock)
        if owner.account_id != account_id:
            owner.deny("ACCOUNT_MISMATCH")
        if repo is None:
            owner.current()
        else:
            owner.check_error()
            self.require_access(repo, account_id, owner.pin, self.sessions.settings)

    def client(self, job, service, region):
        self.require_current(job)
        owner = self._jobs.get(self._key(job))
        if owner is None:
            raise aws_access.AccessBlocked("ACCOUNT_OWNER_UNKNOWN")
        return readonly_client(_Client(owner, service, region), service)

    def release(self, job):
        self._jobs.pop(self._key(job), None)


class _Account:
    """One job's account authorization, shared by the reader threads of its scan."""

    def __init__(self, sessions, account_id, *, clock=time.monotonic):
        self.sessions, self.account_id = sessions, account_id
        self.pin = None
        self.error = None
        self._clock = clock
        self._fresh_at = None
        self._credentials = None
        self._lock = threading.Lock()

    def fresh_due(self) -> bool:
        """Whether this check re-proves the identity: the first one always, then every FRESH_IDENTITY_SECONDS.

        Claimed under the lock, so concurrent readers make one probe rather than one each.
        """
        with self._lock:
            now = self._clock()
            if self._fresh_at is not None and now - self._fresh_at < FRESH_IDENTITY_SECONDS:
                return False
            self._fresh_at = now
            return True

    def current(self):
        """The check before a content request: a fresh identity proof when one is due."""
        self._checked(self.fresh_due())

    def _proof_older_than(self, seconds) -> bool:
        with self._lock:
            return self._fresh_at is None or self._clock() - self._fresh_at >= seconds

    def _checked(self, fresh):
        try:
            self.check(fresh=fresh)
        except BaseException:
            if fresh:
                with self._lock:
                    self._fresh_at = None  # a proof that did not complete does not count as one
            raise
        if fresh:
            with self._lock:
                self._fresh_at = self._clock()

    def deny(self, code):
        self.error = code
        self.check_error()

    def check_error(self):
        if self.error == "AWS_LOGIN_REQUIRED":
            raise AwsLoginRequired()
        if self.error:
            raise aws_access.AccessBlocked(self.error)

    def check(self, *, fresh=True):
        self.check_error()
        code, account, approved = self.sessions.refusal(self.account_id, aws_access.SCANNER, fresh=fresh)
        if code:
            self.deny(code)
        pin = aws_access.validation_key(account, aws_access.SCANNER, approved["revision"])
        if self.pin is not None and self.pin != pin:
            self.deny("AWS_ACCESS_REVISION_CHANGED")
        self.pin = pin

    def open(self):
        self.current()
        try:
            # Opening runs the same refusal checks against current state before vending or reusing.
            session = self.sessions.open(self.account_id, aws_access.SCANNER)
        except AwsLoginRequired:
            self.deny("AWS_LOGIN_REQUIRED")
        except aws_access.AccessBlocked as exc:
            self.deny(exc.code)
        if session.pin != self.pin:
            self.deny("AWS_ACCESS_REVISION_CHANGED")
        # Re-check after a credential refresh, before making a content request: vending takes an AWS
        # call made with the worker's identity, which may have changed since the last proof (re-proved
        # here unless that proof is only seconds old), and authorization may have changed meanwhile.
        # Reused or ambient (runtime identity) credentials involved no call since the refusal check
        # inside open().
        if session.credentials is not None and session.credentials is not self._credentials:
            self._checked(self._proof_older_than(RECENT_PROOF_SECONDS))
            self._credentials = session.credentials
        return session


class _Client:
    def __init__(self, owner, service, region):
        self.owner, self.service, self.region = owner, service, region
        self._credentials = self._client = None
        self._lock = threading.Lock()

    def _current(self):
        session = self.owner.open()
        # Reader threads share this client; one of them builds the replacement after a refresh.
        with self._lock:
            if self._client is None or self._credentials is not session.credentials:
                self._client = session.client(self.service, self.region)
                self._credentials = session.credentials
            return self._client

    def __getattr__(self, operation):
        def call(*args, **kwargs):
            if self.service == "s3" and "Bucket" in kwargs:
                if kwargs.get("ExpectedBucketOwner", self.owner.account_id) != self.owner.account_id:
                    self.owner.deny("ACCOUNT_MISMATCH")
                kwargs["ExpectedBucketOwner"] = self.owner.account_id
            result = getattr(self._current(), operation)(*args, **kwargs)
            body = result.get("Body") if isinstance(result, dict) else None
            try:
                self.owner.check(fresh=False)
            except Exception:
                if body is not None:
                    with suppress(Exception):
                        body.close()
                raise
            if body is not None:
                result = {**result, "Body": _Body(body, self.owner)}
            return result
        return call

    def get_paginator(self, operation):
        from botocore.paginate import Paginator

        template = self._current().get_paginator(operation)
        # Keep botocore's token/limit semantics, but bind every page to our
        # guarded method instead of the SDK client that created the paginator.
        return Paginator(getattr(self, operation), template._pagination_cfg, template._model)

    def can_paginate(self, operation):
        return self._current().can_paginate(operation)


class _Body:
    """A streaming response must stop reading when its authorization is lost."""

    def __init__(self, body, owner):
        self.body, self.owner = body, owner

    def read(self, *args, **kwargs):
        self.owner.check(fresh=False)
        result = self.body.read(*args, **kwargs)
        self.owner.check(fresh=False)
        return result

    def close(self):
        self.body.close()
