"""What a ticket system adapter offers CreMore, and what it is given.

An adapter finds the one account a person has in the system by their mail address (with every address that
account carries, so CreMore can tell the owner apart from the security side), opens a ticket that asks that
account for the system's own approval, and later says how that approval was answered. It receives its setup (plain
values and opened secrets) and an HTTP client, never a repository; it raises TicketError with a fixed code, never
text from a response.
"""

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Literal, Protocol

_CODE = re.compile(r"[A-Z0-9_]{1,64}")


class TicketError(Exception):
    """A refused or failed call. ``retryable``: the system did not answer, try again later. ``ticket``: a ticket
    that was opened before the failure (a person closes it in the system)."""

    def __init__(self, code: str, *, retryable: bool = False, ticket: str = ""):
        super().__init__(code)
        self.code, self.retryable, self.ticket = code, retryable, ticket


def safe_code(error) -> str:
    """An error's code as CreMore writes it in an audit note or a response: an installed adapter's own text never."""
    code = getattr(error, "code", None) if isinstance(error, TicketError) else str(error)
    return code if isinstance(code, str) and _CODE.fullmatch(code) else "TICKET_SYSTEM_ERROR"


@dataclass(frozen=True)
class Field:
    """One setup value the admin enters. ``secret`` values are sealed and never shown again."""

    name: str
    label: str
    label_ko: str
    kind: Literal["url", "text", "number", "secret"] = "text"
    required: bool = True
    hint: str = ""


@dataclass(frozen=True)
class Approver:
    """The one account a person has in the system, and every mail address it carries."""

    id: str
    addresses: tuple[str, ...]


@dataclass(frozen=True)
class ApprovalRequest:
    """Plain text: the adapter escapes it for its own format."""

    title: str
    lines: tuple[str, ...]
    report_required: bool = False  # remediation completion only; never key-execution approval


@dataclass(frozen=True)
class Opened:
    """The system's own references: the ticket, the approval asked in it and the account asked."""

    ticket: str
    approval: str
    approver: str
    url: str = ""  # where a person opens the ticket


@dataclass(frozen=True)
class Answer:
    state: Literal["WAITING", "APPROVED", "DECLINED"]
    by: str = ""  # the account that answered
    at: str = ""  # when, ISO 8601 as the system reports it
    comment: str = ""  # plain text, bounded by the adapter
    report: Mapping[str, object] | None = None  # untrusted structured statement; platform validates before saving


class TicketSystem(Protocol):
    def check(self) -> None:
        """Sign in and read what asking needs; raise TicketError if something is missing."""

    def find_approver(self, address: str) -> Approver:
        """The one active account with this address (not the adapter's own); TicketError when none or several."""

    def open_approval(self, request: ApprovalRequest, approver: Approver) -> Opened: ...

    def answer(self, opened: Opened) -> Answer: ...

    def close(self) -> None: ...


@dataclass(frozen=True)
class TicketSystemProvider:
    id: str
    label: str
    fields: tuple[Field, ...]
    # (setup values, opened secrets, HTTP client) -> system; validates the values (ValueError with a code).
    build: Callable[[Mapping[str, object], Mapping[str, str], object], TicketSystem]
    validate: Callable[[Mapping[str, object]], dict]
    api_version: int = 1
