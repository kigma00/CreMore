"""The worker's minute for the approvals asked in a plugin ticket system: read each answer, record it.

Reading the approval itself is the source of truth (a webhook would need a way in past the sign-in proxy). One worker
reads per minute, only while approvals are waiting, within ``BUDGET_SECONDS`` of the worker's loop, and stops at the
first sign that the system is not answering. A request asked on another server than the one set up now
(``setup.binding``) is not read. Exposure responses asked by Slack, mail or record are not read here
(cremore.governance.response.pending lists ticket requests only).
"""

from __future__ import annotations

import datetime as _dt
import logging
import time
import uuid

from cremore.governance import response
from cremore.remediation import owner_approval
from cremore.ticketing import setup
from cremore.ticketing.contract import Opened, TicketError, safe_code

SWEEP_KEY = "ticketing:owner-approvals:sweep"
CURSOR_KEY = "ticketing:answers:cursor"
ACTOR = "system:ticketing"
BUDGET_SECONDS = 20  # the loop's share for the ticket system; what is left waits for the next minute

logger = logging.getLogger(__name__)


def _queue(repo, approvals, responses):
    """Resume after the last attempted item, across both kinds and worker ticks."""
    items = sorted([("owner:" + identity, "owner", identity, value) for identity, value in approvals]
                   + [("response:" + identity, "response", identity, value) for identity, value in responses])
    last = ((repo.get_setting(CURSOR_KEY) or {}).get("value") or {}).get("last", "")
    return [item for item in items if item[0] > last] + [item for item in items if item[0] <= last]


def sweep(repo, settings, http_client, *, now=None, clock=time.monotonic, orchestrator=None) -> int:
    """One maintenance tick: the answers recorded (approved, declined, or refused as not the owner's)."""
    fixed_now = now
    now = now or _dt.datetime.now(_dt.UTC)
    waiting = owner_approval.pending_tickets(repo, now)
    responses = response.pending(repo, now=now)
    if not (waiting or responses) or not repo.claim_slot(SWEEP_KEY, int(now.timestamp()) // 60, ACTOR):
        return 0
    separate = settings.auth_mode == "oidc"
    queued = _queue(repo, waiting, responses)
    deadline = clock() + BUDGET_SECONDS
    client = http_client()
    try:
        try:
            # The system, its name and its server binding come from one reading of the setup.
            system, system_name, binding = setup.open_system(repo, settings, client)
        except TicketError as exc:
            for key, kind, identity, value in queued:
                if clock() > deadline:
                    break
                check = owner_approval.ticket_checked if kind == "owner" else response.checked
                request = value["ticket"]["request"] if kind == "owner" else value["request_id"]
                check(repo, identity, request, safe_code(exc))
                repo.put_setting(CURSOR_KEY, {"last": key}, ACTOR)
            return 0
        recorded = 0
        try:
            for key, kind, identity, value in queued:
                if clock() > deadline:
                    break
                ticket = value["ticket"]
                request = ticket["request"] if kind == "owner" else value["request_id"]
                check = owner_approval.ticket_checked if kind == "owner" else response.checked
                try:
                    if ticket.get("system") != system_name or ticket.get("binding") != binding:
                        # Asked on a server the installation no longer uses: its numbers may name other tickets here.
                        check(repo, identity, request, "TICKET_SYSTEM_CHANGED")
                        continue
                    try:
                        answer = system.answer(Opened(ticket=ticket["ticket"], approval=ticket["approval"],
                                                      approver=ticket["approver"], url=ticket.get("url") or ""))
                    except TicketError as exc:
                        check(repo, identity, request, safe_code(exc))
                        if exc.retryable:
                            return recorded  # not answering: one wait is enough this minute
                        continue
                    if kind == "owner":
                        check(repo, identity, request, None)
                        if owner_approval.ticket_answered(repo, identity, request, answer, now,
                            lambda plan_id: repo.get_action_plan(uuid.UUID(plan_id)), separate=separate):
                            recorded += 1
                    else:
                        if answer.report is not None:
                            # An address reassigned or removed in the ticket directory must not
                            # keep the old approval account bound to the selected IdP person.
                            try:
                                current = system.find_approver(value["assigned_to"])
                            except TicketError as exc:
                                check(repo, identity, request, safe_code(exc))
                                if exc.retryable:
                                    return recorded
                                continue
                            if (current.id != ticket["approver"] or value["assigned_to"].casefold()
                                    not in [a.casefold() for a in current.addresses if isinstance(a, str)]):
                                check(repo, identity, request, "RESPONSE_REPORT_RECIPIENT_REQUIRED")
                                continue
                        from cremore.governance.response_reports import credential_types

                        received_at = fixed_now or _dt.datetime.now(_dt.UTC)
                        if response.answered(repo, identity, request, answer, system=system_name,
                                             binding=binding, received_at=received_at, settings=settings,
                                             contains_credentials=(lambda text: credential_types(orchestrator, text))
                                             if orchestrator is not None else None):
                            recorded += 1
                        elif answer.state == "WAITING":
                            check(repo, identity, request, None)
                except Exception as exc:  # noqa: BLE001 -- adapter text never reaches output
                    logger.warning("ticket answer read failed: %s", type(exc).__name__)
                finally:
                    repo.put_setting(CURSOR_KEY, {"last": key}, ACTOR)
        finally:
            system.close()
        return recorded
    finally:
        client.close()
