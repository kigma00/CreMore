"""The dashboard contract, one module per area.

``register_dashboard_routes`` supplies application-scoped dependencies through
an explicit context. Reusable services and response projections live outside
the composition root, so registrars can be imported independently.

AREAS is in the order the routes were registered in before they were split
out, and that order is load-bearing: FastAPI matches in registration order,
so a literal path registered after a matching ``{placeholder}`` never runs.
``test_no_route_is_unreachable_behind_an_earlier_parameterised_one`` fails
if a reordering ever buries one.
"""

from __future__ import annotations

from cremore.api.route_context import DashboardContext as DashboardContext
from cremore.api.routes import (
    alerts,
    aws,
    credentials,
    findings,
    governance,
    leavers,
    misc,
    onboarding,
    rules,
    scans,
    secrets,
    settings,
    siem,
    sources,
)

# Registration order, which is not the alphabetical order the imports above
# were sorted into. It is the order these routes were registered in before
# the split, and FastAPI matches in registration order.
AREAS = (aws, sources, governance, misc, settings, findings, scans, secrets, rules, siem, leavers, onboarding,
         credentials, alerts)


def register_areas(ctx: DashboardContext) -> None:
    for area in AREAS:
        area.register(ctx)
