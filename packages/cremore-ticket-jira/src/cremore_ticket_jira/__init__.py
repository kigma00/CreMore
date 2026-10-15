"""Opt-in Jira ticket system: installed as a ``cremore.ticket_systems`` entry point, allowed by TICKET_SYSTEM_PLUGINS."""

from .jira import PROVIDER

__all__ = ["PROVIDER"]
