"""Opt-in Slack output; credentials and durable delivery belong to the exporter."""

from cremore.siem import SinkProvider

from .sink import SlackSink

PROVIDER = SinkProvider(id="slack_alerts", build=SlackSink)

__all__ = ["PROVIDER"]
