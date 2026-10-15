"""Falcon LogScale structured ingestion (not Falcon NG-SIEM connectors).

https://library.humio.com/logscale-api/api-ingest-structured-data.html
https://library.humio.com/logscale-api/api-ingest.html
"""

from cremore.siem.contract import SinkProvider, event_family
from cremore.siem.sinks._http import HTTPSink, event_time


class LogScaleSink(HTTPSink):
    def __init__(self, options):
        super().__init__(options, require_token=True,
                         required_path="/api/v1/ingest/humio-structured")

    def send(self, event: dict) -> None:
        # The event family is a tag, so each kind lands in its own datasource
        # (few, fixed values: finding, connection, collection, platform, ...).
        self._post([{"tags": {"source": "cremore", "family": event_family(event.get("event_type"))}, "events": [
            {"timestamp": event_time(event).isoformat(), "attributes": event},
        ]}], status=200)


PROVIDER = SinkProvider(id="logscale", build=LogScaleSink)
