"""Splunk HTTP Event Collector event endpoint; acceptance is not indexer ACK."""

from cremore.siem.contract import DeliveryError, SinkProvider, event_family
from cremore.siem.sinks._http import HTTPSink, event_time


class SplunkHECSink(HTTPSink):
    def __init__(self, options):
        super().__init__(options, scheme="Splunk", require_token=True,
                         required_path="/services/collector/event")

    def send(self, event: dict) -> None:
        # One sourcetype per event family: cremore:finding keeps its meaning and
        # operational events (cremore:connection, cremore:platform, ...) get their own.
        sourcetype = "cremore:" + event_family(event.get("event_type"))
        response = self._post({"event": event, "time": event_time(event).timestamp(),
                               "source": "cremore", "sourcetype": sourcetype}, status=200)
        try:
            result = response.json()
            if not isinstance(result, dict) or type(result.get("code")) is not int or result["code"] != 0:
                raise ValueError
        except (TypeError, ValueError, RecursionError):
            raise DeliveryError("HEC_RESPONSE_REJECTED") from None


PROVIDER = SinkProvider(id="splunk_hec", build=SplunkHECSink)
