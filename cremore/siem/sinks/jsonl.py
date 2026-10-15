"""Write sanitized events to the process's stdout for an operator log shipper."""

import sys
from collections.abc import Mapping

from cremore.siem.contract import DeliveryError, SinkProvider
from cremore.siem.sinks._http import json_line


class JsonlSink:
    def __init__(self, options: Mapping[str, object]):
        if not isinstance(options, Mapping) or options:
            raise ValueError("SIEM_OPTIONS_INVALID")

    def send(self, event: dict) -> None:
        line = json_line(event) + "\n"
        try:
            sys.stdout.write(line)
            sys.stdout.flush()
        except Exception:  # noqa: BLE001 -- injected stream errors must not expose event content.
            raise DeliveryError("STDOUT_DELIVERY_FAILED") from None

    def close(self) -> None:
        # stdout belongs to the process, including when a caller injected it.
        pass


PROVIDER = SinkProvider(id="jsonl", build=JsonlSink)
