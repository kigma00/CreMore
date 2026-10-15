"""Deliver committed events independently of scans and independently per destination."""

import copy
import logging
from dataclasses import dataclass

from cremore.siem.config import ExportConfig
from cremore.siem.contract import DeliveryError
from cremore.siem.formats import encode
from cremore.siem.outbox import safe_code
from cremore.siem.registry import load_provider

logger = logging.getLogger("cremore.siem")


@dataclass
class DeliveryCounts:
    delivered: int = 0
    failed: int = 0
    lease_lost: int = 0
    held: int = 0


class Exporter:
    def __init__(self, outbox, config: ExportConfig):
        self.outbox, self.config = outbox, config
        self.sinks = {}
        self.forms = {destination.id: destination.format for destination in config.destinations}
        try:
            for destination in config.destinations:
                provider = load_provider(destination.provider, allow_plugins=tuple(config.allow_plugins))
                sink = provider.build(destination.options)
                self.sinks[destination.id] = sink
                if not callable(getattr(sink, "send", None)) or not callable(getattr(sink, "close", None)):
                    raise TypeError("SIEM_SINK_CONTRACT_INVALID")
        except Exception:  # noqa: BLE001 -- close opened sinks and redact plugin configuration errors.
            self.close()
            raise ValueError("SIEM_SINK_CONFIGURATION_INVALID") from None

    def run_once(self) -> DeliveryCounts:
        counts = DeliveryCounts()
        # One outstanding lease per sink. Claiming a large batch before slow
        # network requests would let the last entries expire before being sent.
        for destination, sink in self.sinks.items():
            outcome, code = "IDLE", None
            for _ in range(self.config.batch_size):
                rows = self.outbox.claim(destination, limit=1, lease_seconds=60)
                if not rows:
                    break
                row = rows[0]
                event, token = row["event"], row["token"]
                try:
                    sink.send(encode(copy.deepcopy(event), self.forms.get(destination, "native")))
                except Exception as exc:  # noqa: BLE001 -- retain event for retry; never publish plugin diagnostics.
                    # Sink exceptions may contain response bodies, URLs or tokens;
                    # only a fixed code from a known list is kept.
                    outcome, code = "FAILURE", safe_code(getattr(exc, "code", None))
                    delay = min(3600, 5 * (2 ** min(row["attempts"], 9)))
                    if isinstance(exc, DeliveryError):
                        hint = exc.retry_after_seconds
                        if type(hint) is int:
                            delay = max(delay, min(86400, max(0, hint)))
                    hold = bool(self.config.max_attempts) and row["attempts"] >= self.config.max_attempts
                    owned = self.outbox.retry(destination, event["event_id"], token,
                                              error_code=code, delay_seconds=delay, hold=hold)
                    counts.failed += 1
                    counts.held += hold and owned
                    counts.lease_lost += not owned
                    logger.warning("SIEM_DELIVERY_FAILED destination=%s event_id=%s code=%s%s",
                                   destination, event["event_id"], code, " held" if hold else "")
                    break
                if self.outbox.acknowledge(destination, event["event_id"], token):
                    counts.delivered += 1
                    outcome = "SUCCESS"
                else:
                    counts.lease_lost += 1
                    logger.warning("SIEM_DELIVERY_LEASE_LOST destination=%s event_id=%s",
                                   destination, event["event_id"])
            try:
                self.outbox.record_status(destination, outcome, error_code=code)
            except Exception:  # noqa: BLE001 -- status is advisory; delivery state is already durable.
                logger.warning("SIEM_STATUS_WRITE_FAILED destination=%s", destination)
        return counts

    def close(self) -> None:
        for sink in self.sinks.values():
            try:
                sink.close()
            except Exception:  # noqa: BLE001 -- one cleanup failure must not skip the remaining sinks.
                logger.warning("SIEM_SINK_CLOSE_FAILED")
        self.sinks.clear()
