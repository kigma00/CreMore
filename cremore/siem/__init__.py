"""Public contract for trusted, outbound-only security event integrations."""

from cremore.siem.contract import DeliveryError, Sink, SinkProvider

__all__ = ["DeliveryError", "Sink", "SinkProvider"]
