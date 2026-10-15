"""Registered schema 2 adapter: the shared identity collector over GitHub external identities."""

from cremore.identity.idp import Collector

from . import directory as _vendor

_collector = Collector(_vendor)
collect_pages = _collector.collect_pages
validate_spec = _collector.validate_spec
validate_record = _collector.validate_record
validate_machine_record = _collector.validate_machine_record
