"""Separate, opt-in SIEM exporter. Does not run collectors or read source credentials."""

import argparse
import logging
import os
import time
from types import SimpleNamespace

from sqlalchemy import create_engine

from cremore.siem.config import load_config
from cremore.siem.registry import providers


def _beat(path: str) -> None:
    """Touch the liveness file a Kubernetes probe checks; a missing path never stops delivery."""
    if not path:
        return
    try:
        with open(path, "a"):
            pass
        os.utime(path, None)
    except OSError:
        logging.getLogger("cremore.siem").warning("SIEM_HEARTBEAT_FILE_UNWRITABLE")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", help="Path to SIEM destination JSON; credentials use environment references")
    parser.add_argument("--once", action="store_true", help="Process at most one batch per destination, then exit")
    parser.add_argument("--list-sinks", action="store_true", help="List installed adapter names without importing plugins")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    # httpx INFO includes full URLs; private SIEM paths must not become logs.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    engine = exporter = None
    try:
        if args.list_sinks:
            print("\n".join(sorted(providers())))
            return 0
        if not args.config:
            parser.error("--config is required for delivery")
        config = load_config(args.config)
        url = os.environ.get("SIEM_DATABASE_URL", "")
        if not url:
            raise ValueError("SIEM_DATABASE_URL_REQUIRED")
        # API/worker schema expansion owns DDL. PostgreSQL row locking needs
        # SELECT + UPDATE(event_id) on siem_events; delivery state also needs
        # SELECT/INSERT/UPDATE on siem_deliveries. No scan tables are read.
        from cremore.db.sql import SqlRepository
        from cremore.siem.outbox import SiemOutbox
        from cremore.siem.runner import Exporter

        engine = create_engine(url, pool_pre_ping=True, hide_parameters=True)
        if os.environ.get("ISOLATED_DEPLOYMENT", "false").lower() in {"true", "1"}:
            from cremore.db.startup import startup

            startup(SimpleNamespace(isolated_deployment=True), engine, runtime_role="siem")
        exporter = Exporter(SiemOutbox(SqlRepository(engine)), config)
        heartbeat = os.environ.get("SIEM_HEARTBEAT_FILE", "/tmp/cremore-siem.heartbeat")
        while True:
            counts = exporter.run_once()
            _beat(heartbeat)
            logging.getLogger("cremore.siem").info(
                "SIEM_BATCH delivered=%s failed=%s lease_lost=%s held=%s",
                counts.delivered, counts.failed, counts.lease_lost, counts.held)
            if args.once:
                return int(bool(counts.failed or counts.lease_lost))
            time.sleep(config.poll_seconds)
    except KeyboardInterrupt:
        return 0
    except Exception:  # noqa: BLE001 -- process boundary suppresses database/plugin secrets and exits nonzero.
        # Database/plugin exceptions can include configuration secrets.
        logging.getLogger("cremore.siem").error("SIEM_EXPORTER_FAILED")
        return 1
    finally:
        if exporter is not None:
            exporter.close()
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
