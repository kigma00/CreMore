"""Remove retired GCP raw-value rows without reading, printing or archiving their bodies."""

import argparse
import json
import os

from sqlalchemy import delete, func, inspect, select, table, text


def purge(engine, *, apply=False, offline=False):
    if apply and not offline:
        raise ValueError("OFFLINE_GCP_VALUE_PURGE_REQUIRED")
    legacy = table("gcp_values")
    with engine.begin() as conn:
        if not inspect(conn).has_table(legacy.name):
            return {"rows": 0, "deleted": 0}
        if apply and engine.dialect.name == "postgresql":
            conn.execute(text("LOCK TABLE gcp_values IN ACCESS EXCLUSIVE MODE"))
        count = conn.execute(select(func.count()).select_from(legacy)).scalar_one()
        if apply:
            conn.execute(delete(legacy))
        return {"rows": count, "deleted": count if apply else 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Delete all legacy GCP value rows")
    parser.add_argument("--offline", action="store_true", help="All API and worker processes are stopped")
    args = parser.parse_args()
    if args.apply and not args.offline:
        parser.error("--apply requires --offline")
    url = os.environ.get("DATABASE_URL")
    if not url:
        parser.error("DATABASE_URL must be set; never put credentials in CLI arguments")
    from cremore.db.sql import make_engine

    engine = None
    try:
        engine = make_engine(url)
        engine.hide_parameters = True
        print(json.dumps(purge(engine, apply=args.apply, offline=args.offline)))
    except Exception:  # noqa: BLE001 -- driver failures must not print connection details
        # Driver errors can contain connection details; report no DSN, SQL or row data.
        parser.exit(1, "GCP_VALUE_PURGE_FAILED\n")
    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    main()
