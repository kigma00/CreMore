"""Worker-side reference resolution; authentication never belongs in checkpoints."""

from contextlib import contextmanager

from cremore.coverage.store import CoverageError


def resolve_slots(spec, resolver, optional=frozenset()):
    """Only the worker resolves references. Plaintext never enters task state.

    A role the provider declares optional (``optional_secret_roles``) is left out
    when it cannot be resolved: the adapter fails only the reads that need it.
    """
    aliases = {"app_id": "GITHUB_APP_ID", "installation_id": "GITHUB_APP_INSTALLATION_ID",
               "private_key": "GITHUB_APP_PRIVATE_KEY_BASE64"}
    result = {}
    for slot, ref in spec.secret_refs.items():
        if resolver is None:
            raise CoverageError("METADATA_SECRET_UNAVAILABLE")
        try:
            data = resolver.resolve(ref)
            value = data.get(slot) or data.get(aliases.get(slot, ""))
            if slot not in aliases:
                value = value or data.get("token")
        except Exception:  # noqa: BLE001 -- backend errors can contain resolved values; expose only a fixed code.
            value = None
        if not isinstance(value, str) or not value or len(value) > 1048576:
            if slot in optional:
                continue
            raise CoverageError("METADATA_SECRET_UNAVAILABLE")
        result[slot] = value
    return result


@contextmanager
def resolved_slots(spec, resolver, optional=frozenset()):
    """Release the resolved mapping even if planning fails before collection."""
    values = resolve_slots(spec, resolver, optional)
    try:
        yield values
    finally:
        values.clear()
