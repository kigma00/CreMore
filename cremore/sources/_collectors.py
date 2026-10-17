"""Shared construction for bounded provider content libraries."""


def object_limit(value):
    if value is None:
        from cremore.collectors.base import DEFAULT_MAX_OBJECT_BYTES

        return DEFAULT_MAX_OBJECT_BYTES
    return value
