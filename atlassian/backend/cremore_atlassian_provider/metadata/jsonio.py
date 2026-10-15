# Adapted from publish/develop_atlassian 49abdc11a998f61917e151ab276e84c7a21815ea (atlassian_collector/jsonio.py).
"""Shared bounded JSON contract for saved artifacts and their consumers."""

import hashlib
import json
import math
import os
import stat

# A full run can contain many individually bounded 1 MiB API responses.
# Writers and readers use these same limits, including JSON indentation/UTF-8.
MAX_BYTES = 128 * 1024 * 1024
MAX_NODES = 4_000_000
MAX_DEPTH = 64


def require(condition):
    if not condition:
        raise ValueError("Invalid or oversized JSON artifact")


def canonical(value):
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    )


def bounded_json(value, *, max_nodes=MAX_NODES, max_depth=MAX_DEPTH, tuples=False):
    """Walk with O(depth) auxiliary memory, including very wide arrays/objects."""
    stack, nodes = [iter((value,))], 0
    while stack:
        try:
            item = next(stack[-1])
        except StopIteration:
            stack.pop()
            continue
        nodes += 1
        require(nodes <= max_nodes and len(stack) - 1 <= max_depth)
        if type(item) is dict:
            require(all(type(key) is str for key in item))
            stack.append(iter(item.values()))
        elif type(item) is list or (tuples and type(item) is tuple):
            stack.append(iter(item))
        else:
            if item is not None and type(item) not in (str, bool, int, float):
                raise TypeError("Unsupported JSON value")
            require(type(item) is not float or math.isfinite(item))


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def invalid_constant(_value):
    raise ValueError("Non-finite JSON value")


def loads(raw):
    return json.loads(raw, object_pairs_hook=unique_object, parse_constant=invalid_constant)


def read_json(handle, *, max_bytes=MAX_BYTES, max_nodes=MAX_NODES, max_depth=MAX_DEPTH):
    info = os.fstat(handle.fileno())
    require(stat.S_ISREG(info.st_mode) and info.st_size <= max_bytes)
    raw = handle.read(max_bytes + 1)
    require(len(raw) <= max_bytes)
    digest = hashlib.sha256(raw).hexdigest()
    value = loads(raw)
    del raw
    bounded_json(value, max_nodes=max_nodes, max_depth=max_depth)
    return value, digest


def load_json(path, **limits):
    """Regular files only; reject symlinks, duplicate keys and non-finite values."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        return read_json(handle, **limits)


def write_json(handle, value, *, max_bytes=MAX_BYTES, max_nodes=MAX_NODES, max_depth=MAX_DEPTH):
    """Stream to a binary temporary file; never publish unreadable artifacts."""
    bounded_json(value, max_nodes=max_nodes, max_depth=max_depth, tuples=True)
    encoder = json.JSONEncoder(ensure_ascii=False, indent=2, allow_nan=False)
    size = 0
    for chunk in encoder.iterencode(value):
        encoded = chunk.encode("utf-8")
        size += len(encoded)
        require(size + 1 <= max_bytes)  # Include the final newline.
        handle.write(encoded)
    handle.write(b"\n")
    return size + 1
