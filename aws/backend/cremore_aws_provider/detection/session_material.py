"""AWS-owned passive, bounded STS component binding inside the detection boundary.

Only direct JSON fields or contiguous env/profile assignments share a context.
The returned evidence contains keyed digests, never the session token.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

from cremore.detection.fingerprint import fingerprint

MAX_BINDING_BYTES = 1024 * 1024
MAX_CONTEXT_BYTES = 16384
MAX_TOKEN_BYTES = 4096
# RE2 caps counted repetitions at 1000; enforce the byte budget after matching.
TOKEN_PATTERN = r"[A-Za-z0-9/+=]{16,}"
_TOKEN = re.compile(TOKEN_PATTERN.encode())
_ID = re.compile(rb"ASIA[A-Z0-9]{16}")
_SECRET = re.compile(rb"[A-Za-z0-9/+=]{40}")
_JSON_TOKENS = re.compile(rb'"(?:[^"\\]|\\.)*"|[{}\[\]:,]')
_ASSIGNMENT = re.compile(rb'''[ \t]*(?:export[ \t]+)?(?P<label>[A-Za-z_][A-Za-z0-9_-]*)[ \t]*=[ \t]*(?:"(?P<double>[A-Za-z0-9/+=]+)"|'(?P<single>[A-Za-z0-9/+=]+)'|(?P<bare>[A-Za-z0-9/+=]+))''')


def _kind(label):
    label = label.lower().replace("_", "").replace("-", "")
    return {"awsaccesskeyid": "id", "accesskeyid": "id", "awssecretaccesskey": "secret",
            "secretaccesskey": "secret", "awssessiontoken": "token", "sessiontoken": "token"}.get(label)


@dataclass(frozen=True)
class _Field:
    kind: str
    value: bytes
    start: int
    end: int


@dataclass(frozen=True)
class BoundPair:
    """Match-compatible direct-field pair; raw values stay within the engine."""
    identifier: _Field
    secret: _Field

    def group(self, number):
        return (self.identifier if number == 1 else self.secret).value

    def start(self, number):
        return (self.identifier if number == 1 else self.secret).start

    def end(self, number):
        return (self.identifier if number == 1 else self.secret).end


def _json_contexts(data):
    try:
        json.loads(data)
    except (ValueError, RecursionError):
        return []
    stack, contexts = [], []
    for match in _JSON_TOKENS.finditer(data):
        token = match.group()
        if token in (b"{", b"["):
            if stack:
                stack[-1]["state"] = "done"
            stack.append({"object": token == b"{", "start": match.start(), "state": "key", "key": "", "fields": []})
        elif token in (b"}", b"]"):
            node = stack.pop()
            if node["object"] and match.end() - node["start"] <= MAX_CONTEXT_BYTES:
                contexts.append((node["start"], match.end(), node["fields"]))
        elif stack and stack[-1]["object"]:
            node = stack[-1]
            if token == b",":
                node["state"] = "key"
            elif token == b":":
                node["state"] = "value"
                kind = _kind(node["key"])
                if kind:
                    node["fields"].append(_Field(kind, b"", match.end(), match.end()))
            elif token.startswith(b'"'):
                if node["state"] == "key":
                    node["key"] = json.loads(token)
                    node["state"] = "colon"
                elif node["state"] == "value":
                    if _kind(node["key"]):
                        node["fields"][-1] = _Field(
                            _kind(node["key"]), json.loads(token).encode("utf-8", "surrogatepass"),
                            match.start() + 1, match.end() - 1)
                    node["state"] = "done"
    return contexts


def _assignment_contexts(data):
    contexts, fields = [], []
    start, offset, indent = 0, 0, None

    def flush(end):
        nonlocal fields, indent
        if fields and end - start <= MAX_CONTEXT_BYTES:
            contexts.append((start, end, fields))
        fields, indent = [], None

    for line in data.splitlines(keepends=True):
        body = line.rstrip(b"\r\n")
        indentation = len(body) - len(body.lstrip(b" \t"))
        parsed, position = [], 0
        while position < len(body):
            match = _ASSIGNMENT.match(body, position)
            if match is None:
                break
            kind = _kind(match.group("label").decode("ascii"))
            if kind is None:
                break
            group = next(name for name in ("double", "single", "bare") if match.group(name) is not None)
            parsed.append(_Field(kind, match.group(group), offset + match.start(group), offset + match.end(group)))
            position = match.end()
            if position < len(body) and body[position:position + 1] not in (b" ", b"\t"):
                break
            if not body[position:].strip() or body[position:].lstrip().startswith(b"#"):
                position = len(body)
        if position != len(body) or not parsed:
            flush(offset)
        else:
            if fields and (indent != indentation or offset + len(body) - start > MAX_CONTEXT_BYTES):
                flush(offset)
            if not fields:
                start, indent = offset, indentation
            fields.extend(parsed)
        offset += len(line)
    flush(offset)
    return contexts


def bind_sessions(data, pairs, *, key, validate_secret):
    """Return additional structural pairs, safe evidence, and the token spans of
    COMPLETE bindings keyed by ``(id-start, secret-start)``.

    ``pairs`` entries are (id-start, secret-start, id-bytes, secret-bytes). The
    span map covers only COMPLETE bindings; a caller slices the raw token from
    ``data`` to redact it or, for opt-in verification, to sign a probe with it.
    Ambiguous repeated material cannot inherit a token from another occurrence.
    The returned ``evidence`` never contains a raw token, only keyed digests.
    """
    if len(data) > MAX_BINDING_BYTES:
        return [], {}, {}
    structured = data.lstrip().startswith((b"{", b"["))
    contexts = _json_contexts(data) if structured else _assignment_contexts(data)
    if structured and not contexts and re.fullmatch(rb"\[[A-Za-z0-9_+,.@ /-]{1,256}\]", data.lstrip().splitlines()[0].strip()):
        contexts = _assignment_contexts(data)
    additional = []
    complete = {}
    token_spans = {}
    token_values = {}
    for start, end, fields in contexts:
        grouped = {kind: [field for field in fields if field.kind == kind] for kind in ("id", "secret", "token")}
        if not all(len(grouped[kind]) == 1 for kind in grouped):
            continue
        identifier, secret, token = (grouped[kind][0] for kind in ("id", "secret", "token"))
        if (not _ID.fullmatch(identifier.value) or not _SECRET.fullmatch(secret.value)
                or len(token.value) > MAX_TOKEN_BYTES or not _TOKEN.fullmatch(token.value)
                or (validate_secret is not None and not validate_secret(secret.value))
                or all(char in b"0123456789abcdefABCDEF" for char in secret.value)):
            continue
        pair = BoundPair(identifier, secret)
        additional.append(pair)
        position = (identifier.start, secret.start)
        complete[position] = {"aws_session_material": "COMPLETE"}
        if key and len(key) >= 32:
            complete[position]["aws_session_fingerprint"] = fingerprint(
                b"AWS_STS_SESSION_V1\x00" + identifier.value + b"\x00" + secret.value + b"\x00" + token.value, key=key)
        token_spans[position] = (token.start, token.end)
        token_values[position] = token.value
    all_pairs = list(pairs) + [(pair.identifier.start, pair.secret.start, pair.identifier.value, pair.secret.value) for pair in additional]
    evidence, material_positions = {}, {}
    for id_start, secret_start, identifier, secret in all_pairs:
        if not identifier.startswith(b"ASIA"):
            continue
        position = (id_start, secret_start)
        metadata = complete.get(position)
        if metadata is None:
            ambiguous = any(start <= id_start < end and start <= secret_start < end
                            and any(sum(field.kind == kind for field in fields) > 1 for kind in ("id", "secret", "token"))
                            for start, end, fields in contexts)
            metadata = {"aws_session_material": "AMBIGUOUS" if ambiguous else "UNBOUND"}
        evidence[position] = metadata
        material_positions.setdefault((identifier, secret), set()).add(position)
    for positions in material_positions.values():
        signatures = {(evidence[position]["aws_session_material"], token_values.get(position))
                      for position in positions}
        if len(signatures) > 1:
            for position in positions:
                evidence[position] = {"aws_session_material": "AMBIGUOUS"}
    complete_tokens = {position: span for position, span in token_spans.items()
                       if evidence[position]["aws_session_material"] == "COMPLETE"}
    return additional, evidence, complete_tokens
