"""Approved-name fact trees shared by providers whose payloads are plain JSON.

A provider whose response grammar needs its own rules keeps its own writer.
This one only refuses what the shared model refuses: unapproved names, depth,
node counts and values the typed model rejects. Nothing rejected is reflected
back into the record; only its path and reason survive as an omission.

Moved unchanged from ``cremore.coverage.providers.facts`` during the three-way
integration: importing that path first runs the provider registry package,
which loads every provider descriptor and, through the collector runtime, the
DB layer. Provider libraries import this module directly; the old path is an
alias of this module for existing callers.
"""

from __future__ import annotations

import hashlib

from pydantic import ValidationError

from cremore.coverage.metadata_models import (
    FACT_NAMES,
    MetadataFact,
    MetadataOmission,
    metadata_text,
)


class FactWriter:
    """Every nested field must be approved; rejected values are never reflected."""

    def __init__(self):
        self.omissions = []
        self.count = 0

    def omit(self, path, reason):
        if len(self.omissions) >= 511:
            return
        try:
            safe = metadata_text(path)
            if len(safe) > 512:
                raise ValueError("PATH_LIMIT")
        except ValueError:
            safe = "field/" + hashlib.sha256(path.encode()).hexdigest()
        self.omissions.append(MetadataOmission(path=safe, reason=reason))

    def fact(self, name, value, path, depth=1):
        if name not in FACT_NAMES:
            self.omit(path, "UNAPPROVED_METADATA_FIELD")
            return None
        if depth > 6 or self.count >= 2048:
            self.omit(path, "METADATA_FACT_LIMIT")
            return None
        self.count += 1
        if value is None:
            return MetadataFact(name=name, state="NULL")
        if isinstance(value, dict):
            children = []
            for key, item in value.items():
                if len(children) == 512:
                    self.omit(path, "METADATA_FACT_LIMIT")
                    break
                child = self.fact(str(key), item, path + "/" + str(key), depth + 1)
                if child is not None:
                    children.append(child)
            return MetadataFact(name=name, container="object", children=children)
        if isinstance(value, list) and any(
            isinstance(item, (dict, list)) or item is None for item in value
        ):
            if depth == 6:
                self.omit(path, "METADATA_FACT_LIMIT")
                return MetadataFact(name=name, state="INVALID", reason="METADATA_FACT_LIMIT")
            children = []
            for index, item in enumerate(value[:512]):
                if self.count >= 2048:
                    self.omit(path, "METADATA_FACT_LIMIT")
                    break
                child = self.fact("entry", item, path + "/" + str(index), depth + 1)
                if child is not None:
                    children.append(child)
            if len(value) > 512:
                self.omit(path, "METADATA_FACT_LIMIT")
            return MetadataFact(name=name, container="array", children=children)
        try:
            return MetadataFact(name=name, value=value)
        except (ValidationError, ValueError):
            self.omit(path, "INVALID_METADATA_VALUE")
            return MetadataFact(name=name, state="INVALID", reason="INVALID_METADATA_VALUE")

    def facts(self, value):
        output = []
        for key, item in value.items():
            fact = self.fact(key, item, key)
            if fact is not None:
                output.append(fact)
        return output


def unpack_facts(facts):
    def unpack(fact):
        if fact["state"] in {"NULL", "INVALID"}:
            return None
        if fact.get("container") == "object":
            return unpack_facts(fact.get("children", []))
        if fact.get("container") == "array":
            return [unpack(child) for child in fact.get("children", [])]
        return fact.get("value")

    return {fact["name"]: unpack(fact) for fact in facts if fact["state"] != "MISSING"}
