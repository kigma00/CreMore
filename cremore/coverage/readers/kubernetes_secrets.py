"""Built-in reader: Kubernetes Secrets through the customer's own ``kubectl``.

``kubectl get secrets -o json`` returns each Secret's ``data`` map with
base64-encoded values (https://kubernetes.io/docs/concepts/configuration/secret/).
Declared prefixes are namespaces, optionally narrowed to one Secret
(``prod`` or ``prod/db-credentials``); the empty prefix lists every namespace
(``--all-namespaces``). An item's path is ``namespace/secret/key`` and its
version is the Secret's ``resourceVersion``.

The listing is complete only when every requested ``kubectl`` call succeeded:
RBAC refuses a whole namespace rather than silently hiding some Secrets, so a
refusal is an incomplete listing, never an empty one.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import subprocess
from collections.abc import Iterator, Mapping

from cremore.coverage.external_vault import ReaderProvider, VaultEntry

_NAME = re.compile(r"[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?\Z")
_OUTPUT_LIMIT = 256 << 20


class KubernetesSecretsReader:
    def __init__(self, options: Mapping[str, str], *, run=subprocess.run) -> None:
        unknown = set(options) - {"context", "kubectl"}
        if unknown:
            raise ValueError("READER_OPTION_UNKNOWN")
        self.context = options.get("context", "")
        self.kubectl = options.get("kubectl", "kubectl")
        if self.context and not re.fullmatch(r"[A-Za-z0-9._@:/-]{1,253}", self.context):
            raise ValueError("READER_OPTION_INVALID")
        self.run = run
        self.complete = False

    def _list(self, namespace: str | None) -> list | None:
        command = [self.kubectl, "get", "secrets", "-o", "json"]
        command += ["--all-namespaces"] if namespace is None else ["--namespace", namespace]
        if self.context:
            command += ["--context", self.context]
        try:
            result = self.run(command, capture_output=True, timeout=300, check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode != 0 or len(result.stdout) > _OUTPUT_LIMIT:
            return None
        try:
            items = json.loads(result.stdout).get("items")
        except (ValueError, AttributeError):
            return None
        return items if isinstance(items, list) else None

    def entries(self, prefixes: tuple[str, ...]) -> Iterator[VaultEntry]:
        requests = {}
        for prefix in prefixes:
            namespace, _, secret = prefix.partition("/")
            if not namespace:
                requests = {None: set()}
                break
            if not _NAME.fullmatch(namespace) or (secret and (not _NAME.fullmatch(secret) or "/" in secret)):
                return
            requests.setdefault(namespace, set()).add(secret)
        ok = bool(requests)
        for namespace, names in requests.items():
            items = self._list(namespace)
            if items is None:
                ok = False
                continue
            for item in items:
                meta = item.get("metadata") if isinstance(item, dict) else None
                if not isinstance(meta, dict):
                    ok = False
                    continue
                space, name = meta.get("namespace", ""), meta.get("name", "")
                if not isinstance(space, str) or not isinstance(name, str) or not space or not name:
                    ok = False
                    continue
                if namespace is not None and ("" not in names and name not in names):
                    continue
                version = meta.get("resourceVersion") if isinstance(meta.get("resourceVersion"), str) else ""
                data = item.get("data") or {}
                if not isinstance(data, dict):
                    ok = False
                    continue
                for key, encoded in sorted(data.items()):
                    try:
                        raw = base64.b64decode(encoded, validate=True) if isinstance(encoded, str) else None
                    except (binascii.Error, ValueError):
                        raw = None
                    if raw == b"":
                        continue  # An empty value holds no credential.
                    # A malformed encoding stays visible as an unreadable item.
                    yield VaultEntry(path=f"{space}/{name}/{key}", value=raw or "", version=version[:256])
        self.complete = ok


PROVIDER = ReaderProvider(id="kubernetes_secrets", api_version=1, build=KubernetesSecretsReader)
