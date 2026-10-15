"""Bounded transport for explicitly approved Vault/OpenBao inventory reads."""

from cremore.http_client import bounded_request


class ReadError(ValueError):
    def __init__(self, code, *, metadata=None):
        super().__init__(code)
        self.metadata = metadata


class InventoryHTTP:
    def __init__(self, spec, client, token, collection):
        self.spec, self.client, self.token, self.collection = spec, client, token, collection
        self.sensitive = set()

    def __call__(self, namespace, path, params=None, *, method="GET", body=None):
        token = self.token() if callable(self.token) else self.token
        self.sensitive.add(token)
        headers = {"X-Vault-Token": token}
        if namespace:
            headers["X-Vault-Namespace"] = namespace
        response = bounded_request(self.client, method, self.spec.endpoint + "/v1/" + path,
                                   params=params, json=body, headers=headers, follow_redirects=False,
                                   retry_429=True, before_attempt=self.collection.charge,
                                   max_response_bytes=self.spec.max_value_bytes + (64 << 10))
        if response.status_code == 404:
            try:
                payload = response.json()
            except ValueError:
                payload = None
            if isinstance(payload, dict):
                listing = method == "LIST" or (method == "GET" and params and params.get("list") == "true")
                if listing and payload.get("errors") == []:
                    return {"data": {"keys": []}}
                data = payload.get("data")
                if method == "GET" and not listing and isinstance(data, dict) and isinstance(data.get("metadata"), dict):
                    # Carry only KV version-state metadata, never values or custom metadata.
                    metadata = {key: data["metadata"][key] for key in ("version", "destroyed", "deletion_time")
                                if key in data["metadata"]}
                    raise ReadError("VAULT_HTTP_404", metadata=metadata)
        if response.status_code != 200:
            raise ReadError("VAULT_HTTP_" + str(response.status_code))
        payload = response.json()
        if not isinstance(payload, dict):
            raise ReadError("VAULT_RESPONSE_MALFORMED")
        return payload

    def data(self, namespace, path, params=None, *, method="GET", body=None):
        data = self(namespace, path, params, method=method, body=body).get("data")
        if not isinstance(data, dict):
            raise ReadError("VAULT_RESPONSE_MALFORMED")
        return data
