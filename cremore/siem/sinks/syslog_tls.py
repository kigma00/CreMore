"""Syslog over TLS: RFC 5424 messages framed per RFC 5425, as JSON, CEF or LEEF.

https://www.rfc-editor.org/rfc/rfc5424 (message), https://www.rfc-editor.org/rfc/rfc5425
(TLS transport, octet-counting frames, port 6514). ``framing: "lf"`` sends
newline-terminated messages for receivers that expect RFC 6587 non-transparent
framing. The message body is the event as compact JSON, CEF (ArcSight) or
LEEF 2.0 (QRadar); CEF and LEEF encode the native event.

TLS is always verified (the system CAs or ``ca_file``), at least TLS 1.2, with an
optional client certificate for mutual TLS. Syslog has no application-level
acknowledgement: a send is accepted once the frame is written to the TLS stream.
Before each write the connection is checked for a peer that closed it, so a
stale connection is replaced instead of silently swallowing an event. A failed
write closes the connection and is retried by the outbox, like every sink.
"""

from __future__ import annotations

import ipaddress
import re
import select
import socket
import ssl
from collections.abc import Mapping
from datetime import UTC, datetime

from cremore.siem.contract import DeliveryError, SinkProvider
from cremore.siem.formats import syslog_severity, to_cef, to_leef
from cremore.siem.sinks._http import json_line

_OPTIONS = {"host", "port", "ca_file", "cert_file", "key_file", "server_name", "message_format", "framing",
            "facility", "app_name", "hostname", "timeout_seconds"}
_HOSTNAME = re.compile(r"(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\Z")
_PRINT = re.compile(r"[\x21-\x7e]+\Z")
_OCSF_SEVERITY = {6: 2, 5: 2, 4: 3, 3: 4, 2: 5, 1: 6, 0: 6}
MAX_MESSAGE_BYTES = 64 << 10


def _host(value) -> str:
    """A DNS name or an IP address (IPv6 may be bracketed)."""
    if not isinstance(value, str) or not value:
        raise ValueError("SIEM_SYSLOG_HOST_INVALID")
    bare = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    try:
        return str(ipaddress.ip_address(bare))
    except ValueError:
        pass
    if _HOSTNAME.fullmatch(bare):
        return bare
    raise ValueError("SIEM_SYSLOG_HOST_INVALID")


def _file(value, code):
    if not isinstance(value, str) or not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError(code)
    return value


class SyslogTLSSink:
    def __init__(self, options: Mapping[str, object], *, connect=socket.create_connection):
        if not isinstance(options, Mapping) or set(options) - _OPTIONS:
            raise ValueError("SIEM_OPTIONS_INVALID")
        host = _host(options.get("host"))
        port = options.get("port", 6514)
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("SIEM_SYSLOG_PORT_INVALID")
        self._format = options.get("message_format", "json")
        if self._format not in ("json", "cef", "leef"):
            raise ValueError("SIEM_SYSLOG_FORMAT_INVALID")
        self._framing = options.get("framing", "octet-counting")
        if self._framing not in ("octet-counting", "lf"):
            raise ValueError("SIEM_SYSLOG_FRAMING_INVALID")
        facility = options.get("facility", 10)  # 10: security/authorization (RFC 5424 table 1)
        if type(facility) is not int or not 0 <= facility <= 23:
            raise ValueError("SIEM_SYSLOG_FACILITY_INVALID")
        app = options.get("app_name", "cremore")
        if not isinstance(app, str) or not _PRINT.fullmatch(app) or len(app) > 48:
            raise ValueError("SIEM_SYSLOG_APP_NAME_INVALID")
        name = options.get("hostname", socket.gethostname())
        name = name if isinstance(name, str) and _PRINT.fullmatch(name) and len(name) <= 255 else None
        if "hostname" in options and name is None:
            raise ValueError("SIEM_SYSLOG_HOSTNAME_INVALID")
        timeout = options.get("timeout_seconds", 10)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 30:
            raise ValueError("SIEM_TIMEOUT_INVALID")
        server_name = _host(options.get("server_name", host))
        try:
            context = ssl.create_default_context(
                cafile=_file(options["ca_file"], "SIEM_CA_INVALID") if "ca_file" in options else None)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            if "cert_file" in options or "key_file" in options:
                context.load_cert_chain(_file(options.get("cert_file"), "SIEM_CLIENT_CERT_INVALID"),
                                        _file(options.get("key_file"), "SIEM_CLIENT_CERT_INVALID"))
        except ValueError:
            raise
        except (OSError, ssl.SSLError):
            raise ValueError("SIEM_TLS_CONFIGURATION_INVALID") from None
        self._address, self._server_name = (host, port), server_name
        self._context, self._timeout, self._connect = context, float(timeout), connect
        self._facility, self._app, self._hostname = facility, app, name or "-"
        self._sock = None

    def _open(self):
        try:
            raw = self._connect(self._address, timeout=self._timeout)
        except OSError:
            raise DeliveryError("SYSLOG_CONNECT_FAILED") from None
        try:
            sock = self._context.wrap_socket(raw, server_hostname=self._server_name)
            sock.settimeout(self._timeout)
            return sock
        except (OSError, ssl.SSLError):
            raw.close()
            raise DeliveryError("SYSLOG_TLS_FAILED") from None

    def _stale(self) -> bool:
        """True when the receiver closed the connection since the last write."""
        try:
            readable, _, _ = select.select([self._sock], [], [], 0)
            if not readable and not self._sock.pending():
                return False
            self._sock.setblocking(False)
            try:
                return self._sock.recv(1) == b""
            except (ssl.SSLWantReadError, BlockingIOError):
                return False
            finally:
                self._sock.settimeout(self._timeout)
        except (OSError, ValueError):
            return True

    def _message(self, event: dict) -> bytes:
        ocsf = "class_uid" in event
        kind = (event.get("metadata") or {}).get("log_name") if ocsf else event.get("event_type")
        if not isinstance(kind, str) or not _PRINT.fullmatch(kind):
            raise DeliveryError("INVALID_EVENT")
        try:
            when = (datetime.fromtimestamp(event["time"] / 1000, UTC) if ocsf
                    else datetime.fromisoformat(event["occurred_at"]))
            if when.tzinfo is None:
                raise ValueError
        except (KeyError, TypeError, ValueError, OverflowError):
            raise DeliveryError("INVALID_EVENT_TIME") from None
        stamp = when.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
        level = _OCSF_SEVERITY.get(event.get("severity_id"), 6) if ocsf else syslog_severity(event)
        body = to_cef(event) if self._format == "cef" else to_leef(event) if self._format == "leef" else json_line(event)
        # HEADER: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID; no STRUCTURED-DATA.
        message = f"<{self._facility * 8 + level}>1 {stamp} {self._hostname} {self._app} - {kind[:32]} - {body}"
        encoded = message.encode("ascii", errors="strict")
        if len(encoded) > MAX_MESSAGE_BYTES:
            raise DeliveryError("INVALID_EVENT")
        return encoded

    def send(self, event: dict) -> None:
        try:
            message = self._message(event)
        except UnicodeEncodeError:
            raise DeliveryError("INVALID_EVENT") from None
        frame = str(len(message)).encode() + b" " + message if self._framing == "octet-counting" else message + b"\n"
        if self._sock is not None and self._stale():
            self._drop()
        if self._sock is None:
            self._sock = self._open()
        try:
            self._sock.sendall(frame)
        except (OSError, ssl.SSLError):
            self._drop()
            raise DeliveryError("SYSLOG_DELIVERY_FAILED") from None

    def _drop(self):
        sock, self._sock = self._sock, None
        if sock is None:
            return
        try:
            # Read what the receiver sent (TLS 1.3 session tickets) so closing
            # ends the stream cleanly instead of resetting it under unread data.
            sock.setblocking(False)
            for _ in range(64):
                if not sock.recv(65536):
                    break
        except (OSError, ssl.SSLError, ValueError):
            pass
        try:
            sock.close()
        except OSError:
            pass

    def close(self) -> None:
        self._drop()


def _build(options):
    return SyslogTLSSink(options)


PROVIDER = SinkProvider(id="syslog_tls", build=_build)
