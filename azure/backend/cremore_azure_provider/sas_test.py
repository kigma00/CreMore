"""SAS string-to-sign pinned to Microsoft's documented formats; synthetic keys only."""

import base64
import hashlib
import hmac

import pytest

from cremore.detection.fingerprint import fingerprint
from cremore_azure_provider.sas import sas_facts, signed_fingerprints, string_to_sign

KEY1 = base64.b64encode(bytes(range(64))).decode()
KEY2 = base64.b64encode(bytes(range(1, 65))).decode()
FINGERPRINT_KEY = b"synthetic-sas-fingerprint-key-32bytes"


@pytest.mark.parametrize("field", ["tn", "spk", "srk", "epk", "erk", "rscd", "rscc"])
def test_secret_bearing_signed_fields_are_omitted_and_cannot_be_reconstructed(field):
    from cremore.detection.engine_test import GH

    query = f"sv=2022-11-02&ss=b&srt=o&sp=r&{field}={GH}".encode()
    result = sas_facts(query, account=b"myaccount", service=b"blob")
    assert GH not in str(result) and result["redacted"] == "true"
    assert string_to_sign(result) is None


def test_secret_bearing_path_is_omitted_after_url_decoding():
    from cremore.detection.engine_test import GH

    path = "/" + "".join(f"%{ord(char):02X}" for char in GH)
    result = sas_facts(b"sv=2022-11-02&sr=b&sp=r", account=b"myaccount", service=b"blob",
                       match=("https://myaccount.blob.core.windows.net" + path + "?").encode())
    assert "path" not in result and result["redacted"] == "true"
    assert string_to_sign(result) is None


def facts(query, *, url=b""):
    return sas_facts(query, account=b"myaccount", service=b"blob", match=url)


@pytest.mark.parametrize("query,url,expected", [
    # Account SAS before 2020-12-06: nine fields, each followed by a newline.
    (b"sv=2019-12-12&ss=bfqt&srt=sco&sp=rwdlac&st=2026-01-01T00:00:00Z&se=2026-12-01T00:00:00Z&spr=https",
     b"", "myaccount\nrwdlac\nbfqt\nsco\n2026-01-01T00:00:00Z\n2026-12-01T00:00:00Z\n\nhttps\n2019-12-12\n"),
    # 2020-12-06 and later add the signed encryption scope.
    (b"sv=2022-11-02&ss=b&srt=o&sp=r&se=2026-12-01T00%3A00%3A00Z&sip=198.51.100.10-198.51.100.20&ses=scope1",
     b"", "myaccount\nr\nb\no\n\n2026-12-01T00:00:00Z\n198.51.100.10-198.51.100.20\n\n2022-11-02\nscope1\n"),
    # Blob service SAS, 2020-12-06 and later: URL-decoded resource, no trailing newline.
    (b"sp=r&se=2026-12-01T00:00:00Z&spr=https&sv=2022-11-02&sr=b",
     b"https://myaccount.blob.core.windows.net/pictures/p%20q.jpg?",
     "r\n\n2026-12-01T00:00:00Z\n/blob/myaccount/pictures/p q.jpg\n\n\nhttps\n2022-11-02\nb\n\n\n\n\n\n\n"),
    # A container SAS names the container even when appended to one of its blobs.
    (b"sp=rl&se=2026-12-01T00:00:00Z&sv=2022-11-02&sr=c&si=policy-1&rsct=text/plain",
     b"https://myaccount.blob.core.windows.net/pictures/p.jpg?",
     "rl\n\n2026-12-01T00:00:00Z\n/blob/myaccount/pictures\npolicy-1\n\n\n2022-11-02\nc\n\n\n\n\n\n\ntext/plain"),
    # 2018-11-09 to 2020-12-06: signed resource and snapshot time, no encryption scope.
    (b"sp=r&se=2026-12-01T00:00:00Z&sv=2019-02-02&sr=b",
     b"https://myaccount.blob.core.windows.net/pictures/p.jpg?",
     "r\n\n2026-12-01T00:00:00Z\n/blob/myaccount/pictures/p.jpg\n\n\n\n2019-02-02\nb\n\n\n\n\n\n"),
    # 2015-04-05 to 2018-11-09 blob and file format.
    (b"sp=r&se=2026-12-01T00:00:00Z&sv=2017-11-09&sr=b",
     b"https://myaccount.blob.core.windows.net/pictures/p.jpg?",
     "r\n\n2026-12-01T00:00:00Z\n/blob/myaccount/pictures/p.jpg\n\n\n\n2017-11-09\n\n\n\n\n"),
])
def test_string_to_sign_follows_the_documented_format(query, url, expected):
    assert string_to_sign(facts(query, url=url)) == expected


def test_file_and_queue_service_sas_use_their_own_canonical_resources():
    file = sas_facts(b"sp=r&se=2026-12-01T00:00:00Z&sv=2022-11-02&sr=f", account=b"myaccount", service=b"file",
                     match=b"https://myaccount.file.core.windows.net/share/dir/a.txt?")
    assert string_to_sign(file) == "r\n\n2026-12-01T00:00:00Z\n/file/myaccount/share/dir/a.txt\n\n\n\n2022-11-02\n\n\n\n\n"
    queue = sas_facts(b"sp=a&se=2026-12-01T00:00:00Z&sv=2022-11-02", account=b"myaccount", service=b"queue",
                      match=b"https://myaccount.queue.core.windows.net/orders/messages?")
    assert string_to_sign(queue) == "a\n\n2026-12-01T00:00:00Z\n/queue/myaccount/orders\n\n\n\n2022-11-02"


@pytest.mark.parametrize("query,url,service,expected", [
    # Table: its name comes from tn and is lowercased; the key range closes the string.
    (b"sp=r&se=2026-12-01T00:00:00Z&sv=2019-02-02&tn=Employees&spk=a&srk=b&epk=c&erk=d",
     b"https://myaccount.table.core.windows.net/Employees()?", b"table",
     "r\n\n2026-12-01T00:00:00Z\n/table/myaccount/employees\n\n\n\n2019-02-02\na\nb\nc\nd"),
    # 2013-08-15 to 2015-02-21: no signed IP or protocol, and no service name before 2015-02-21.
    (b"sp=r&se=2026-12-01T00:00:00Z&sv=2013-08-15&tn=Employees", b"", b"table",
     "r\n\n2026-12-01T00:00:00Z\n/myaccount/employees\n\n2013-08-15\n\n\n\n"),
    (b"sp=r&se=2026-12-01T00:00:00Z&sv=2013-08-15&sr=b", b"https://myaccount.blob.core.windows.net/pictures/p.jpg?", b"blob",
     "r\n\n2026-12-01T00:00:00Z\n/myaccount/pictures/p.jpg\n\n2013-08-15\n\n\n\n\n"),
    (b"sp=r&se=2026-12-01T00:00:00Z&sv=2015-02-21&sr=b", b"https://myaccount.blob.core.windows.net/pictures/p.jpg?", b"blob",
     "r\n\n2026-12-01T00:00:00Z\n/blob/myaccount/pictures/p.jpg\n\n2015-02-21\n\n\n\n\n"),
    (b"sp=r&se=2026-12-01T00:00:00Z&sv=2015-02-21&sr=f", b"https://myaccount.file.core.windows.net/share/a.txt?", b"file",
     "r\n\n2026-12-01T00:00:00Z\n/file/myaccount/share/a.txt\n\n2015-02-21\n\n\n\n\n"),
    (b"sp=a&se=2026-12-01T00:00:00Z&sv=2014-02-14", b"https://myaccount.queue.core.windows.net/orders/messages?", b"queue",
     "a\n\n2026-12-01T00:00:00Z\n/myaccount/orders\n\n2014-02-14"),
    # 2012-02-12 signs a blob or container only, without response headers.
    (b"sp=r&se=2026-12-01T00:00:00Z&sv=2012-02-12&sr=c", b"https://myaccount.blob.core.windows.net/pictures/p.jpg?", b"blob",
     "r\n\n2026-12-01T00:00:00Z\n/myaccount/pictures\n\n2012-02-12"),
])
def test_older_and_table_service_sas_follow_their_documented_formats(query, url, service, expected):
    assert string_to_sign(sas_facts(query, account=b"myaccount", service=service, match=url)) == expected


@pytest.mark.parametrize("query,url,service", [
    (b"sp=r&se=2026-12-01T00:00:00Z&sv=2022-11-02&sr=b&skoid=11111111-2222-3333-4444-555555555555",
     b"https://myaccount.blob.core.windows.net/c/b?", b"blob"),  # user delegation key, not an account key
    (b"sp=r&se=2026-12-01T00:00:00Z&sv=2022-11-02&sr=b", b"", b"blob"),  # no resource path
    (b"sp=r&se=2026-12-01T00:00:00Z&sv=2022-11-02", b"https://myaccount.table.core.windows.net/x?", b"table"),  # no tn
    (b"sp=r&se=2026-12-01T00:00:00Z&sv=2014-02-14&sr=f", b"https://myaccount.file.core.windows.net/s/a?", b"file"),
    (b"sp=a&se=2026-12-01T00:00:00Z&sv=2012-02-12", b"https://myaccount.queue.core.windows.net/q?", b"queue"),
    (b"sp=r&se=2026-12-01T00:00:00Z&sv=2011-08-18&sr=b", b"https://myaccount.blob.core.windows.net/c/b?", b"blob"),
    (b"sv=2014-02-14&ss=b&srt=o&sp=r&se=2026-12-01T00:00:00Z", b"", b"blob"),  # account SAS starts at 2015-04-05
])
def test_unsupported_forms_have_no_string_to_sign(query, url, service):
    assert string_to_sign(sas_facts(query, account=b"myaccount", service=service, match=url)) is None


@pytest.mark.parametrize("encode", [
    lambda sig: sig,
    lambda sig: sig.replace("+", "%2B").replace("/", "%2F").replace("=", "%3D"),
    lambda sig: sig.replace("+", "%2b").replace("=", "%3d"),
])
def test_only_the_key_that_signed_the_sas_reproduces_its_fingerprint(encode):
    found = facts(b"sv=2022-11-02&ss=bfqt&srt=sco&sp=rwdlacup&se=2027-01-01T00:00:00Z")
    signature = base64.b64encode(hmac.new(base64.b64decode(KEY1), string_to_sign(found).encode(),
                                          hashlib.sha256).digest()).decode()
    sas = {"fingerprint": fingerprint(encode(signature).encode(), key=FINGERPRINT_KEY), "sas": found}
    assert signed_fingerprints(KEY1, "myaccount", [sas], FINGERPRINT_KEY) == [sas["fingerprint"]]
    assert signed_fingerprints(KEY2, "myaccount", [sas], FINGERPRINT_KEY) == []
    assert signed_fingerprints(KEY1, "otheraccount", [sas], FINGERPRINT_KEY) == []
    assert signed_fingerprints(KEY1, "myaccount", [sas], b"another-fingerprint-key-of-32-bytes!") == []
