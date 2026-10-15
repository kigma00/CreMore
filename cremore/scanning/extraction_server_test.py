"""The POSIX parser server: spawn-per-document results, limits, faults and isolation.

Synthetic documents only. Misbehaving servers are small scripts written to a temporary
directory and started in place of server.py; no document bytes are written to disk.
"""

import functools
import gzip
import io
import itertools
import os
import signal
import threading
import time
import zipfile
from dataclasses import replace

import pytest

from cremore.scanning import extraction
from cremore.scanning.document_scan_test import MARKER, doc, hwp, pdf, pe, xls, zipped
from cremore.scanning.extraction import DEFAULT_LIMITS, ExtractionResult, extract

pytestmark = pytest.mark.skipif(not hasattr(os, "fork"), reason=(
    "POSIX only: without os.fork (Windows) every document is parsed in its own spawned process"))
needs_proc = pytest.mark.skipif(not os.path.isdir("/proc"), reason="looks at processes through /proc (Linux)")

DOCX = zipped({"word/document.xml": b"<document><p><t>SYNTHETIC_</t><t>DOCUMENT_A1B2C3D4</t></p></document>"})
HANG = "import time\ntime.sleep(60)\n"
# The busy document keeps a parser child working far longer than this limit on any machine,
# so a test can look at the running child before the server ends it with PARSE_TIMEOUT.
BUSY = replace(DEFAULT_LIMITS, seconds=2)
# A test that kills the child ends as soon as it does; on a loaded machine finding the child can
# take longer than BUSY allows, and the server's own PARSE_TIMEOUT would come first.
KILLABLE = replace(DEFAULT_LIMITS, seconds=60)
CONTROL = b"HWP Document File"  # a constant every server and child holds in memory


class Cancelled(Exception):
    pass


@pytest.fixture(autouse=True)
def fresh_server():
    extraction._SERVER.stop()
    yield
    extraction._SERVER.stop()


@pytest.fixture
def started(monkeypatch):
    """Every parser server process started during the test, in order."""
    processes = []
    original = extraction.subprocess.Popen

    def start(*args, **kwargs):
        processes.append(original(*args, **kwargs))
        return processes[-1]

    monkeypatch.setattr(extraction.subprocess, "Popen", start)
    return processes


@pytest.fixture
def server_script(tmp_path, monkeypatch):
    """use(source) runs a stand-in server script from then on; use(None) restores server.py."""
    real = extraction._SERVER_SCRIPT

    def use(source):
        script = real
        if source is not None:
            script = tmp_path / "server.py"
            script.write_text(source, encoding="utf-8")
        monkeypatch.setattr(extraction, "_SERVER_SCRIPT", script)

    return use


@functools.cache
def busy_pdf():
    """One page with 500,000 text operations: many seconds of pypdf work, little memory."""
    from pypdf import PdfWriter
    from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject

    writer = PdfWriter()
    page = writer.add_blank_page(612, 792)
    font = DictionaryObject({NameObject("/Type"): NameObject("/Font"), NameObject("/Subtype"): NameObject("/Type1"),
                             NameObject("/BaseFont"): NameObject("/Helvetica")})
    page[NameObject("/Resources")] = DictionaryObject({NameObject("/Font"):
                                                       DictionaryObject({NameObject("/F1"): writer._add_object(font)})})
    stream = DecodedStreamObject()
    stream.set_data(b"BT /F1 12 Tf " + b"(x) Tj " * 500_000 + b"ET")
    page[NameObject("/Contents")] = writer._add_object(stream)
    page.compress_content_streams()
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def children(pid):
    """Process ids whose parent is pid, from /proc."""
    found = []
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            try:
                with open(f"/proc/{entry}/stat", "rb") as stat:
                    fields = stat.read().rsplit(b")", 1)[1].split()
            except OSError:
                continue
            if int(fields[1]) == pid:
                found.append(int(entry))
    return found


def gone(pid):
    """The process has exited (a zombie waiting for an unrelated reaper counts)."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as stat:
            return stat.read().rsplit(b")", 1)[1].split()[0] == b"Z"
    except OSError:
        return True


def settled(check, seconds=5):
    """The server zeroes and frees a request's buffers right after its reply: wait for that
    instead of sampling it mid-cleanup. A retained buffer never passes."""
    deadline = time.monotonic() + seconds
    while not (result := check()) and time.monotonic() < deadline:
        time.sleep(0.02)
    return result


def memory_hits(pid, needles):
    """How often each needle occurs in the readable memory of pid, and how much was read."""
    hits = dict.fromkeys(needles, 0)
    read = 0
    with open(f"/proc/{pid}/maps") as maps:
        regions = [line.split() for line in maps]
    try:
        with open(f"/proc/{pid}/mem", "rb", 0) as memory:
            for fields in regions:
                if "r" not in fields[1] or (len(fields) > 5 and fields[5].startswith("[v")):
                    continue
                start, end = (int(value, 16) for value in fields[0].split("-"))
                try:
                    memory.seek(start)
                    chunk = memory.read(end - start)
                except (OSError, ValueError, OverflowError):
                    continue
                read += len(chunk)
                for needle in needles:
                    hits[needle] += chunk.count(needle)
    except PermissionError:  # opening another process's memory can be refused
        return hits, 0
    return hits, read


CASES = [
    ("report.docx", lambda: DOCX, DEFAULT_LIMITS),
    ("report.pdf", pdf, DEFAULT_LIMITS),
    ("report.zip", lambda: zipped({"notes.txt": MARKER, "document.docx": DOCX, "tool.exe": pe()}), DEFAULT_LIMITS),
    ("report.txt.gz", lambda: gzip.compress(MARKER), DEFAULT_LIMITS),
    ("report.rtf", lambda: b"{\\rtf1\\ansi {\\footnote " + MARKER + b"}}", DEFAULT_LIMITS),
    ("report.hwp", hwp, DEFAULT_LIMITS),
    ("report.doc", doc, DEFAULT_LIMITS),
    ("report.xls", xls, DEFAULT_LIMITS),
    ("prefixed.pdf", lambda: b"\xef\xbb\xbf" + pdf(), DEFAULT_LIMITS),
    ("encrypted.pdf", lambda: pdf(encrypted=True), DEFAULT_LIMITS),
    ("malformed.zip", lambda: b"PK\x03\x04" + MARKER, DEFAULT_LIMITS),
    ("partial.zip", lambda: zipped({"notes.txt": MARKER, "unread.png": b"\x89PNG\r\n\x1a\n"}), DEFAULT_LIMITS),
    ("members.zip", lambda: zipped({"one": b"a", "two": b"b"}), replace(DEFAULT_LIMITS, members=1)),
    ("nested.zip", lambda: zipped({"n": zipped({"n": zipped({"notes.txt": MARKER})})}), replace(DEFAULT_LIMITS, depth=1)),
    ("pages.pdf", lambda: pdf(pages=2), replace(DEFAULT_LIMITS, pages=1)),
    ("short.docx", lambda: DOCX, replace(DEFAULT_LIMITS, text_bytes=10)),
]


@pytest.mark.parametrize("name,make,limits", CASES, ids=[case[0] for case in CASES])
def test_server_results_equal_spawn_per_document(name, make, limits, monkeypatch):
    data = make()
    served = extract(data, filename=name, limits=limits)
    monkeypatch.setattr(extraction, "_FORK_SERVER", False)
    assert extract(data, filename=name, limits=limits) == served
    assert type(served.data) is bytes


def test_a_parse_over_the_time_limit_is_killed_and_the_next_document_still_works(started):
    result = extract(busy_pdf(), limits=replace(DEFAULT_LIMITS, seconds=0.05))
    assert result == ExtractionResult(format="pdf", reason="PARSE_TIMEOUT")
    result = extract(pdf())
    assert result.complete and MARKER in result.data
    # The child died by a signal, so a fresh server read the next document.
    assert len(started) == 2 and started[0].poll() is not None and started[1].poll() is None


@needs_proc
@pytest.mark.parametrize("sent,reason", [
    ("SIGKILL", "PARSER_UNAVAILABLE"),  # from outside, like the OOM killer: retryable
    ("SIGSEGV", "PARSER_RESOURCE_LIMIT"),  # a crash maps like a failed spawned parser
])
def test_a_child_killed_by_a_signal_is_reported_and_its_server_replaced(sent, reason, started):
    assert extract(gzip.compress(MARKER)).complete  # a running server
    server = started[0].pid
    killed = []

    def crash():
        for pid in children(server):
            if not killed:
                os.kill(pid, getattr(signal, sent))
                killed.append(pid)

    assert extract(busy_pdf(), limits=KILLABLE, progress=crash) == ExtractionResult(format="pdf", reason=reason)
    assert killed
    assert extract(pdf()).complete and len(started) == 2 and started[0].poll() is not None


@needs_proc
def test_a_parser_child_does_not_outlive_a_server_killed_mid_request(started):
    assert extract(gzip.compress(MARKER)).complete
    server = started[0].pid
    orphans = []

    def kill_server():
        if not orphans and (found := children(server)):
            orphans.extend(found)
            os.kill(server, signal.SIGKILL)

    result = extract(busy_pdf(), limits=KILLABLE, progress=kill_server)
    assert result == ExtractionResult(format="pdf", reason="PARSER_UNAVAILABLE") and orphans
    # Left alone, the child would work on until its CPU-time backstop, seconds later.
    assert settled(lambda: all(map(gone, orphans)), seconds=1)


@needs_proc
def test_no_later_parser_child_holds_an_earlier_document():
    extracted_only = b"OUTPUT_ONLY_9F8E7D6C5B4A"  # deflated in the input: only the extracted text has it
    input_only = b"INPUT_ONLY_1A2B3C4D5E6F"  # an archive comment: in the input, never extracted
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("notes.txt", b"key " + extracted_only + b"\n")
        archive.comment = input_only
    earlier = out.getvalue()
    assert extracted_only not in earlier and input_only in earlier
    result = extract(earlier)
    assert extracted_only in result.data and input_only not in result.data
    needles = (CONTROL, extracted_only, input_only)
    server = extraction._SERVER.process.pid
    if not memory_hits(server, needles)[1]:
        pytest.skip("process memory is not readable in this environment")

    def clean(found):
        return found[CONTROL] and not found[extracted_only] and not found[input_only]

    # Every later child is a fork of this idle server.
    assert settled(lambda: clean(memory_hits(server, needles)[0]))
    later = {}

    def look():
        for pid in children(server):
            if pid not in later:
                try:
                    later[pid] = memory_hits(pid, needles)[0]
                except OSError:
                    pass  # that child already exited

    assert extract(busy_pdf(), limits=BUSY, progress=look).reason == "PARSE_TIMEOUT"
    assert later, "no running parser child was observed"
    assert all(map(clean, later.values()))


@needs_proc
def test_a_large_reply_leaves_the_server_no_bigger_for_later_children(started):
    def address_space():  # what RLIMIT_AS counts in every later child
        with open(f"/proc/{started[0].pid}/status") as status:
            return next(int(line.split()[1]) for line in status if line.startswith("VmSize:")) * 1024

    assert extract(gzip.compress(MARKER)).complete
    before = address_space()
    big = extract(zipped({"big.txt": b"A" * ((16 << 20) - 64)}))
    assert big.complete and len(big.data) > 15 << 20
    assert settled(lambda: address_space() - before < 4 << 20) and len(started) == 1


@pytest.mark.parametrize("source", [
    "import sys\nsys.stdin.buffer.readline()\nsys.stdout.buffer.write(b'not a reply\\n')\n"
    "sys.stdout.buffer.flush()\n" + HANG,
    "import sys\nsys.stdin.buffer.readline()\n",  # exits: the reply pipe closes early
], ids=["malformed-reply", "closed-pipe"])
def test_a_protocol_fault_discards_the_server_and_the_next_document_starts_another(source, started, server_script):
    server_script(source)
    assert extract(pdf()) == ExtractionResult(format="pdf", reason="PARSER_UNAVAILABLE")
    assert extraction._SERVER.process is None and started[0].poll() is not None
    server_script(None)
    assert extract(pdf()).complete and len(started) == 2


def test_a_hung_server_is_killed_after_the_margin(started, server_script, monkeypatch):
    margin = extraction._ForkServer.margin
    monkeypatch.setattr(extraction._ForkServer, "margin", 0.3)
    server_script(HANG)
    begun = time.monotonic()
    assert extract(pdf(), limits=replace(DEFAULT_LIMITS, seconds=0.2)) == ExtractionResult(
        format="pdf", reason="PARSE_TIMEOUT")
    assert time.monotonic() - begun < 5 and started[0].poll() is not None
    monkeypatch.setattr(extraction._ForkServer, "margin", margin)
    server_script(None)
    assert extract(pdf()).complete and len(started) == 2


def test_progress_runs_while_waiting_and_its_exception_ends_the_request(started, server_script):
    server_script(HANG)
    calls = []

    def progress():
        calls.append(time.monotonic())
        if len(calls) == 4:
            raise Cancelled

    with pytest.raises(Cancelled):
        extract(pdf(), progress=progress)
    # Called before the request, then about every 0.2 s while the server is silent.
    assert len(calls) == 4 and max(b - a for a, b in itertools.pairwise(calls)) < 0.5
    assert extraction._SERVER.process is None and started[0].poll() is not None
    server_script(None)
    assert extract(pdf()).complete and len(started) == 2


def test_the_server_is_replaced_after_recycle_after_documents(started, monkeypatch):
    monkeypatch.setattr(extraction._ForkServer, "recycle_after", 2)
    for _ in range(3):
        assert extract(gzip.compress(MARKER)).complete
    assert len(started) == 2 and started[0].poll() is not None and started[1].poll() is None


def test_a_server_that_died_while_idle_is_replaced_transparently(started):
    assert extract(pdf()).complete
    started[0].kill()
    started[0].wait()
    assert extract(pdf()).complete and len(started) == 2


def test_concurrent_extracts_share_one_server_one_request_at_a_time(started):
    documents = [zipped({"word/document.xml": b"<p><t>SYNTHETIC_DOCUMENT_%08d</t></p>" % n}) for n in range(16)]
    results = [None] * len(documents)

    def work(n):
        results[n] = extract(documents[n], filename="report.docx")

    threads = [threading.Thread(target=work, args=(n,)) for n in range(len(documents))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    for n, result in enumerate(results):
        assert result.complete and result.format == "docx"
        assert result.data.count(b"SYNTHETIC_DOCUMENT_") == 1 and b"SYNTHETIC_DOCUMENT_%08d" % n in result.data
    assert len(started) == 1 and extraction._SERVER.served == len(documents)


def test_neither_the_server_nor_its_parser_children_see_the_scanner_environment(monkeypatch):
    monkeypatch.setenv("SYNTHETIC_SECRET_TOKEN", "synthetic-secret-value")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "synthetic-environment-value")
    settings = []
    original = extraction.subprocess.Popen

    def start(*args, **kwargs):
        settings.append(kwargs)
        return original(*args, **kwargs)

    monkeypatch.setattr(extraction.subprocess, "Popen", start)
    assert extract(gzip.compress(MARKER)).complete
    assert len(settings) == 1 and settings[0]["env"] == {"MALLOC_MMAP_THRESHOLD_": "131072"}
    assert settings[0]["close_fds"] is True and settings[0]["start_new_session"] is True
    if not os.path.isdir("/proc"):
        return
    server = extraction._SERVER.process.pid
    environments = {}

    def inspect():  # runs while a parser child works on the busy document
        for pid in [server, *children(server)]:
            try:
                with open(f"/proc/{pid}/environ", "rb") as stream:
                    environments[pid] = stream.read()
            except OSError:
                pass  # that child already exited

    assert extract(busy_pdf(), limits=BUSY, progress=inspect).reason == "PARSE_TIMEOUT"
    assert set(environments) - {server}, "no running parser child was observed"
    assert not any(b"synthetic" in environ for environ in environments.values())


def test_a_forked_copy_of_the_scanner_never_shares_the_parent_server():
    assert extract(pdf()).complete
    server = extraction._SERVER.process
    pid = os.fork()
    if pid == 0:
        code = 1
        try:
            if extraction._SERVER.process is None and extract(pdf()).complete:
                code = 0
            extraction._SERVER.stop()
        finally:
            os._exit(code)
    deadline = time.monotonic() + 60
    while not (finished := os.waitpid(pid, os.WNOHANG))[0]:
        if time.monotonic() > deadline:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            pytest.fail("the forked copy did not finish")
        time.sleep(0.05)
    assert os.waitstatus_to_exitcode(finished[1]) == 0
    assert extraction._SERVER.process is server and extract(pdf()).complete
