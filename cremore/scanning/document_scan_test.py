"""Synthetic document bytes only: extraction, bounded work, and durable safety."""

import base64
import bz2
import gzip
import io
import json
import lzma
import struct
import tarfile
import time
import uuid
import zipfile
import zlib
from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace

import pytest

from cremore.collectors.base import CollectedObject
from cremore.db.repository import InMemoryRepository
from cremore.db.scan_store import ScanStore
from cremore.detection import Engine, ResourceRef
from cremore.detection.custom import rule_definition
from cremore.detection.models import DetectorInput
from cremore.domain.models import CustomRule
from cremore.scanning.extraction import DEFAULT_LIMITS, ExtractionResult, cache_digest, extract
from cremore.scanning.extraction.contract import EXTRACTOR_EPOCH, RETRYABLE_REASONS
from cremore.scanning.orchestrator import Orchestrator
from cremore.scanning.service import ScanService
from cremore.sources.registry import SOURCE_TYPES

MARKER = b"SYNTHETIC_DOCUMENT_A1B2C3D4"
SECOND = b"SYNTHETIC_DOCUMENT_E5F6G7H8"
MARKER_TEXT = MARKER.decode()


def zipped(members):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, value in members.items():
            archive.writestr(name, value)
    return out.getvalue()


def pdf(text=MARKER, *, pages=1, encrypted=False):
    from pypdf import PdfWriter
    from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject

    writer = PdfWriter()
    for _ in range(pages):
        page = writer.add_blank_page(612, 792)
        if text:
            font = DictionaryObject({NameObject("/Type"): NameObject("/Font"),
                                     NameObject("/Subtype"): NameObject("/Type1"),
                                     NameObject("/BaseFont"): NameObject("/Helvetica")})
            page[NameObject("/Resources")] = DictionaryObject({NameObject("/Font"):
                DictionaryObject({NameObject("/F1"): writer._add_object(font)})})
            stream = DecodedStreamObject()
            stream.set_data(b"BT /F1 12 Tf 20 100 Td (" + text + b") Tj ET")
            page[NameObject("/Contents")] = writer._add_object(stream)
            page.compress_content_streams()
    if encrypted:
        writer.encrypt("synthetic-fixture-password")
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def compound(streams, *, scattered=()):
    """Small, valid CFB v3 fixture writer with a mini FAT; no disk fixtures. The streams named
    in `scattered` keep their 64-byte mini sectors last to first in the file."""
    end, free, fat_mark = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD
    entries = [{"name": "Root Entry", "type": 5, "children": []}]
    lookup = {(): 0}
    mini = bytearray()
    mini_fat = []
    for path, value in streams.items():
        parts = tuple(path.split("/"))
        for index, part in enumerate(parts):
            key = parts[:index + 1]
            if key in lookup:
                continue
            parent = lookup[key[:-1]]
            is_stream = index == len(parts) - 1
            entry = {"name": part, "type": 2 if is_stream else 1, "children": []}
            if is_stream:
                assert 0 < len(value) < 4096
                start = len(mini_fat)
                count = (len(value) + 63) // 64
                order = list(range(count))[::-1] if path in scattered else list(range(count))
                sectors, chain = [b""] * count, [end] * count
                for n, slot in enumerate(order):  # chunk n sits in mini sector start + slot
                    sectors[slot] = value[n * 64:(n + 1) * 64].ljust(64, b"\0")
                    chain[slot] = start + order[n + 1] if n + 1 < count else end
                mini.extend(b"".join(sectors))
                mini_fat.extend(chain)
                entry.update(start=start + order[0], size=len(value))
            lookup[key] = len(entries)
            entries[parent]["children"].append(len(entries))
            entries.append(entry)
    directory_count = (len(entries) + 3) // 4
    mini_count = (len(mini) + 511) // 512
    mini_fat_count = (len(mini_fat) + 127) // 128
    total = directory_count + mini_count + mini_fat_count + 1
    assert total < 128
    directory = bytearray(directory_count * 512)
    siblings = {}
    for entry in entries:
        for a, b in zip(entry["children"], entry["children"][1:]):
            siblings[a] = b
    for index, entry in enumerate(entries):
        offset = index * 128
        name = (entry["name"] + "\0").encode("utf-16-le")
        directory[offset:offset + len(name)] = name
        struct.pack_into("<HBBIII", directory, offset + 64, len(name), entry["type"], 1,
                         free, siblings.get(index, free), entry["children"][0] if entry["children"] else free)
        struct.pack_into("<IQ", directory, offset + 116,
                         directory_count if index == 0 else entry.get("start", end),
                         len(mini) if index == 0 else entry.get("size", 0))
    fat = [free] * 128
    for start, count in ((0, directory_count), (directory_count, mini_count),
                         (directory_count + mini_count, mini_fat_count)):
        for n in range(count):
            fat[start + n] = start + n + 1 if n + 1 < count else end
    fat[total - 1] = fat_mark
    header = bytearray(512)
    header[:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<HHHH", header, 24, 0x3E, 3, 0xFFFE, 9)
    struct.pack_into("<H", header, 32, 6)
    struct.pack_into("<IIIIIIIII", header, 40, 0, 1, 0, 0, 4096,
                     directory_count + mini_count, mini_fat_count, end, 0)
    struct.pack_into("<109I", header, 76, total - 1, *([free] * 108))
    padded_mini_fat = mini_fat + [free] * (mini_fat_count * 128 - len(mini_fat))
    return (bytes(header) + bytes(directory) + bytes(mini).ljust(mini_count * 512, b"\0")
            + struct.pack(f"<{len(padded_mini_fat)}I", *padded_mini_fat) + struct.pack("<128I", *fat))


def hwp(text=MARKER_TEXT, *, compressed=True, encrypted=False, declared_sections=1):
    header = bytearray(256)
    header[:17] = b"HWP Document File"
    struct.pack_into("<II", header, 32, 0x05000300, int(compressed) | (2 if encrypted else 0))
    content = (text + "\r").encode("utf-16-le")
    para = struct.pack("<I", len(content) // 2) + bytes(18)
    section = (struct.pack("<I", 66 | (len(para) << 20)) + para
               + struct.pack("<I", 67 | (1 << 10) | (len(content) << 20)) + content)
    info = struct.pack("<IH", 16 | (30 << 20), declared_sections) + bytes(28)
    if compressed:
        compressor = zlib.compressobj(wbits=-15)
        section = compressor.compress(section) + compressor.flush()
        compressor = zlib.compressobj(wbits=-15)
        info = compressor.compress(info) + compressor.flush()
    return compound({"FileHeader": bytes(header), "DocInfo": info, "BodyText/Section0": section})


def doc(text=MARKER_TEXT, *, compressed=False, encrypted=False, declared_chars=None):
    word = bytearray(1024)
    struct.pack_into("<HH", word, 0, 0xA5EC, 0x00C1)
    struct.pack_into("<H", word, 10, 0x0100 if encrypted else 0)
    struct.pack_into("<H", word, 32, 14)
    struct.pack_into("<H", word, 62, 22)
    struct.pack_into("<I", word, 76, len(text) if declared_chars is None else declared_chars)
    struct.pack_into("<H", word, 152, 93)
    raw = text.encode("cp1252" if compressed else "utf-16-le")
    assert 900 + len(raw) <= len(word)
    word[900:900 + len(raw)] = raw
    pieces = struct.pack("<IIHIH", 0, len(text), 0, (900 * 2) | 0x40000000 if compressed else 900, 0)
    clx = b"\x02" + struct.pack("<I", len(pieces)) + pieces
    struct.pack_into("<II", word, 154 + 33 * 8, 0, len(clx))
    return compound({"WordDocument": bytes(word), "0Table": clx})


def xls(text=MARKER, *, encrypted=False, extra=None):
    """BIFF8 workbook globals: BOF, an optional FilePass, one shared string, EOF."""
    records = [(0x0809, struct.pack("<HHHHII", 0x0600, 0x0005, 0, 0, 0, 0))]
    if encrypted:
        records.append((0x002F, struct.pack("<HHH", 1, 1, 1) + bytes(48)))
    records += [(0x00FC, struct.pack("<IIHB", 1, 1, len(text), 0) + text), (0x000A, b"")]
    return compound({"Workbook": b"".join(struct.pack("<HH", record, len(body)) + body
                                          for record, body in records), **(extra or {})})


def ppt(text=MARKER_TEXT, *, encrypted=False, records=b"", scattered=False):
    """PowerPoint 97: a CurrentUserAtom and one UTF-16LE TextCharsAtom, then `records`."""
    current = struct.pack("<HHIII", 0, 0x0FF6, 20, 0x14, 0xF3D1C4DF if encrypted else 0xE391C05F)
    chars = text.encode("utf-16-le")
    return compound({"Current User": current + bytes(16),
                     "PowerPoint Document": struct.pack("<HHI", 0, 0x0FA0, len(chars)) + chars + records},
                    scattered={"PowerPoint Document"} if scattered else ())


def biff(*records):
    return b"".join(struct.pack("<HH", record, len(body)) + body for record, body in records)


BIFF_BOF = (0x0809, struct.pack("<HHHHII", 0x0600, 0x0005, 0, 0, 0, 0))


def ascii_pdf(text=MARKER):
    """A PDF of ASCII bytes only (ASCII85 content stream), so it also decodes as UTF-8."""
    content = base64.a85encode(zlib.compress(b"BT /F1 12 Tf 72 712 Td (" + text + b") Tj ET")) + b"~>"
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
               (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R"
                b" /Resources << /Font << /F1 5 0 R >> >> >>"),
               b"<< /Length %d /Filter [/ASCII85Decode /FlateDecode] >>\nstream\n" % len(content)
               + content + b"\nendstream", b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    out, offsets = bytearray(b"%PDF-1.4\n"), []
    for number, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 6\n0000000000 65535 f \n" + b"".join(b"%010d 00000 n \n" % o for o in offsets)
    return bytes(out + b"trailer << /Size 6 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % xref)


def hwp3(text=MARKER_TEXT, *, encrypted=False, compressed=False):
    """HWP 3.0 signature and document information; the body stores ASCII as 16-bit characters."""
    info = bytearray(128)  # file offsets 30-157: password word at 126, compression flag at 154
    struct.pack_into("<H", info, 96, int(encrypted))
    info[124] = int(compressed)
    return b"HWP Document File V3.00 \x1a\x01\x02\x03\x04\x05" + bytes(info) + text.encode("utf-16-le") + bytes(8)


def pe(payload=MARKER):
    """A DOS header pointing at a PE header, then data."""
    header = bytearray(64)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 60, 64)
    return bytes(header) + b"PE\x00\x00" + bytes(20) + payload + bytes(8)


def service(*, limits=DEFAULT_LIMITS):
    repo = InMemoryRepository()
    rule = CustomRule(id=uuid.uuid4(), name="Synthetic documents", pattern=r"SYNTHETIC_DOCUMENT_[A-Z0-9]{8}")
    engine = Engine(definitions=[rule_definition(rule)])
    orchestrator = Orchestrator(repo, engine=engine)
    orchestrator._rules = {f"custom-{rule.id}": rule}
    return repo, ScanService(orchestrator, extraction_limits=limits), uuid.uuid4()


def source(data, *, path="report", revision="v1", source_type="github", loader=None):
    obj = CollectedObject(ResourceRef(source_type=source_type, resource="synthetic", location=path,
                                     revision=revision, size=len(data or b"")), data, loader=loader)
    return SimpleNamespace(collect=lambda: iter([obj]), failed_objects=0, obj=obj)


@pytest.mark.parametrize("name,make", [
    ("report.pdf", pdf), ("report.doc", doc), ("compressed.doc", lambda: doc(compressed=True)),
    ("report.hwp", hwp), ("plain.hwp", lambda: hwp(compressed=False)),
    ("report.rtf", lambda: b"{\\rtf1\\ansi " + MARKER + b"}"),
    ("report.docx", lambda: zipped({"word/document.xml": b"<document><p><t>SYNTHETIC_</t><t>DOCUMENT_A1B2C3D4</t></p></document>"})),
    ("report.pptx", lambda: zipped({"ppt/presentation.xml": b"<presentation/>", "ppt/slides/slide1.xml": b"<slide><p><t>" + MARKER + b"</t></p></slide>"})),
    ("report.xlsx", lambda: zipped({"xl/workbook.xml": b"<workbook/>", "xl/sharedStrings.xml": b"<sst><si><t>" + MARKER + b"</t></si></sst>"})),
    ("report.odt", lambda: zipped({"META-INF/manifest.xml": b"<manifest/>", "content.xml": b"<body><p>" + MARKER + b"</p></body>"})),
    ("report.hwpx", lambda: zipped({"Contents/content.hpf": b"<package/>", "Contents/section0.xml": b"<section><p><t>" + MARKER + b"</t></p></section>"})),
    ("report.zip", lambda: zipped({"notes.txt": MARKER, "document.docx": zipped({"word/document.xml": b"<p>ordinary</p>"})})),
    ("report.txt.gz", lambda: gzip.compress(MARKER)),
    ("report.txt", lambda: MARKER), ("unicode.txt", lambda: ("한글 " + MARKER.decode()).encode("utf-16")),
    ("legacy.txt", lambda: ("한글 " + MARKER_TEXT).encode("cp949")),
    ("program.bin", lambda: b"\x7fELF\x02\x01\x01\x00" + bytes(8) + MARKER + bytes(4)),
    ("tool.exe", pe), ("bundle.zip", lambda: zipped({"tool.exe": pe(), "notes.txt": b"ordinary"})),
    ("report.xls", xls), ("slides.ppt", ppt), ("legacy.hwp", hwp3),
])
def test_supported_documents_detect_and_keep_plaintext_out_of_storage(name, make):
    data = make()
    extracted = extract(data, filename=name)
    assert extracted.complete, extracted.reason
    assert MARKER in extracted.data
    repo, scan, cid = service()
    result = scan.run(source(data, path=name), source_connection_id=cid)
    assert result.detections == result.findings == result.objects == 1
    assert result.objects_failed == result.skipped_unsupported == 0
    durable = repr(vars(repo))
    assert MARKER.decode() not in durable
    assert len(repo.exposures) == 1
    assert next(iter(repo.exposures.values())).location == name


@pytest.mark.parametrize("source_type", SOURCE_TYPES)
def test_common_document_path_preserves_provider_location(source_type):
    repo, scan, cid = service()
    result = scan.run(source(pdf(), path="approved/report.pdf", source_type=source_type), source_connection_id=cid)
    assert result.detections == 1
    exposure = next(iter(repo.exposures.values()))
    assert exposure.source_type == source_type and exposure.location == "approved/report.pdf"
    assert MARKER.decode() not in repr(vars(repo))


def test_public_document_reasons_never_include_parser_output():
    from cremore.api.source_presenters import present_scan_run
    from cremore.domain.models import ScanJob
    from cremore.scanning.scope import run_public

    job = ScanJob(kind="scope", coverage={"extraction_reasons": {
        "ENCRYPTED_DOCUMENT": 2, "private parser output": 1, "COUNT": -1, "RAW": "secret"}})
    expected = {"ENCRYPTED_DOCUMENT": 2}
    assert present_scan_run(job)["extraction_reasons"] == expected
    assert run_public(job, "source", uuid.uuid4())["extraction_reasons"] == expected


@pytest.mark.parametrize("data,reason", [
    (b"%PDF-1.7\n" + MARKER, "MALFORMED_DOCUMENT"),
    (b"PK\x03\x04" + MARKER, "MALFORMED_DOCUMENT"),
    (b"\x89PNG\r\n\x1a\n" + MARKER, "MEDIA_FORMAT"),
    (b"\x00\x00\x00\x18ftypmp42" + MARKER, "MEDIA_FORMAT"),
    (b"7z\xbc\xaf\x27\x1c" + MARKER, "UNSUPPORTED_FORMAT"),
    (b"\x28\xb5\x2f\xfd" + MARKER, "UNSUPPORTED_FORMAT"),  # zstd
    (b"\x04\x22\x4d\x18" + MARKER, "UNSUPPORTED_FORMAT"),  # LZ4 frame
])
def test_unsupported_bytes_never_scan_as_text_or_retire_previous_exposure(data, reason):
    repo, scan, cid = service()
    scan.run(source(MARKER), source_connection_id=cid)
    old = next(iter(repo.exposures.values()))
    result = scan.run(source(data, revision="v2"), source_connection_id=cid, reconcile_objects=True)
    assert result.detections == 0
    assert result.extraction_reasons == {reason: 1}
    assert repo.exposures[old.id].status == "OPEN"
    # Rescanning the unchanged object (from the cache where the service caches skips)
    # never retires the earlier exposure either.
    scan.run(source(data, revision="v2"), source_connection_id=cid, reconcile_objects=True)
    assert repo.exposures[old.id].status == "OPEN"


@pytest.mark.parametrize("make", [lambda: pdf(encrypted=True), lambda: hwp(encrypted=True), lambda: doc(encrypted=True),
                                  lambda: xls(encrypted=True), lambda: ppt(encrypted=True)])
def test_encrypted_document_is_explicit_and_never_guesses_password(make):
    result = extract(make())
    assert not result.complete and not result.data
    assert result.reason == "ENCRYPTED_DOCUMENT"


def test_blank_pdf_has_no_clean_absence_claim():
    result = extract(pdf(text=b""))
    assert not result.complete and result.reason == "NO_EXTRACTABLE_TEXT"


def test_binary_bytes_are_read_as_printable_ascii_and_utf16_strings():
    key = b"AKIA" + b"SYNTHETIC0000001"  # AWS-like synthetic key id between binary bytes
    data = b"\x00\x01\x02\x03" + key + b"\x00\x7f\x80short\x01\x01" + MARKER_TEXT.encode("utf-16-le") + b"\x05\x06"
    # Runs shorter than 8 characters ("short") are not strings.
    assert extract(data) == ExtractionResult(key + b"\n" + MARKER, "binary", True, "")


@pytest.mark.parametrize("data", [
    b"\x7fELF\x02\x01\x01\x00" + bytes(8) + MARKER, pe(), b"\xcf\xfa\xed\xfe\x07\x00\x00\x01" + MARKER,
    b"\xca\xfe\xba\xbe\x00\x00\x00\x41" + MARKER, b"SQLite format 3\x00" + bytes(84) + MARKER,
])
def test_executables_classes_and_databases_are_binary(data):
    result = extract(data)
    assert result.format == "binary" and result.complete and not result.reason and MARKER in result.data


def test_binary_strings_are_bounded_by_the_text_limit():
    limits = replace(DEFAULT_LIMITS, text_bytes=10)
    assert extract(pe(), limits=limits) == ExtractionResult(MARKER[:10], "binary", False, "TEXT_LIMIT")


@pytest.mark.parametrize("text,encoding", [
    ("비밀 설정 " + MARKER_TEXT, "cp949"), ("café " + MARKER_TEXT + " Ångström", "latin-1"),
])
def test_legacy_encoded_text_is_decoded_completely(text, encoding):
    assert extract(text.encode(encoding)) == ExtractionResult(text.encode("utf-8"), "text", True, "")


@pytest.mark.parametrize("make,label", [(xls, "ole-strings"), (ppt, "ole-strings"), (hwp3, "hwp3-strings")])
def test_legacy_office_and_hwp3_files_are_read_as_strings(make, label):
    result = extract(make())
    assert result.format == label and result.complete and not result.reason and MARKER in result.data
    assert result.data.count(MARKER) == 1  # a decoded shared string is not read again as raw bytes


@pytest.mark.parametrize("cut", [1, 9, 20, 39])
@pytest.mark.parametrize("wide_rest", [False, True])
def test_a_shared_string_cut_by_a_continue_record_is_read_whole(cut, wide_rest):
    # Past 8224 bytes the table goes on in CONTINUE records; a string cut there resumes after a
    # flag byte that may switch it to UTF-16. In the file the token is split in two.
    head, rest = GITHUB_TOKEN[:cut], GITHUB_TOKEN[cut:]
    data = compound({"Workbook": biff(
        BIFF_BOF, (0x00FC, struct.pack("<IIHB", 1, 1, len(GITHUB_TOKEN), 0) + head),
        (0x003C, b"\x01" + rest.decode().encode("utf-16-le") if wide_rest else b"\x00" + rest), (0x000A, b""))})
    assert GITHUB_TOKEN not in data and GITHUB_TOKEN.decode().encode("utf-16-le") not in data
    result = extract(data)
    assert result.format == "ole-strings" and result.complete and GITHUB_TOKEN in result.data


@pytest.mark.parametrize("cut", [1, 20, 39])
@pytest.mark.parametrize("wide_rest", [False, True])
@pytest.mark.parametrize("kind", ["comment", "formula"])
def test_a_comment_or_formula_string_cut_by_a_continue_record_is_read_whole(kind, cut, wide_rest):
    # A comment or text box (TxO) keeps its text in CONTINUE records and a formula's string result (String) goes on
    # in them past its own record; each piece starts with a width flag, which splits the token in the file.
    head, rest = GITHUB_TOKEN[:cut], GITHUB_TOKEN[cut:]
    tail = b"\x01" + rest.decode().encode("utf-16-le") if wide_rest else b"\x00" + rest
    if kind == "comment":
        records = [(0x01B6, struct.pack("<HH6sHHH", 0, 0, bytes(6), len(GITHUB_TOKEN), 16, 0)),
                   (0x003C, b"\x00" + head), (0x003C, tail), (0x003C, bytes(16))]
    else:
        records = [(0x0207, struct.pack("<HB", len(GITHUB_TOKEN), 0) + head), (0x003C, tail)]
    data = compound({"Workbook": biff(BIFF_BOF, *records, (0x000A, b""))})
    assert GITHUB_TOKEN not in data and GITHUB_TOKEN.decode().encode("utf-16-le") not in data
    result = extract(data)
    assert result.format == "ole-strings" and result.complete and GITHUB_TOKEN in result.data


def test_a_comment_whose_text_does_not_parse_is_read_raw_and_not_certified():
    # It claims more characters than its CONTINUE records hold: the raw bytes stay for the strings reading.
    records = [(0x01B6, struct.pack("<HH6sHHH", 0, 0, bytes(6), 500, 16, 0)), (0x003C, b"\x00" + GITHUB_TOKEN)]
    result = extract(compound({"Workbook": biff(BIFF_BOF, *records, (0x000A, b""))}))
    assert not result.complete and result.reason == "MALFORMED_DOCUMENT" and GITHUB_TOKEN in result.data



def test_shared_strings_resume_formatting_runs_and_phonetic_data_across_records():
    from cremore.scanning.extraction.formats import shared_strings

    first, second, third = b"alpha-one", "beta-two-wide", b"gamma"
    wide = second.encode("utf-16-le")
    stream = biff(
        BIFF_BOF,
        # One rich string whose characters end the record; its formatting run starts the next.
        (0x00FC, struct.pack("<IIHBH", 3, 3, len(first), 0x08, 1) + first),
        # The run, then a UTF-16 string with phonetic data, cut after five characters.
        (0x003C, struct.pack("<HH", 0, 1) + struct.pack("<HBI", len(second), 0x05, 6) + wide[:10]),
        # A flag byte resumes its characters 8-bit; the phonetic data is cut once more.
        (0x003C, b"\x00" + second[5:].encode("latin-1") + b"\xaa" * 4),
        (0x003C, b"\xaa" * 2 + struct.pack("<HB", len(third), 0) + third),
        (0x00FF, struct.pack("<H", 8)), (0x000A, b""))
    narrow, wide_text, rest, left = shared_strings(stream)
    # 8-bit strings, and a string with UTF-16 characters whole as UTF-16LE, for printable-run reading.
    assert narrow == b"alpha-one\ngamma\n" and wide_text == second.encode("utf-16-le") + b"\n\x00" and not left
    assert rest.startswith(biff(BIFF_BOF)) and rest.endswith(biff((0x00FF, struct.pack("<H", 8)), (0x000A, b"")))
    assert b"alpha" not in rest and b"gamma" not in rest


def test_shared_strings_spend_the_text_budget_like_printable_runs():
    # A workbook of Korean and short cell texts: only printable runs of eight or more characters
    # count against the text limit, as for any other stream, so the token at the end is read.
    korean = ["비밀번호설정값입니다" for _ in range(60)] + ["short" for _ in range(60)]
    strings_ = [text.encode("utf-16-le") for text in korean[:60]] + [text.encode() for text in korean[60:]]
    table = b"".join(struct.pack("<HB", len(text), 1 if index < 60 else 0) + raw
                     for index, (text, raw) in enumerate(zip(korean, strings_)))
    table += struct.pack("<HB", len(GITHUB_TOKEN), 0) + GITHUB_TOKEN
    data = compound({"Workbook": biff(BIFF_BOF, (0x00FC, struct.pack("<II", 121, 121) + table), (0x000A, b""))})
    result = extract(data, limits=replace(DEFAULT_LIMITS, text_bytes=600))
    assert result.format == "ole-strings" and result.complete and GITHUB_TOKEN in result.data


def test_bytes_after_the_declared_shared_strings_are_still_read_but_not_certified():
    # One string declared, two stored: the second is not decoded, so it stays for the raw reading,
    # where a string cut by a CONTINUE record would split. The table does not match its count.
    table = struct.pack("<II", 2, 1) + struct.pack("<HB", 5, 0) + b"hello"
    table += struct.pack("<HB", len(GITHUB_TOKEN), 0) + GITHUB_TOKEN
    result = extract(compound({"Workbook": biff(BIFF_BOF, (0x00FC, table), (0x000A, b""))}))
    assert result.format == "ole-strings" and not result.complete and result.reason == "MALFORMED_DOCUMENT"
    assert GITHUB_TOKEN in result.data


def test_a_table_of_crafted_duplicate_strings_is_not_decoded_to_the_time_limit():
    from cremore.scanning.extraction.formats import shared_strings

    # 200,000 empty strings: Excel never stores one string twice, so no real table walks that many
    # strings in so few bytes. Records are cut between strings, as Excel does.
    first, rest = 2738, 200_000 - 2738
    records = [(0x00FC, struct.pack("<II", 200_000, 200_000) + b"\x00\x00\x00" * first)]
    while rest:
        count = min(rest, 2741)
        records.append((0x003C, b"\x00\x00\x00" * count))
        rest -= count
    assert shared_strings(biff(BIFF_BOF, *records, (0x000A, b""))) is None


def test_an_empty_stream_whose_directory_names_sector_zero_is_skipped():
    # Some writers give an empty stream start sector 0 instead of the end-of-chain mark.
    data = bytearray(compound({"Workbook": biff(BIFF_BOF, (0x00FC, struct.pack("<IIHB", 1, 1, len(MARKER), 0) + MARKER),
                                                (0x000A, b"")), "Pictures": b"p" * 64}))
    struct.pack_into("<IQ", data, directory_entry(2) + 116, 0, 0)
    result = extract(bytes(data))
    assert result.format == "ole-strings" and result.complete and MARKER in result.data


def directory_entry(index):
    """Offset of a directory entry in a compound() file: the header, then the directory."""
    return 512 + index * 128


def test_streams_whose_chains_run_into_each_other_are_read_as_the_raw_file():
    # The second stream starts one mini sector into the first: together they claim more than the
    # file holds, and each would read the other's bytes again. Such a directory is damaged.
    first = MARKER + b"a" * (4000 - len(MARKER))
    data = bytearray(compound({"Workbook": biff(BIFF_BOF, (0x00FC, struct.pack("<IIHB", 1, 1, 5, 0) + b"hello"),
                                                (0x000A, b"")), "Pad": first, "Other": b"b" * 64}))
    struct.pack_into("<IQ", data, directory_entry(3) + 116, 2, len(first) - 64)  # "Other" inside "Pad"
    result = extract(bytes(data))
    assert result.format == "ole-strings" and not result.complete and result.reason == "MALFORMED_DOCUMENT"
    assert MARKER in result.data


def test_a_stream_that_does_not_read_leaves_the_raw_file_strings():
    # A stream longer than its chain: the other streams' text is not thrown away.
    data = bytearray(compound({"Workbook": biff(BIFF_BOF, (0x00FC, struct.pack("<IIHB", 1, 1, len(MARKER), 0) + MARKER),
                                                (0x000A, b"")), "Broken": b"c" * 64}))
    struct.pack_into("<Q", data, directory_entry(2) + 120, 640)
    result = extract(bytes(data))
    assert result.format == "ole-strings" and not result.complete and result.reason == "MALFORMED_DOCUMENT"
    assert MARKER in result.data


def test_a_shared_string_table_that_does_not_parse_is_still_read_and_reported():
    # It declares 40 characters and holds 27: the raw strings are kept, the gap is named.
    data = compound({"Workbook": biff(BIFF_BOF, (0x00FC, struct.pack("<IIHB", 1, 1, 40, 0) + MARKER),
                                      (0x000A, b""))})
    result = extract(data)
    assert result.format == "ole-strings" and not result.complete and result.reason == "MALFORMED_DOCUMENT"
    assert MARKER in result.data


def test_a_stream_is_read_in_sector_order_not_file_order():
    # The text crosses a 64-byte mini sector boundary and the sectors are stored last to first.
    data = ppt("x" * 20 + MARKER_TEXT, scattered=True)
    assert MARKER_TEXT.encode("utf-16-le") not in data
    result = extract(data)
    assert result.format == "ole-strings" and result.complete and MARKER in result.data


def test_a_large_workbook_stream_is_read_whole_despite_the_member_size_limit():
    # A stream read as stored is bounded by the input limit; only inflated members use the member limit.
    result = extract(xls(b"x" * 200 + MARKER), limits=replace(DEFAULT_LIMITS, member_bytes=64))
    assert result.format == "ole-strings" and result.complete and MARKER in result.data


GITHUB_TOKEN = b"ghp_" + b"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"  # synthetic token shapes
AWS_KEYS = b"AKIA" + b"IOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/" + b"bPxRfiCYEXAMPLEKEY"


@pytest.mark.parametrize("legacy,utf8", [
    (b"GITHUB_TOKEN=\xa0" + GITHUB_TOKEN + b"\n", "GITHUB_TOKEN=\u00a0".encode() + GITHUB_TOKEN + b"\n"),
    (b"Keys\n\xb7" + AWS_KEYS + b"\n", "Keys\n\u00b7".encode() + AWS_KEYS + b"\n"),
])
def test_a_stray_cp1252_byte_never_swallows_the_secret_after_it(legacy, utf8):
    # In CP949 the byte would pair with the next ASCII letter; the latin-1 reading follows.
    engine = Engine()
    ref = ResourceRef(source_type="github", resource="synthetic", location="notes.txt", revision="v1")

    def found(data):
        extracted = extract(data)
        assert extracted.complete
        return {d.detector_name for d in engine.scan(DetectorInput(extracted.data, ref, verify=False))}

    assert found(legacy) == found(utf8) != set()


def test_korean_with_extension_syllables_is_read_both_ways():
    # "똠" is a CP949 extension syllable whose trail byte is an ASCII letter.
    text = "설정 파일\n비밀번호 = 똠방각하\n"
    data = text.encode("cp949")
    assert extract(data) == ExtractionResult(text.encode() + b"\n" + data.decode("latin-1").encode(),
                                             "text", True, "")


def test_legacy_text_with_a_stray_control_byte_is_read_as_text():
    data = "로그\r\n토큰=ab12XY\r\nAPI_KEY=".encode("cp949") + GITHUB_TOKEN + b"\r\n\x1a"  # DOS Ctrl-Z
    expected = ("로그\r\n토큰=ab12XY\r\nAPI_KEY=" + GITHUB_TOKEN.decode() + "\r\n\n").encode()
    assert extract(data) == ExtractionResult(expected, "text", True, "")
    noisy = b"\xe9" + bytes(range(1, 32)) * 4  # many control bytes: binary, read as strings
    assert extract(noisy).format == "binary"


@pytest.mark.parametrize("prefix", [b"\xef\xbb\xbf", b"\r\n", b"\x00"])
def test_a_pdf_after_a_few_junk_bytes_is_read_as_a_pdf(prefix):
    result = extract(prefix + pdf())
    assert result.format == "pdf" and result.complete and MARKER in result.data


def test_text_that_only_mentions_the_pdf_header_stays_text():
    data = b"MAGIC = b'%PDF-'  # " + MARKER
    assert extract(data) == ExtractionResult(data, "text", True, "")
    # Even with "%%EOF" near its end, and inside an archive the next member is still read.
    fixture = b'SAMPLE = b"%PDF-1.4\\n1 0 obj<<>>endobj\\ntrailer<<>>\\n%%EOF"\n'
    assert extract(fixture) == ExtractionResult(fixture, "text", True, "")
    result = extract(zipped({"a_pdf_test.py": fixture, "z_settings.py": b"key = " + MARKER}))
    assert result.complete and MARKER in result.data


def test_text_before_a_pdf_is_never_dropped():
    # curl -i output: response headers, then the PDF. Only whitespace, a BOM or NUL bytes may
    # precede a PDF header; this stays strings of a binary that holds an unread PDF.
    headers = b"HTTP/1.1 200 OK\r\nSet-Cookie: session=" + GITHUB_TOKEN + b"\r\n\r\n"
    result = extract(headers + pdf())
    assert not result.complete and result.reason == "EMBEDDED_CONTENT" and GITHUB_TOKEN in result.data


def test_a_text_only_pdf_after_a_line_break_is_read_as_a_pdf():
    result = extract(b"\r\n" + ascii_pdf())
    assert result.format == "pdf" and result.complete and MARKER in result.data
    truncated = extract(b"\r\n" + ascii_pdf()[:ascii_pdf().rindex(b"%%EOF")])  # never complete text
    assert truncated.format == "pdf" and not truncated.complete


@pytest.mark.parametrize("embedded", [
    zipped({"config.txt": MARKER}), pdf(), gzip.compress(MARKER), bz2.compress(MARKER), lzma.compress(MARKER),
    b"7z\xbc\xaf\x27\x1c\x00\x04" + bytes(24), b"Rar!\x1a\x07\x01\x00" + bytes(24), b"\x28\xb5\x2f\xfd" + bytes(24),
], ids=["zip", "pdf", "gzip", "bzip2", "xz", "7z", "rar", "zstd"])
def test_containers_inside_binary_bytes_leave_the_strings_incomplete(embedded):
    # A self-extracting archive and the like: printable runs cannot reach compressed content.
    result = extract(pe() + embedded)
    assert result.format == "binary" and not result.complete and result.reason == "EMBEDDED_CONTENT"
    assert MARKER in result.data  # what the strings did read still counts


@pytest.mark.parametrize("data", [
    b"Salted__" + bytes(range(256)), b"\x00GITCRYPT\x00" + bytes(range(256)), pe() + b"Salted__" + bytes(range(256)),
], ids=["openssl", "git-crypt", "inside-binary"])
def test_encrypted_blobs_are_never_clean(data):
    result = extract(data)
    assert not result.complete and result.reason == "ENCRYPTED_DOCUMENT"


@pytest.mark.parametrize("data", [b"\x1f\x9d\x90" + bytes(range(256)), b"\x5d\x00\x00\x80\x00" + b"\xff" * 8,
                                  b"Rar!\x1a\x07\x00" + MARKER], ids=["compress", "lzma-alone", "rar"])
def test_unopened_compressed_streams_are_unsupported(data):
    assert extract(data) == ExtractionResult(reason="UNSUPPORTED_FORMAT")


@pytest.mark.parametrize("storage", [
    "_VBA_PROJECT_CUR/VBA/dir", "Macros/VBA/dir", "ObjectPool/_1234/CONTENTS", "MBD0049D1D3/CONTENTS",
    "__attach_version1.0_#00000000/__substg1.0_37010102",
])
def test_compound_files_with_macros_objects_or_attachments_are_incomplete(storage):
    result = extract(xls(extra={storage: b"opaque embedded bytes"}))
    assert result.format == "ole-strings" and not result.complete and result.reason == "EMBEDDED_CONTENT"
    assert MARKER in result.data


EXOLEOBJSTG = struct.pack("<HHI", 0x0010, 0x1011, 12) + struct.pack("<I", 64) + zlib.compress(b"")[:8]


@pytest.mark.parametrize("data", [
    compound({"䡀㼿䕷": b"Property ProductName " + MARKER,  # MSI: tables and a CAB
              "䡀㬿䏲": b"MSCF\x00\x00\x00\x00" + zlib.compress(b"config")}),
    compound({"VisioDocument": b"Visio (TM) Drawing " + MARKER + zlib.compress(b"shape text")}),
    compound({"__substg1.0_10090102": b"LZFu" + zlib.compress(b"{\\rtf1 body}"),  # MSG: compressed RTF
              "__substg1.0_0037001F": MARKER_TEXT.encode("utf-16-le")}),
    ppt(records=EXOLEOBJSTG),  # an embedded object or VBA project, compressed
    ppt(records=struct.pack("<HHI", 0x000F, 0x0409, len(EXOLEOBJSTG)) + EXOLEOBJSTG),  # inside a container
], ids=["msi", "visio", "msg", "ppt-object", "ppt-object-in-container"])
def test_compound_files_other_than_plain_workbooks_and_slides_are_incomplete(data):
    result = extract(data)
    assert result.format == "ole-strings" and not result.complete and result.reason == "EMBEDDED_CONTENT"
    assert MARKER in result.data


def test_hwp3_password_compression_and_signature_are_checked():
    assert extract(hwp3(encrypted=True)) == ExtractionResult(format="hwp3-strings", reason="ENCRYPTED_DOCUMENT")
    compressed = extract(hwp3(compressed=True))
    assert compressed.format == "hwp3-strings" and not compressed.complete
    assert compressed.reason == "EMBEDDED_CONTENT"
    text = b"HWP Document File format notes: " + MARKER  # no fixed signature tail: plain text
    assert extract(text) == ExtractionResult(text, "text", True, "")


def test_decoded_text_with_stray_control_bytes_is_read_whole():
    korean = "비밀번호: 한글값 " + MARKER_TEXT  # non-ASCII text and short values stay
    assert extract((korean + "\x1b[0m\npw=ab12\x00").encode()) == ExtractionResult(
        (korean + "\n[0m\npw=ab12\n").encode(), "text", True, "")
    utf32 = ("token " + MARKER_TEXT + "\x1b").encode("utf-32")
    assert extract(utf32) == ExtractionResult(("token " + MARKER_TEXT + "\n").encode(), "text", True, "")
    # UTF-16LE inside UTF-8 decodes one character per line, so its runs follow the text.
    mixed = b"header\x00\x01" + MARKER_TEXT.encode("utf-16-le")
    result = extract(mixed)
    assert result.complete and result.data.endswith(b"\n" + MARKER)
    # Exactly at the text limit those runs no longer fit: never complete.
    limited = extract(mixed, limits=replace(DEFAULT_LIMITS, text_bytes=len(mixed)))
    assert not limited.complete and limited.reason == "TEXT_LIMIT"


def test_a_gzip_marker_needs_its_whole_header():
    near_miss = pe() + b"\x1f\x8b\x08\xff" + bytes(12)  # reserved flag bits set: random bytes
    assert extract(near_miss).complete
    assert extract(pe() + gzip.compress(MARKER)).reason == "EMBEDDED_CONTENT"


@pytest.mark.parametrize("frame", [
    b'{"format": "pdf", "complete": 1, "reason": "", "size": 0}\n',
    b'{"format": "<b>pdf", "complete": true, "reason": "", "size": 0}\n',
    b'{"format": "pdf", "complete": false, "reason": "parser said no", "size": 0}\n',
    b'{"format": "pdf", "complete": true, "reason": "TEXT_LIMIT", "size": 0}\n',
    b'{"format": "pdf", "complete": false, "reason": "", "size": 0}\n',
])
def test_a_parser_frame_outside_the_fixed_vocabulary_is_a_parser_failure(frame):
    from cremore.scanning.extraction import _result

    assert _result(0, frame, DEFAULT_LIMITS, "pdf") == ExtractionResult(format="pdf", reason="PARSER_FAILURE")
    valid = b'{"format": "pdf", "complete": false, "reason": "PAGE_LIMIT", "size": 2}\nok'
    assert _result(0, valid, DEFAULT_LIMITS, "pdf") == ExtractionResult(b"ok", "pdf", False, "PAGE_LIMIT")


BMP_HEADER = b"BM" + struct.pack("<I", 70) + bytes(4) + struct.pack("<II", 54, 40)


@pytest.mark.parametrize("header", [
    b"\x00\x00\x00\x18ftypmp42", b"\x00\x00\x00\x14ftypqt  ", b"\x00\x00\x00\x18ftyp3gp4",
    b"\x00\x00\x00\x20ftypM4A ", b"\x00\x00\x00\x18ftypheic", b"\x00\x00\x00\x1cftypavif",
    b"ID3\x04\x00\x00\x00\x00\x00\x00", b"\xff\xfb\x90\x64", b"\xff\xf3\x48\xc4", b"\xff\xf2\x48\xc4",
    b"RIFF\x24\x08\x00\x00WAVEfmt ", b"RIFF\x24\x08\x00\x00AVI LIST", b"\x1a\x45\xdf\xa3\x9f\x42\x86\x81",
    b"OggS\x00\x02\x00\x00", b"fLaC\x00\x00\x00\x22", b"MThd\x00\x00\x00\x06\x00\x01",
    b"wOFF\x00\x01\x00\x00", b"wOF2\x00\x01\x00\x00", b"wOFFOTTO", b"wOF2true", b"OTTO\x00\x0a\x00\x80",
    b"8BPS\x00\x01\x00\x00", BMP_HEADER,
])
def test_audio_video_font_psd_and_bmp_signatures_are_media(header):
    assert extract(header + MARKER) == ExtractionResult(format="image", reason="MEDIA_FORMAT")


@pytest.mark.parametrize("prefix", [
    b"BMW config\n", b"ID3 tag notes\n", b"OTTO von Bismarck\n", b"8BPS rates\n", b"The ftyp box\n",
    b"OggS stream\n", b"fLaC notes\n", b"MThd chunk\n", b"RIFF notes\n", b"MZ-80 notes " * 8 + b"\n",
    b"wOFF notes\n", b"wOF2 fonts\n", b"Rar! archives\n",
])
def test_text_that_starts_like_a_signature_stays_text(prefix):
    assert extract(prefix + MARKER) == ExtractionResult(prefix + MARKER, "text", True, "")


def test_only_timeouts_and_unavailable_parsers_are_retryable():
    # Every other reason is deterministic for the same bytes and extraction digest.
    assert RETRYABLE_REASONS == frozenset({"PARSE_TIMEOUT", "PARSER_UNAVAILABLE"})
    assert EXTRACTOR_EPOCH == 4


def test_partial_archive_keeps_positive_detections_and_previous_exposures():
    repo, scan, cid = service()
    scan.run(source(MARKER + b"\n" + SECOND), source_connection_id=cid)
    data = zipped({"notes.txt": MARKER, "unread.png": b"\x89PNG\r\n\x1a\n"})
    result = scan.run(source(data, revision="v2"), source_connection_id=cid, reconcile_objects=True)
    assert result.detections == 1
    assert result.extraction_reasons == {"MEDIA_FORMAT": 1}
    assert all(e.status == "OPEN" for e in repo.exposures.values())
    # A rescan of the unchanged archive (from the cache where partials are cached) too.
    scan.run(source(data, revision="v2"), source_connection_id=cid, reconcile_objects=True)
    assert all(e.status == "OPEN" for e in repo.exposures.values())


@pytest.mark.parametrize("limits,data,reason", [
    (replace(DEFAULT_LIMITS, input_bytes=4), b"ordinary", "INPUT_LIMIT"),
    (replace(DEFAULT_LIMITS, text_bytes=10), MARKER, "TEXT_LIMIT"),
    (replace(DEFAULT_LIMITS, member_bytes=10), zipped({"notes.txt": MARKER}), "MEMBER_SIZE_LIMIT"),
    (replace(DEFAULT_LIMITS, expanded_bytes=10), zipped({"notes.txt": MARKER}), "EXPANSION_LIMIT"),
    (replace(DEFAULT_LIMITS, members=1), zipped({"one": b"a", "two": b"b"}), "MEMBER_LIMIT"),
    (replace(DEFAULT_LIMITS, depth=1), zipped({"nested": zipped({"nested": zipped({"notes.txt": MARKER})})}), "DEPTH_LIMIT"),
    (replace(DEFAULT_LIMITS, pages=1), pdf(pages=2), "PAGE_LIMIT"),
    (replace(DEFAULT_LIMITS, seconds=0.0001), pdf(), "PARSE_TIMEOUT"),
])
def test_extraction_limits_are_explicit(limits, data, reason):
    result = extract(data, limits=limits)
    assert not result.complete and result.reason == reason
    repo, scan, cid = service(limits=limits)
    result = scan.run(source(data), source_connection_id=cid, reconcile_objects=True)
    assert result.extraction_reasons == {reason: 1}
    if reason in RETRYABLE_REASONS:
        # Only an outcome another attempt can change is a failed, uncached read; the
        # service's handling of fixed limits is covered by its own cache tests.
        assert result.objects_failed == 1
        assert not ScanStore(repo).memory["cache"]


def test_xml_entity_document_is_rejected_without_fetching_or_emitting_entity():
    data = zipped({"word/document.xml": b'<!DOCTYPE x [<!ENTITY e "SYNTHETIC_DOCUMENT_A1B2C3D4">]><p>&e;</p>'})
    result = extract(data)
    assert result.reason == "MALFORMED_DOCUMENT" and not result.complete
    assert MARKER not in result.data


@pytest.mark.parametrize("data,reason", [
    (hwp(declared_sections=2), "MALFORMED_DOCUMENT"),
    (doc(declared_chars=1000), "MALFORMED_DOCUMENT"),
    (zipped({"word/document.xml": b"<p>ordinary</p>", "word/_rels/document.xml.rels":
             b'<Relationships><Relationship Target="missing.xml"/></Relationships>'}), "MISSING_PACKAGE_MEMBER"),
])
def test_declared_but_missing_document_content_is_incomplete(data, reason):
    result = extract(data)
    assert not result.complete and result.reason == reason


@pytest.mark.parametrize("destination", [b"header", b"footer", b"footnote", b"annotation"])
def test_rtf_secondary_stories_are_scanned(destination):
    result = extract(b"{\\rtf1 ordinary {\\" + destination + b" " + MARKER + b"}}")
    assert result.complete and MARKER in result.data


def test_rtf_unicode_surrogate_pairs_do_not_discard_other_text():
    result = extract(b"{\\rtf1 \\u-10179?\\u-8704? " + MARKER + b"}")
    assert result.complete and MARKER in result.data


def test_format_identity_is_content_based_across_renames():
    assert extract(MARKER, filename="misnamed.pdf") == extract(MARKER, filename="notes.txt")


def test_unchanged_document_cache_avoids_download_and_parser(monkeypatch):
    repo, scan, cid = service()
    first = source(pdf(), path="report.pdf")
    scan.run(first, source_connection_id=cid)
    import cremore.scanning.service as module

    def forbidden(*args, **kwargs):
        pytest.fail("unchanged complete document must not download or parse")

    monkeypatch.setattr(module, "extract", forbidden)
    result = scan.run(source(None, path="renamed.pdf", loader=forbidden), source_connection_id=cid)
    assert result.reused == result.detections == 1
    assert len(repo.exposures) == 2  # same blob, two stable source locations


def test_extractor_policy_invalidates_prior_detection_cache():
    _repo, scan, cid = service()
    scan.run(source(MARKER), source_connection_id=cid)
    prior = cache_digest(scan.orchestrator.engine.detection_digest)
    limits = replace(DEFAULT_LIMITS, text_bytes=DEFAULT_LIMITS.text_bytes - 1)
    assert cache_digest(scan.orchestrator.engine.detection_digest, limits=limits) != prior
    changed = ScanService(scan.orchestrator, extraction_limits=limits)
    calls = []
    result = changed.run(source(None, loader=lambda: calls.append(1) or MARKER), source_connection_id=cid)
    assert calls == [1] and result.reused == 0


def test_extractor_update_invalidates_root_policy(monkeypatch):
    from cremore.scanning import extraction

    _repo, scan, _cid = service()
    before, fingerprints = scan.orchestrator.detection_policy_digest, scan.orchestrator.coverage_policy_digest
    monkeypatch.setattr(extraction, "EXTRACTOR_EPOCH", extraction.EXTRACTOR_EPOCH + 1)
    assert before != scan.orchestrator.detection_policy_digest
    # What is found changes, not how a found value is fingerprinted: vault comparisons and the customer-side
    # collector's contract keep matching (cremore.coverage.models.Contract's default is the same policy).
    from cremore.coverage.models import Contract

    assert scan.orchestrator.coverage_policy_digest == fingerprints
    plain = Orchestrator(InMemoryRepository(), engine=scan.orchestrator.engine)  # no operator rules
    assert Contract(engine_digest=plain.engine.detection_digest).policy_digest == plain.coverage_policy_digest


def test_document_process_does_not_inherit_secrets_or_extra_handles(monkeypatch):
    from cremore.scanning import extraction

    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "synthetic-environment-value")
    monkeypatch.setenv("DATABASE_URL", "synthetic-database-address")
    extraction._SERVER.stop()  # POSIX: the next document starts a fresh parser server
    original = extraction.subprocess.Popen
    settings = []

    def start(*args, **kwargs):
        settings.append(kwargs)
        return original(*args, **kwargs)

    monkeypatch.setattr(extraction.subprocess, "Popen", start)
    assert extract(pdf()).complete
    # Windows keeps its system directory variables; the POSIX server only gets a malloc setting.
    assert settings and set(settings[0]["env"]) <= {"SystemRoot", "WINDIR", "MALLOC_MMAP_THRESHOLD_"}
    assert "synthetic" not in repr(settings[0]["env"])
    assert settings[0]["close_fds"] is True


def test_parser_progress_and_cancellation_are_outside_fenced_write(monkeypatch):
    repo, scan, cid = service()
    writes = []
    progress_calls = []

    @contextmanager
    def boundary():
        writes.append(True)
        try:
            yield repo
        finally:
            writes.pop()

    def progress():
        assert not writes
        progress_calls.append(True)

    result = scan.run(source(pdf()), source_connection_id=cid, progress=progress, write_context=boundary)
    assert result.detections == 1 and len(progress_calls) >= 3

    import cremore.scanning.extraction as module

    class Cancelled(Exception):
        pass

    # Spawn-per-document mechanics; extraction_server_test.py covers the POSIX server.
    monkeypatch.setattr(module, "_FORK_SERVER", False)
    calls = []
    original = module.subprocess.Popen

    def capture(*args, **kwargs):
        process = original(*args, **kwargs)
        calls.append(process)
        return process

    monkeypatch.setattr(module.subprocess, "Popen", capture)
    counter = 0

    def cancel():
        nonlocal counter
        counter += 1
        if counter > 1:
            raise Cancelled

    # A deliberately delayed synthetic parser wrapper gives cancellation a
    # deterministic window, without an expensive or malicious document fixture.
    original_communicate = original.communicate

    def delayed(process, *args, **kwargs):
        if kwargs.get("timeout") is not None:
            raise module.subprocess.TimeoutExpired(process.args, 0.2)
        return original_communicate(process, *args, **kwargs)

    monkeypatch.setattr(original, "communicate", delayed)
    with pytest.raises(Cancelled):
        extract(pdf(), progress=cancel)
    assert calls and calls[0].poll() is not None


def test_tar_and_gzip_nested_text_and_special_members_are_bounded():
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as archive:
        entry = tarfile.TarInfo("notes.txt")
        entry.size = len(MARKER)
        archive.addfile(entry, io.BytesIO(MARKER))
    result = extract(gzip.compress(out.getvalue()), filename="bundle.tgz")
    assert result.complete and MARKER in result.data


def test_synthetic_document_cache_measurement():
    _repo, scan, cid = service()
    data = pdf()
    reads = []
    started = time.perf_counter()
    first = scan.run(source(None, path="report.pdf", loader=lambda: reads.append(len(data)) or data), source_connection_id=cid)
    cold = time.perf_counter() - started
    started = time.perf_counter()
    warm = scan.run(source(None, path="report.pdf", loader=lambda: reads.append(len(data)) or data), source_connection_id=cid)
    elapsed = time.perf_counter() - started
    assert first.detections == warm.detections == 1
    assert len(reads) == 1 and warm.reused == 1
    print(json.dumps({"synthetic_only": True, "cold_seconds": round(cold, 6),
                      "cached_seconds": round(elapsed, 6), "cold_download_bytes": reads[0],
                      "cached_download_bytes": 0, "cached_parser_calls": 0}))
