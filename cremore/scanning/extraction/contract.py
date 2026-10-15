"""Private, RAM-only document extraction contract (no provider or DB imports)."""

import math
import re
from dataclasses import dataclass

EXTRACTOR_EPOCH = 4

# A later attempt on the same bytes can end differently only when the parser ran out of
# time or could not run. Every other reason is deterministic for (object bytes, extraction
# cache digest): repeating the read cannot inspect more.
RETRYABLE_REASONS = frozenset({"PARSE_TIMEOUT", "PARSER_UNAVAILABLE"})


def public_reasons(value):
    """Only bounded machine reason counts leave coverage, never parser output."""
    if not isinstance(value, dict):
        return {}
    return {key: count for key, count in list(value.items())[:64]
            if isinstance(key, str) and re.fullmatch(r"[A-Z][A-Z_]{0,63}", key)
            and type(count) is int and 0 < count <= 2**53 - 1}


@dataclass(frozen=True)
class ExtractionLimits:
    input_bytes: int = 50 * 1024 * 1024
    expanded_bytes: int = 64 * 1024 * 1024
    member_bytes: int = 16 * 1024 * 1024
    text_bytes: int = 16 * 1024 * 1024
    members: int = 512
    pages: int = 500
    depth: int = 3
    seconds: float = 15.0
    memory_bytes: int = 512 * 1024 * 1024

    def __post_init__(self):
        if any(not math.isfinite(value) or value <= 0 for value in vars(self).values()):
            raise ValueError("extraction limits must be positive")


DEFAULT_LIMITS = ExtractionLimits()


@dataclass(frozen=True)
class ExtractionResult:
    # Private scanner input, never serialized into findings, jobs or API output.
    data: bytes = b""
    format: str = "unknown"
    complete: bool = False
    reason: str = "UNSUPPORTED_FORMAT"


# Images, audio, video, fonts and PSD: no text to inspect without OCR or decoding.
# Short ASCII signatures include their next structural bytes, so text that merely starts
# with "ID3", "OTTO", "wOFF" or "8BPS" stays text.
MEDIA_MAGIC = (
    b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a",
    b"II*\x00", b"MM\x00*", b"\x00\x00\x01\x00",
    b"ID3\x02", b"ID3\x03", b"ID3\x04", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2",  # MP3
    b"\x1a\x45\xdf\xa3", b"OggS\x00", b"fLaC\x00", b"fLaC\x80",  # MKV/WebM, Ogg, FLAC
    b"MThd\x00\x00\x00\x06", b"OTTO\x00", b"8BPS\x00\x01", b"8BPS\x00\x02",  # MIDI, OTF, PSD
    *(woff + flavor for woff in (b"wOFF", b"wOF2")  # WOFF/WOFF2 and their font flavour
      for flavor in (b"\x00\x01\x00\x00", b"OTTO", b"true")),
)
# Executables, Java classes and SQLite databases are read as printable strings.
BINARY_MAGIC = (
    b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf", b"SQLite format 3\x00",
)
# 7z, RAR, zstd, LZ4, Unix compress (.Z) and LZMA-alone streams: containers this reader
# does not open.
UNSUPPORTED_MAGIC = (b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07", b"\x28\xb5\x2f\xfd",
                     b"\x04\x22\x4d\x18", b"\x1f\x9d", b"\x5d\x00\x00")
HWP3_MAGIC = (b"HWP Document File", b"\x1a\x01\x02\x03\x04\x05")  # bytes 0-17 and 24-30
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
DOCUMENT_SUFFIXES = frozenset({
    ".pdf", ".doc", ".docx", ".docm", ".dotx", ".dotm", ".pptx", ".pptm",
    ".xlsx", ".xlsm", ".odt", ".ods", ".odp", ".hwp", ".hwpx", ".rtf",
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar",
    ".xls", ".ppt", ".epub",
})


PLAIN_KINDS = frozenset({"text", "binary", "hwp3"})  # read in-process, no parser library
_CONTROL = r"[\x00-\x07\x0b\x0e-\x1f]"
_TEXT_CONTROL = re.compile(_CONTROL)
_BYTE_CONTROL = re.compile(_CONTROL.encode("ascii"))
# strings() classifies every byte once (printable ASCII or tab -> 1, NUL -> 2, other -> 0)
# and finds runs in that copy with C-speed searches: several times faster than a regex
# over large binaries, with the same runs.
_BYTE_CLASSES = bytes(1 if b == 9 or 32 <= b <= 126 else 2 if b == 0 else 0 for b in range(256))
_ASCII_RUNS = (b"\x01" * 8, re.compile(rb"\x01+"), 1)
_UTF16_RUNS = (b"\x01\x02" * 8, re.compile(rb"(?:\x01\x02)+"), 2)  # keeps the low bytes
_HIGH_BYTES = bytes(range(128, 256))
_CONTROL_LINES = bytes(10 if b < 8 or b == 11 or 14 <= b < 32 else b for b in range(256))
# Content printable runs cannot reach. Found anywhere in binary bytes (a self-extracting
# archive, an embedded PDF, an encrypted blob), they leave the strings incomplete instead of
# certifying that content clean.
_ENCRYPTED_SIGNATURES = re.compile(rb"Salted__|\x00GITCRYPT\x00")
# A gzip member needs its whole 10-byte header (reserved flag bits clear, a known XFL and OS
# byte); its 3-byte magic alone turns up in random data about once per 16 MiB.
_EMBEDDED_SIGNATURES = re.compile(rb"PK\x03\x04|%PDF-|\x1f\x8b\x08[\x00-\x1f][\x00-\xff]{4}[\x00\x02\x04]"
                                  rb"[\x00-\x0d\xff]|7z\xbc\xaf\x27\x1c|Rar!\x1a\x07|BZh[1-9]1AY&SY"
                                  rb"|\xfd7zXZ\x00|\x28\xb5\x2f\xfd")
_CONTROL_BYTES = bytes(b for b in range(32) if b not in (8, 9, 10, 12, 13))


def media(data: bytes) -> bool:
    if data.startswith(MEDIA_MAGIC):
        return True
    if data.startswith(b"RIFF") and data[8:12] in (b"WEBP", b"WAVE", b"AVI "):
        return True
    # ISO BMFF (MP4, MOV, 3GP, M4A, HEIC, AVIF): a small big-endian box size, then "ftyp".
    if data[4:8] == b"ftyp" and data[:2] == b"\x00\x00":
        return True
    # A BMP needs its file header, not just "BM": text such as "BMW config" stays text.
    return (len(data) >= 18 and data.startswith(b"BM") and data[6:10] == b"\x00\x00\x00\x00"
            and int.from_bytes(data[14:18], "little") in (12, 40, 52, 56, 64, 108, 124))


def _portable_executable(data: bytes) -> bool:
    # "MZ" also starts ordinary text; a PE file points at its "PE\0\0" header from offset 60.
    if not data.startswith(b"MZ") or len(data) < 64:
        return False
    offset = int.from_bytes(data[60:64], "little")
    return data[offset:offset + 4] == b"PE\x00\x00"


def pdf_offset(data: bytes) -> int:
    """Where a PDF header starts, or -1.

    PDF readers accept a BOM, whitespace or NUL bytes before the header within the first 1024
    bytes. Anything else in front (text that mentions "%PDF-", HTTP headers saved with the
    file) is content the PDF reader would drop, so such bytes are not a PDF.
    """
    start = data.find(b"%PDF-", 0, 1024)
    if start > 0 and data[:start].removeprefix(b"\xef\xbb\xbf").strip(b"\x00 \t\r\n\x0b\x0c"):
        return -1
    return start


def kind(data: bytes, suffix: str = "") -> str:
    if media(data):
        return "image"  # every media kind; consumers count these as skipped media
    if data.startswith(b"%PDF-"):
        return "pdf"
    if data.startswith(ZIP_MAGIC):
        return "zip"
    if data.startswith(OLE_MAGIC):
        return "ole"
    if data.lstrip().startswith(b"{\\rtf"):
        return "rtf"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if data.startswith(b"BZh"):
        return "bzip2"
    if data.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if len(data) > 262 and data[257:262] == b"ustar":
        return "tar"
    if data.startswith(HWP3_MAGIC[0]) and data[24:30] == HWP3_MAGIC[1]:
        return "hwp3"  # HWP 5 is an OLE file; this signature at offset 0 is HWP 3 or older
    if data.startswith(BINARY_MAGIC) or _portable_executable(data):
        return "binary"
    if data.startswith(UNSUPPORTED_MAGIC):
        return "unsupported"
    # Only after every container that starts at offset 0: a stored PDF inside a ZIP is no PDF.
    if pdf_offset(data) > 0:
        return "pdf"
    # Filename/MIME labels never change interpretation: content-addressed cache
    # hits remain valid after a rename. Recognizable text stays text even if an
    # application gave it an Office extension (for example HTML saved as .doc).
    return "text"


def _runs(data: bytes, *kinds):
    classes = data.translate(_BYTE_CLASSES)
    for first, rest, step in kinds:
        position = 0
        while (start := classes.find(first, position)) >= 0:
            position = rest.match(classes, start).end()
            yield data[start:position:step]


def _joined(runs, limit: int) -> bytes:
    """Runs joined by newlines, stopping once past `limit` (the caller reports TEXT_LIMIT)."""
    output = bytearray()
    for run in runs:
        if output:
            output += b"\n"
        output += run
        if len(output) > limit:
            break
    return bytes(output)


def strings(data: bytes, limit: int, label: str = "binary") -> ExtractionResult:
    """Printable runs of non-text bytes, like strings(1): ASCII, then UTF-16LE.

    Runs of at least 8 characters (tab included) are joined by newlines. Compressed or
    otherwise encoded regions are not decoded: bytes that show an archive, a PDF or
    encryption leave the result incomplete.
    """
    gap = _unreadable(data)
    output = _joined(_runs(data, _ASCII_RUNS, _UTF16_RUNS), limit)
    if len(output) > limit:
        return ExtractionResult(output[:limit], label, False, gap or "TEXT_LIMIT")
    return ExtractionResult(output, label, not gap, gap)


def _unreadable(data: bytes) -> str:
    """The reason bytes read as strings or legacy text cannot be certified, or ""."""
    if _ENCRYPTED_SIGNATURES.search(data):
        return "ENCRYPTED_DOCUMENT"
    return "EMBEDDED_CONTENT" if _EMBEDDED_SIGNATURES.search(data) else ""


def text_content(data: bytes, limit: int) -> ExtractionResult:
    """Strict decoding; bytes that do not decode as text (NUL, many control bytes) become strings."""
    bom = data.startswith((b"\xff\xfe", b"\xfe\xff", b"\x00\x00\xfe\xff"))
    try:
        if data.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
            text = data.decode("utf-32")
        elif bom:
            text = data.decode("utf-16")
        else:
            text = data.decode("utf-8-sig")
    except UnicodeError:
        # Legacy text has no NUL and few control bytes (a DOS Ctrl-Z at the end, terminal
        # colours); anything else that does not decode is binary. Binary content inside legacy
        # text (a PDF after saved HTTP headers) still leaves it incomplete.
        if (b"\x00" in data
                or 16 * (len(data) - len(data.translate(None, _CONTROL_BYTES))) > len(data)):
            return strings(data, limit)
        output, gap = _legacy_text(data), _unreadable(data)
    else:
        output, gap = text.encode("utf-8"), ""
        del text
    if _BYTE_CONTROL.search(output):  # UTF-8 keeps every control character one byte
        # Text with stray control characters is read whole, the controls as line breaks.
        # UTF-16LE text inside UTF-8 decodes one character per line, so its runs are added;
        # a UTF-16/32 decode already is that text.
        output = output.translate(_CONTROL_LINES)
        if (not bom and b"\x00" in data and len(output) <= limit
                and (runs := _joined(_runs(data, _UTF16_RUNS), limit - len(output) - 1))):
            output += b"\n" + runs
    return ExtractionResult(output, "text", not gap, gap)


def _legacy_text(data: bytes) -> bytes:
    """Non-UTF text as UTF-8: CP949 (Korean, EUC-KR), else latin-1, which never fails."""
    try:
        korean = data.decode("cp949")
    except UnicodeError:
        return data.decode("latin-1").encode("utf-8")
    # A CP949 trail byte can be an ASCII letter. Korean with extension syllables uses that,
    # but so does a stray cp1252 byte that swallows the letter after it ("\xa0ghp_..." ->
    # "쟥hp_..."). When an ASCII byte went missing, the latin-1 reading follows as well.
    if korean.encode("ascii", "ignore") == data.translate(None, _HIGH_BYTES):
        return korean.encode("utf-8")
    return korean.encode("utf-8") + b"\n" + data.decode("latin-1").encode("utf-8")


def _hwp3(data: bytes, limit: int) -> ExtractionResult:
    # The document information block after the 30-byte signature (LibreOffice hwpfilter
    # HWPInfo::Read): a nonzero word at offset 126 means a password, byte 154 a compressed body.
    if len(data) < 158:
        return ExtractionResult(format="hwp3-strings", reason="MALFORMED_DOCUMENT")
    if data[126:128] != b"\x00\x00":
        return ExtractionResult(format="hwp3-strings", reason="ENCRYPTED_DOCUMENT")
    result = strings(data, limit, "hwp3-strings")
    if data[154] and result.complete:
        return ExtractionResult(result.data, result.format, False, "EMBEDDED_CONTENT")
    return result


def plain_content(data: bytes, file_kind: str, limit: int) -> ExtractionResult:
    """PLAIN_KINDS: decoded text, or printable strings of binary bytes."""
    if file_kind == "text":
        return text_content(data, limit)
    if file_kind == "hwp3":
        return _hwp3(data, limit)
    return strings(data, limit)
