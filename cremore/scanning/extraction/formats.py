"""Document readers for the isolated worker; all streams stay in memory.

Container readers enforce one aggregate budget across nested documents. See
docs/DOCUMENT_SCANNING.md for format specifications and the supported subsets.
"""

from __future__ import annotations

import bz2
import io
import lzma
import posixpath
import re
import struct
import tarfile
import zipfile
import zlib
from pathlib import PurePosixPath
from urllib.parse import unquote, urlsplit

if __package__:
    from .contract import PLAIN_KINDS, ExtractionResult, kind, pdf_offset, plain_content, strings
else:  # Fixed worker.py/server.py script, normal sibling import (no sys.path mutation).
    from contract import PLAIN_KINDS, ExtractionResult, kind, pdf_offset, plain_content, strings

# Compound-file storages holding macros, embedded objects or mail attachments, which the
# printable strings of the raw file cannot read.
OLE_EMBEDDED = frozenset({"_VBA_PROJECT_CUR", "_VBA_PROJECT", "Macros", "VBA", "ObjectPool"})


class LimitReached(Exception):
    pass


class InvalidDocument(Exception):
    pass


# BIFF8 record types (MS-XLS): the shared string table, the record that carries on any record
# longer than 8224 bytes, a comment or text box's text (TxO) and a formula's string result.
_SST, _CONTINUE, _TXO, _STRING = 0x00FC, 0x003C, 0x01B6, 0x0207


def shared_strings(stream):
    """A BIFF8 workbook stream's texts rejoined, and the stream with them zeroed.

    The shared string table (SST, MS-XLS 2.4.265) holds every distinct cell text. Past 8224
    bytes it goes on in CONTINUE records, and a string cut there goes on after a one-byte
    flag giving the width of its remaining characters (MS-XLS 2.5.293, as xlrd reads it):
    read as raw bytes, that record header and flag split the string's printable run in two.
    A comment or text box (TxO, 2.4.329) and a formula's string result (String, 2.4.268) go
    on the same way, so their texts are rejoined too (``_continued``).
    Returns (8-bit strings joined by newlines, strings with UTF-16 characters as UTF-16LE
    joined by UTF-16 newlines, the stream with the bytes that were read zeroed, whether bytes
    were left that should have been decoded), all for printable-run reading; or None when the
    table does not parse. A stream without any of them comes back unchanged.
    """
    narrow, wide, rest, left = bytearray(), bytearray(), bytearray(stream), False
    position, end = 0, len(stream)
    while position + 4 <= end:
        record, size = struct.unpack_from("<HH", stream, position)
        if record == _SST:
            break
        position += 4 + size
    else:
        position = None
    if position is not None:
        start, segments, offsets = position, [], []
        while position + 4 <= end:
            record, size = struct.unpack_from("<HH", stream, position)
            if segments and record != _CONTINUE:
                break
            segments.append(stream[position + 4:position + 4 + size])
            offsets.append(position + 4)
            position += 4 + size
        try:
            index, stop = _table(segments, narrow, wide)
        except (IndexError, ValueError, struct.error):
            return None
        # Bytes after the declared strings were not decoded: they stay for the raw reading, where
        # a string cut by a CONTINUE record would still split, so the table is not certified.
        read = min(offsets[index] + stop, end)
        rest[start:read] = bytes(read - start)
        left = read < min(position, end)
    if not _continued(stream, rest, narrow, wide):
        left = True
    return narrow, wide, rest, left


def _continued(stream, rest, narrow, wide):
    """Appends each TxO text and String result to `narrow` or `wide` and zeroes its bytes in `rest`. A text
    starts in the String record itself (after its character count and width flag) or in the CONTINUE record
    after a TxO (whose character count is at offset 10), and goes on in CONTINUE records that each start
    with a width flag. False when one does not parse: its bytes stay for the raw reading."""
    records, position, end = [], 0, len(stream)
    while position + 4 <= end:
        record, size = struct.unpack_from("<HH", stream, position)
        records.append((record, position + 4, min(position + 4 + size, end)))
        position += 4 + size
    parsed = True
    for index, (record, start, stop) in enumerate(records):
        if record not in (_TXO, _STRING):
            continue
        try:
            if record == _TXO:
                count, pieces, following = struct.unpack_from("<H", stream, start + 10)[0], [], index + 1
            else:
                count, flag = struct.unpack_from("<HB", stream, start)
                pieces, following = [(flag & 0x01, start, start + 3, stop)], index + 1
            parts, cleared = [], []
            for is_wide, cut, first, last in pieces:
                take = min(count, (last - first) // (2 if is_wide else 1))
                parts.append((is_wide, stream[first:first + take * (2 if is_wide else 1)]))
                cleared.append((cut, first + take * (2 if is_wide else 1)))
                count -= take
            while count:
                kind, first, last = records[following]  # IndexError: the stream ends inside the text
                if kind != _CONTINUE or first >= last:
                    raise ValueError
                is_wide, width = stream[first] & 0x01, 2 if stream[first] & 0x01 else 1
                take = min(count, (last - first - 1) // width)
                if not take:
                    raise ValueError
                parts.append((is_wide, stream[first + 1:first + 1 + take * width]))
                cleared.append((first, first + 1 + take * width))
                count, following = count - take, following + 1
        except (IndexError, ValueError, struct.error):
            parsed = False
            continue
        if not any(raw for _part_wide, raw in parts):
            continue
        if any(part_wide for part_wide, _raw in parts):
            for part_wide, raw in parts:
                wide += raw if part_wide else raw.decode("latin-1").encode("utf-16-le")
            wide += b"\n\x00"
        else:
            for _part_wide, raw in parts:
                narrow += raw
            narrow += b"\n"
        for begin, finish in cleared:
            rest[begin:finish] = bytes(finish - begin)
    return parsed


def _table(segments, narrow, wide):
    """Appends each shared string to `narrow` or `wide`; returns the segment and offset where
    reading stopped."""
    if len(segments[0]) < 8:
        raise ValueError
    unique = struct.unpack_from("<I", segments[0], 4)[0]
    index, data, position = 0, segments[0], 8
    for walked in range(unique):
        # Excel keeps one copy of each string, so a real table holds at most ~131K strings under
        # six bytes; a table walking far more of them is crafted duplicates, and decoding it
        # would only spend the parse time limit.
        if walked & 0xFFFF == 0xFFFF and 6 * walked - sum(map(len, segments[:index])) - position > 400_000:
            raise ValueError
        if position >= len(data):
            if index + 1 == len(segments):
                break  # fewer strings than declared, and every byte was read
            index, position = index + 1, 0
            data = segments[index]
        count, flags = struct.unpack_from("<HB", data, position)
        position += 3
        runs = phonetic = 0
        if flags & 0x08:
            runs = struct.unpack_from("<H", data, position)[0]
            position += 2
        if flags & 0x04:
            phonetic = struct.unpack_from("<I", data, position)[0]
            position += 4
        is_wide, parts = flags & 0x01, []
        while True:
            width = 2 if is_wide else 1
            take = min(count, (len(data) - position) // width)
            parts.append((is_wide, data[position:position + take * width]))
            position, count = position + take * width, count - take
            if not count:
                break
            if position != len(data):  # half a character before the cut
                raise ValueError
            index += 1
            data = segments[index]
            is_wide, position = data[0] & 0x01, 1
        if any(part_wide for part_wide, _raw in parts):
            for part_wide, raw in parts:
                wide += raw if part_wide else raw.decode("latin-1").encode("utf-16-le")
            wide += b"\n\x00"
        else:
            for _part_wide, raw in parts:
                narrow += raw
            narrow += b"\n"
        # Formatting runs and phonetic data go on across a cut without a flag byte.
        skip = 4 * runs + phonetic
        while skip > len(data) - position:
            skip -= len(data) - position
            index, position = index + 1, 0
            data = segments[index]
        position += skip
    return index, position


class Reader:
    def __init__(self, limits):
        self.limits = limits
        self.output = bytearray()
        self.expanded = 0
        self.members = 0
        self.pages = 0
        self.reason = ""
        self.format = "unknown"

    def partial(self, reason):
        if not self.reason:
            self.reason = reason

    def stop(self, reason):
        self.partial(reason)
        raise LimitReached

    def text(self, value):
        raw = value.encode("utf-8") if isinstance(value, str) else value
        remaining = self.limits.text_bytes - len(self.output)
        if len(raw) > remaining:
            self.output.extend(raw[:remaining])
            self.stop("TEXT_LIMIT")
        self.output.extend(raw)

    def member(self, size):
        self.members += 1
        if self.members > self.limits.members:
            self.stop("MEMBER_LIMIT")
        if size < 0 or size > self.limits.member_bytes:
            self.stop("MEMBER_SIZE_LIMIT")
        self.expanded += size
        if self.expanded > self.limits.expanded_bytes:
            self.stop("EXPANSION_LIMIT")

    def page(self):
        self.pages += 1
        if self.pages > self.limits.pages:
            self.stop("PAGE_LIMIT")

    def read(self, data, suffix="", depth=0):
        if depth > self.limits.depth:
            self.stop("DEPTH_LIMIT")
        file_kind = kind(data, suffix)
        if depth == 0:
            self.format = file_kind
        if file_kind in PLAIN_KINDS:
            self.plain(plain_content(data, file_kind, self.limits.text_bytes))
        elif file_kind == "pdf":
            self.pdf(data)
        elif file_kind == "zip":
            self.zip(data, depth)
        elif file_kind == "ole":
            self.ole(data, depth)
        elif file_kind == "rtf":
            self.rtf(data)
        elif file_kind in ("gzip", "bzip2", "xz"):
            raw = self.inflate(data, file_kind)
            self.read(raw, ".tar" if suffix == ".tgz" else "", depth + 1)
        elif file_kind == "tar":
            self.tar(data, depth)
        else:
            self.partial("MEDIA_FORMAT" if file_kind == "image" else "UNSUPPORTED_FORMAT")
        self.text("\n")

    def plain(self, result):
        if not result.complete:
            self.partial(result.reason)
        self.text(result.data)

    def inflate(self, data, encoding):
        cap = min(self.limits.member_bytes, self.limits.expanded_bytes - self.expanded)
        if cap <= 0:
            self.stop("EXPANSION_LIMIT")
        if encoding in ("deflate", "gzip"):
            decoder = zlib.decompressobj(-15 if encoding == "deflate" else 31)
        elif encoding == "bzip2":
            decoder = bz2.BZ2Decompressor()
        else:
            decoder = lzma.LZMADecompressor(memlimit=self.limits.memory_bytes // 4)
        result = decoder.decompress(data, max_length=cap + 1)
        if len(result) > cap or not decoder.eof:
            self.stop("EXPANSION_LIMIT")
        # Concatenated compressed streams are not silently treated as one clean
        # first stream. Scanning the first stream still supplies positive proof.
        if decoder.unused_data:
            self.partial("TRAILING_COMPRESSED_DATA")
        self.member(len(result))
        return result

    def xml(self, data):
        from defusedxml.ElementTree import fromstring

        root = fromstring(data, forbid_dtd=True, forbid_entities=True, forbid_external=True)
        # Iterative traversal preserves adjacent Word/HWP runs and avoids Python
        # recursion for deeply nested XML. Only structural boundaries add lines.
        boundaries = {"p", "br", "tr", "row", "c", "si", "table-row", "table-cell"}
        stack = [(root, False)]
        while stack:
            node, closing = stack.pop()
            local = node.tag.rsplit("}", 1)[-1]
            if closing:
                if local in boundaries:
                    self.text("\n")
                if node.tail:
                    self.text(node.tail)
                continue
            # Hyperlink/alt-text attributes can contain secrets too. They are
            # inspected as text and are never fetched or persisted as metadata.
            for key, value in node.attrib.items():
                if key.rsplit("}", 1)[-1] in {"href", "Target", "descr", "title"}:
                    self.text("\n" + value + "\n")
            if node.text:
                self.text(node.text)
            stack.append((node, True))
            stack.extend((child, False) for child in reversed(node))
        return root

    def zip(self, data, depth):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > self.limits.members - self.members:
                self.stop("MEMBER_LIMIT")
            names = {info.filename for info in entries}
            if len(names) != len(entries):
                self.partial("DUPLICATE_MEMBERS")
            document = None
            if "word/document.xml" in names:
                document = "docx"
            elif "ppt/presentation.xml" in names:
                document = "pptx"
            elif "xl/workbook.xml" in names:
                document = "xlsx"
            elif "Contents/content.hpf" in names or "Contents/section0.xml" in names:
                document = "hwpx"
            elif "content.xml" in names and "META-INF/manifest.xml" in names:
                document = "odf"
            elif "[Content_Types].xml" in names:
                document = "ooxml"
                self.partial("MISSING_DOCUMENT_BODY")
            if depth == 0 and document:
                self.format = document
            for info in entries:
                if info.is_dir():
                    self.member(0)
                    continue
                self.member(info.file_size)
                if info.flag_bits & 1:
                    self.partial("ENCRYPTED_DOCUMENT")
                    continue
                mode = info.external_attr >> 16
                if mode & 0o170000 == 0o120000:
                    self.partial("ARCHIVE_SPECIAL_MEMBER")
                    continue
                name = info.filename.replace("\\", "/")
                if name.startswith("/") or ".." in PurePosixPath(name).parts:
                    self.partial("ARCHIVE_SPECIAL_MEMBER")
                    continue
                with archive.open(info) as stream:
                    raw = stream.read(min(self.limits.member_bytes, info.file_size) + 1)
                if len(raw) != info.file_size:
                    raise InvalidDocument
                lower = name.lower()
                if document and lower.endswith((".xml", ".rels", ".hpf")):
                    # ODF manifest encryption is metadata, not readable content.
                    if b"encryption-data" in raw:
                        self.partial("ENCRYPTED_DOCUMENT")
                    root = self.xml(raw)
                    if lower.endswith(".rels"):
                        self.relationships(root, name, names)
                    self.text("\n")
                elif document:
                    if lower == "mimetype" or lower.startswith(("docprops/thumbnail", "preview/", "thumbnails/")):
                        continue  # redundant previews, not document body
                    if lower.endswith((".bin", ".odttf", ".ttf", ".woff", ".dat")):
                        self.partial("EMBEDDED_CONTENT")
                    else:
                        self.read(raw, PurePosixPath(name).suffix.lower(), depth + 1)
                else:
                    self.read(raw, PurePosixPath(name).suffix.lower(), depth + 1)

    def relationships(self, root, name, names):
        # OPC relationship files declare required internal package parts. A
        # missing part is incomplete, even if the remaining XML is well formed.
        base = posixpath.dirname(posixpath.dirname(name))
        for relation in root:
            target = relation.get("Target", "")
            if relation.get("TargetMode") == "External" or not target:
                continue
            target = unquote(urlsplit(target).path)
            target = posixpath.normpath(posixpath.join(base, target)).lstrip("/")
            if target not in names:
                self.partial("MISSING_PACKAGE_MEMBER")

    def tar(self, data, depth):
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            for entry in archive:
                self.member(entry.size)
                if entry.isdir():
                    continue
                if not entry.isfile():
                    self.partial("ARCHIVE_SPECIAL_MEMBER")
                    continue
                name = entry.name.replace("\\", "/")
                if name.startswith("/") or ".." in PurePosixPath(name).parts:
                    self.partial("ARCHIVE_SPECIAL_MEMBER")
                    continue
                stream = archive.extractfile(entry)
                if stream is None:
                    raise InvalidDocument
                with stream:
                    raw = stream.read(entry.size + 1)
                if len(raw) != entry.size:
                    raise InvalidDocument
                self.read(raw, PurePosixPath(name).suffix.lower(), depth + 1)

    def pdf(self, data):
        from pypdf import PdfReader

        # Offsets inside a PDF count from its header, after any junk bytes before it.
        start = pdf_offset(data)
        reader = PdfReader(io.BytesIO(data[start:] if start > 0 else data), strict=True)
        if reader.is_encrypted:
            self.partial("ENCRYPTED_DOCUMENT")
            return
        root = reader.trailer["/Root"]
        names = root.get("/Names", {})
        names = names.get_object() if hasattr(names, "get_object") else names
        if names.get("/EmbeddedFiles") or root.get("/AF"):
            self.partial("EMBEDDED_CONTENT")
        for page in reader.pages:
            self.page()
            # get_data is itself a parser operation: process memory/time caps
            # apply while decompressing, before the aggregate size is known.
            content = page.get_contents()
            if content is not None:
                self.member(len(content.get_data()))
            text = page.extract_text() or ""
            if not text.strip():
                self.partial("NO_EXTRACTABLE_TEXT")
            # This examines resource dictionaries, never decodes image pixels.
            resources = page.get("/Resources", {})
            resources = resources.get_object() if hasattr(resources, "get_object") else resources
            if resources.get("/XObject"):
                self.partial("PDF_GRAPHICS_CONTENT")
            self.text(text)
            self.text("\n")
            for annotation in page.get("/Annots", []):
                annotation = annotation.get_object()
                for key in ("/Contents", "/T", "/V"):
                    value = annotation.get(key)
                    if isinstance(value, str):
                        self.text(value + "\n")
                action = annotation.get("/A")
                action = action.get_object() if hasattr(action, "get_object") else action
                if action and isinstance(action.get("/URI"), str):
                    self.text(action["/URI"] + "\n")
        if self.pages == 0:
            self.partial("NO_EXTRACTABLE_TEXT")

    def rtf(self, data):
        from striprtf import striprtf

        source = data.decode("latin1")
        # Validate group balance rather than accepting a truncated RTF as clean.
        level = 0
        for token in re.finditer(r"\\(?:[a-zA-Z]+-?\d* ?|[^a-zA-Z])|[{}]", source):
            value = token.group()
            if value == "{":
                level += 1
            elif value == "}":
                level -= 1
                if level < 0:
                    raise InvalidDocument
            elif re.match(r"\\(?:object|objdata|pict|bin)\b", value):
                self.partial("EMBEDDED_CONTENT")
            elif value == r"\*":
                # The library ignores extension destinations. Do not certify
                # their text absent, even when the main body is fully readable.
                self.partial("RTF_EXTENSION_CONTENT")
        if level:
            self.partial("MALFORMED_DOCUMENT")
        # striprtf normally drops secondary stories. In this private, one-shot
        # parser process, include their text so headers/footnotes are inspected.
        include = {"header", "headerl", "headerr", "headerf", "footer", "footerl",
                   "footerr", "footerf", "footnote", "annotation", "comment", "shptxt",
                   "dptxbxtext", "info", "title", "subject", "author", "keywords",
                   "doccomm", "operator", "company", "manager", "category"}
        previous = striprtf.destinations
        try:
            striprtf.destinations = previous - include
            text = striprtf.rtf_to_text(source, errors="strict")
            if re.search(r"[\ud800-\udfff]", text):
                text = text.encode("utf-16-le", "surrogatepass").decode("utf-16-le")
            self.text(text)
        finally:
            striprtf.destinations = previous

    def ole(self, data, depth):
        import olefile

        with olefile.OleFileIO(io.BytesIO(data), raise_defects=olefile.DEFECT_INCORRECT) as document:
            entries = document.listdir()
            if len(entries) > self.limits.members - self.members:
                self.stop("MEMBER_LIMIT")
            if document.exists("EncryptedPackage") or document.exists("EncryptionInfo"):
                self.partial("ENCRYPTED_DOCUMENT")
                return
            if document.exists("FileHeader"):
                if depth == 0:
                    self.format = "hwp5"
                self.hwp(document, entries)
            elif document.exists("WordDocument"):
                if depth == 0:
                    self.format = "doc"
                self.doc(document, entries)
            elif self.legacy_encrypted(document):
                self.partial("ENCRYPTED_DOCUMENT")
            else:
                # XLS, PPT and other compound files: printable strings of each stream as stored,
                # not of the raw file (a stream's sectors need not be adjacent, so a run could
                # break where one ends), a workbook's shared strings rejoined across records.
                # Only a workbook and a presentation without embedded objects keep their text in
                # plain runs; installers, drawings, mail and the like store compressed streams.
                if depth == 0:
                    self.format = "ole-strings"
                results, objects, parsed = [], False, True
                # The streams of a well-formed file never hold more than the file: chains that run
                # into each other would make every stream read the file again.
                try:
                    if sum(document.get_size(entry) for entry in entries) > len(data):
                        results = None
                except (OSError, IndexError, ValueError, struct.error):
                    results = None
                for entry in entries if results is not None else ():
                    name = "/".join(entry).lower()
                    try:
                        if not document.get_size(entry):
                            continue  # nothing to read (some writers give an empty stream sector 0)
                        stream = self.ole_stream(document, entry, stored=True)
                    except (OSError, InvalidDocument, IndexError, ValueError, struct.error):
                        results = None  # a stream whose chain does not read
                        break
                    if name == "powerpoint document":
                        objects = self.ppt_objects(stream)
                    elif name in ("workbook", "book"):
                        decoded = shared_strings(stream)
                        if decoded is None:
                            parsed = False
                        else:
                            narrow, wide, stream, left = decoded
                            parsed = parsed and not left
                            results.append(strings(narrow, self.limits.text_bytes, "ole-strings"))
                            results.append(strings(wide, self.limits.text_bytes, "ole-strings"))
                            del narrow, wide
                    results.append(strings(stream, self.limits.text_bytes, "ole-strings"))
                    del stream
                if results is None:
                    # A damaged directory: the raw file's strings, never certified complete.
                    self.partial("MALFORMED_DOCUMENT")
                    self.plain(strings(data, self.limits.text_bytes, "ole-strings"))
                    return
                if any(part in OLE_EMBEDDED or part.startswith(("MBD", "__attach_version1.0_"))
                       for entry in entries for part in entry):
                    self.partial("EMBEDDED_CONTENT")
                elif not (document.exists("Workbook") or document.exists("Book")
                          or (document.exists("PowerPoint Document") and not objects)):
                    self.partial("EMBEDDED_CONTENT" if any(result.data for result in results)
                                 else "UNSUPPORTED_OLE_FORMAT")
                elif not parsed:
                    self.partial("MALFORMED_DOCUMENT")  # its raw strings are still read below
                for result in results:
                    self.plain(result)
                    self.text("\n")

    @staticmethod
    def ppt_objects(data):
        """Whether a PowerPoint Document stream holds an ExOleObjStg record (0x1011): an
        embedded object or VBA project, stored compressed (MS-PPT)."""
        ranges, records = [(0, len(data))], 0
        while ranges:
            position, end = ranges.pop()
            while position + 8 <= end:
                version, record, size = struct.unpack_from("<HHI", data, position)
                body, records = position + 8, records + 1
                if record == 0x1011 or body + size > end or records > 1_000_000:
                    return True  # an object, or records too damaged or many to certify
                if version & 0x0F == 0x0F:  # a container: its records are walked too
                    ranges.append((body, body + size))
                position = body + size
        return False

    @staticmethod
    def legacy_encrypted(document):
        # Encrypted XLS has a FilePass record (0x002F) among the first workbook records,
        # after BOF and an optional WriteProtect (MS-XLS); encrypted PPT marks the
        # CurrentUserAtom headerToken (MS-PPT). Strings of either would read nothing.
        for name in ("Workbook", "Book"):
            if document.exists(name):
                with document.openstream(name) as stream:
                    for _ in range(3):
                        head = stream.read(4)
                        if len(head) < 4:
                            break
                        record, size = struct.unpack("<HH", head)
                        if record == 0x002F:
                            return True
                        stream.read(size)
        if document.exists("Current User"):
            with document.openstream("Current User") as stream:
                return stream.read(16)[12:16] == b"\xdf\xc4\xd1\xf3"
        return False

    def ole_stream(self, document, name, *, stored=False):
        size = document.get_size(name)
        # A stream read only as stored, never inflated, after the directory's sizes were checked
        # against the file: it counts as a member but not against the member or expansion bytes.
        self.member(0 if stored else size)
        with document.openstream(name) as stream:
            data = stream.read(size + 1)
        if len(data) != size:
            raise InvalidDocument
        return data

    def hwp(self, document, entries):
        header = self.ole_stream(document, "FileHeader")
        if len(header) < 40 or not header.startswith(b"HWP Document File"):
            raise InvalidDocument
        if header[35] != 5 or header[34] != 0:
            self.partial("UNSUPPORTED_HWP_VERSION")
            return
        flags = struct.unpack_from("<I", header, 36)[0]
        if flags & ((1 << 1) | (1 << 2) | (1 << 4) | (1 << 8) | (1 << 10)):
            self.partial("ENCRYPTED_DOCUMENT")
            return
        sections = [name for name in entries if len(name) == 2 and name[0] == "BodyText"
                    and re.fullmatch(r"Section\d+", name[1])]
        if not sections:
            raise InvalidDocument
        info = self.ole_stream(document, "DocInfo")
        if flags & 1:
            info = self.inflate(info, "deflate")
        expected_sections = None
        for tag, record in self.hwp_records(info):
            if tag == 16:  # HWPTAG_DOCUMENT_PROPERTIES
                if len(record) < 30:
                    raise InvalidDocument
                expected_sections = struct.unpack_from("<H", record)[0]
                break
        if expected_sections is None or sorted(int(name[1][7:]) for name in sections) != list(range(expected_sections)):
            raise InvalidDocument
        for name in sorted(sections, key=lambda value: int(value[1][7:])):
            raw = self.ole_stream(document, name)
            if flags & 1:
                raw = self.inflate(raw, "deflate")
            expected_chars = None
            for tag, record in self.hwp_records(raw):
                if tag == 66:  # HWPTAG_PARA_HEADER
                    if expected_chars is not None or len(record) < 22:
                        raise InvalidDocument
                    expected_chars = struct.unpack_from("<I", record)[0] & 0x7FFFFFFF
                elif tag == 67:  # HWPTAG_PARA_TEXT
                    if expected_chars != len(record) // 2:
                        raise InvalidDocument
                    self.hwp_text(record)
                    expected_chars = None
            if expected_chars is not None:
                raise InvalidDocument
        if any(name[0] in {"BinData", "Scripts"} for name in entries):
            self.partial("EMBEDDED_CONTENT")

    @staticmethod
    def hwp_records(raw):
        offset = 0
        while offset < len(raw):
            if offset + 4 > len(raw):
                raise InvalidDocument
            header = struct.unpack_from("<I", raw, offset)[0]
            offset += 4
            size = header >> 20
            if size == 0xFFF:
                if offset + 4 > len(raw):
                    raise InvalidDocument
                size = struct.unpack_from("<I", raw, offset)[0]
                offset += 4
            if offset + size > len(raw):
                raise InvalidDocument
            yield header & 0x3FF, raw[offset:offset + size]
            offset += size

    def hwp_text(self, data):
        if len(data) % 2:
            raise InvalidDocument
        pos = 0
        run = bytearray()
        while pos < len(data):
            code = struct.unpack_from("<H", data, pos)[0]
            if code >= 32:
                run.extend(data[pos:pos + 2])
                pos += 2
                continue
            if run:
                self.text(run.decode("utf-16-le"))
                run.clear()
            # Hancom v5 table 6: inline/extended controls occupy eight WCHARs.
            if 1 <= code <= 9 or 11 <= code <= 12 or 14 <= code <= 23:
                if pos + 16 > len(data) or struct.unpack_from("<H", data, pos + 14)[0] != code:
                    raise InvalidDocument
                pos += 16
                if code == 9:
                    self.text("\t")
            else:
                pos += 2
                self.text("\n" if code in (10, 13) else ("-" if code == 24 else " "))
        if run:
            self.text(run.decode("utf-16-le"))
        self.text("\n")

    def doc(self, document, entries):
        """MS-DOC Fib/Clx/PlcPcd: Word 97–2003 text, including secondary stories."""
        word = self.ole_stream(document, "WordDocument")
        if len(word) < 34 or word[:2] != b"\xec\xa5":
            raise InvalidDocument
        version, flags = struct.unpack_from("<H", word, 2)[0], struct.unpack_from("<H", word, 10)[0]
        if flags & (0x0100 | 0x8000):
            self.partial("ENCRYPTED_DOCUMENT")
            return
        if version not in {0x00C1, 0x00D9, 0x0101, 0x010C, 0x0112}:
            self.partial("UNSUPPORTED_DOC_VERSION")
            return
        pos = 32
        expected_chars = 0
        for size in (2, 4):  # FibRgW, FibRgLw
            if pos + 2 > len(word):
                raise InvalidDocument
            count = struct.unpack_from("<H", word, pos)[0]
            if size == 4:
                if count < 11 or pos + 2 + count * size > len(word):
                    raise InvalidDocument
                stories = struct.unpack_from("<11I", word, pos + 2)
                expected_chars = sum(stories[index] for index in (3, 4, 5, 7, 8, 9, 10))
            pos += 2 + count * size
        if pos + 2 > len(word):
            raise InvalidDocument
        count = struct.unpack_from("<H", word, pos)[0]
        pos += 2
        if count < 34 or pos + count * 8 > len(word):
            raise InvalidDocument
        offset, size = struct.unpack_from("<II", word, pos + 33 * 8)
        table = self.ole_stream(document, "1Table" if flags & 0x0200 else "0Table")
        if not size or offset + size > len(table):
            raise InvalidDocument
        clx = table[offset:offset + size]
        pos = 0
        while pos < len(clx) and clx[pos] == 1:  # optional Prc formatting records
            if pos + 3 > len(clx):
                raise InvalidDocument
            pos += 3 + struct.unpack_from("<H", clx, pos + 1)[0]
        if pos + 5 > len(clx) or clx[pos] != 2:
            raise InvalidDocument
        size = struct.unpack_from("<I", clx, pos + 1)[0]
        pieces = clx[pos + 5:pos + 5 + size]
        if len(pieces) != size or size < 4 or (size - 4) % 12:
            raise InvalidDocument
        count = (size - 4) // 12
        first_cp, last_cp = struct.unpack_from("<I", pieces, 0)[0], struct.unpack_from("<I", pieces, count * 4)[0]
        if first_cp or not expected_chars <= last_cp <= expected_chars + 1:
            raise InvalidDocument
        if count > self.limits.members * 1024:
            self.stop("MEMBER_LIMIT")
        for index in range(count):
            first, last = struct.unpack_from("<II", pieces, index * 4)
            if last < first:
                raise InvalidDocument
            fc = struct.unpack_from("<I", pieces, (count + 1) * 4 + index * 8 + 2)[0]
            compressed = bool(fc & 0x40000000)
            if fc & 0x80000000:
                raise InvalidDocument
            start = (fc & 0x3FFFFFFF) // (2 if compressed else 1)
            length = (last - first) * (1 if compressed else 2)
            if start + length > len(word):
                raise InvalidDocument
            text = word[start:start + length].decode("cp1252" if compressed else "utf-16-le")
            # Word story separators/cell marks are logical text boundaries.
            self.text("".join("\n" if ord(char) < 32 and char != "\t" else char for char in text))
        if any(name[0] in {"Data", "ObjectPool", "Macros", "VBA"} for name in entries):
            self.partial("EMBEDDED_CONTENT")


def parse(data, suffix, limits):
    reader = Reader(limits)
    try:
        reader.read(data, suffix)
    except LimitReached:
        pass
    except ImportError:
        reader.partial("PARSER_UNAVAILABLE")
    except MemoryError:
        reader.partial("PARSER_RESOURCE_LIMIT")
    except Exception:  # noqa: BLE001 -- parser exceptions may quote secret document text
        reader.partial("MALFORMED_DOCUMENT")
    data = bytes(reader.output)
    if not data.strip():
        data = b""
    return ExtractionResult(data, reader.format, not reader.reason, reader.reason)
