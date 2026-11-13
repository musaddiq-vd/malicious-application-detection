"""Dependency-free static analysis of an Android ``.apk``.

An APK is a ZIP archive. This module reads it entirely in memory (nothing is
extracted to disk and nothing is executed) and maps what it finds onto the 35
model features:

* **Manifest.** ``AndroidManifest.xml`` is in Android's binary XML format
  (AXML). The parser walks its chunks, decodes the string pool (UTF-8 and
  UTF-16 pools), and reads the ``package`` attribute, every ``uses-permission``
  (and ``uses-permission-sdk-23``) name, and every intent-filter ``action``.
  If the chunk structure is damaged it falls back to scanning the string pool,
  and failing that the raw bytes, for permission and action names. A plain-text
  manifest (as in a source tree) is also accepted.
* **Bytecode.** Every ``classes*.dex`` file is parsed: its string table, type
  table and method-reference table.
* **Other entries.** File names in the archive, plus the contents of small
  script/text files (e.g. ``assets/*.sh``), are checked for file-type and shell
  command indicators.

How each feature category is matched
------------------------------------
* Permissions: an exact ``uses-permission`` name ``<prefix>.<KEY>``, e.g.
  ``android.permission.SEND_SMS``. ``PHONE_STATE`` matches ``READ_PHONE_STATE``
  and ``MODIFY_PHONE_STATE``, since the dataset column is a substring match.
* Intents: the action string appears in a manifest ``<action>`` or anywhere in
  the dex string tables (receivers can be registered from code).
* ``TelephonyManager.*getDeviceId``, ``TelephonyManager.*getSubscriberId``,
  ``System.*loadLibrary`` and ``io.File.*delete(``: the dataset defines these
  as regular expressions over decompiled source. Here they are approximated by
  a dex *method reference* whose class is ``Landroid/telephony/TelephonyManager;``
  (or ``Ljava/lang/System;`` / ``Ljava/io/File;``) and whose name is the method
  name. A method reference means the code calls (or at least links against)
  that exact method, which is close to the original intent but not identical:
  calls through reflection or on subclasses are not seen, and an unused
  reference is still counted. If the method table cannot be parsed, the
  fallback is "class descriptor and method name both occur in the strings",
  which is looser.
* ``abortBroadcast``: a method reference named ``abortBroadcast`` (any class).
* ``Ljava.net.InetSocketAddress``: the type descriptor
  ``Ljava/net/InetSocketAddress;`` occurs in a dex string table.
* ``chown`` / ``chmod`` / ``mount``: the command appears as a whole word in a
  dex string or a small text entry (so ``amount`` does not match ``mount``,
  but an English sentence containing "mount" would).
* ``.apk`` / ``.zip`` / ``.dex`` / ``.so`` / ``.exe``: the extension appears at
  the end of a token in a dex string, or is the extension of an archive entry
  (top-level ``classes*.dex`` excluded, since every APK has them).

These heuristics are static and can be defeated by obfuscation, string
encryption or dynamically downloaded code; a clean report is not proof that
an app is safe.

Hostile input: non-ZIP data, a missing manifest, encrypted or unsupported
entries and malformed structures raise ``ApkParseError`` (or are skipped when
they are not essential). All reads go through a budget: each entry is read
with a size cap and the total number of decompressed bytes is bounded, so a
ZIP bomb cannot exhaust memory. Every offset taken from the file is
bounds-checked before use.
"""

from __future__ import annotations

import hashlib
import io
import re
import struct
import zipfile
import zlib
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from maldetect.features import FEATURES

MANIFEST_NAME = "AndroidManifest.xml"
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_DEX_BYTES = 64 * 1024 * 1024
MAX_DEX_FILES = 64
MAX_TEXT_ENTRY_BYTES = 1024 * 1024
MAX_TEXT_ENTRIES = 200
MAX_TOTAL_BYTES = 384 * 1024 * 1024
MAX_ENTRIES = 50_000
MAX_EVIDENCE_CHARS = 120

TEXT_SUFFIXES = (".sh", ".txt", ".xml", ".json", ".js", ".cfg", ".conf", ".ini", ".properties")

# AXML chunk types (frameworks/base/libs/androidfw/include/androidfw/ResourceTypes.h)
RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_RESOURCE_MAP_TYPE = 0x0180
UTF8_FLAG = 0x100
TYPE_STRING = 0x03
NO_INDEX = 0xFFFFFFFF
ANDROID_ATTR_NAME = 0x01010003  # android:name

DEX_MAGIC = b"dex\n"
DEX_HEADER_SIZE = 0x70


class ApkParseError(ValueError):
    """The input is not a readable APK."""


@dataclass(frozen=True)
class ApkReport:
    package: str | None
    sha256: str
    size_bytes: int
    dex_count: int
    permissions: list[str]
    features: dict[str, int]
    evidence: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- reading


class _Budget:
    """Caps the total number of decompressed bytes read from the archive."""

    def __init__(self, total: int) -> None:
        self.remaining = total

    def read(self, archive: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
        cap = min(limit, self.remaining)
        if info.file_size > cap:
            raise _TooLarge(info.filename)
        try:
            with archive.open(info) as handle:
                # Read one byte past the cap: the declared size can lie, the stream cannot.
                payload = handle.read(cap + 1)
        except (zipfile.BadZipFile, zlib.error, EOFError, OSError, RuntimeError,
                NotImplementedError, ValueError) as exc:
            raise _Unreadable(f"{info.filename}: {exc}") from exc
        if len(payload) > cap:
            raise _TooLarge(info.filename)
        self.remaining -= len(payload)
        return payload


class _TooLarge(Exception):
    pass


class _Unreadable(Exception):
    pass


# --------------------------------------------------------------------------- AXML


def _u16(buf: bytes, pos: int) -> int:
    return struct.unpack_from("<H", buf, pos)[0]


def _u32(buf: bytes, pos: int) -> int:
    return struct.unpack_from("<I", buf, pos)[0]


def _decode_string_pool(buf: bytes, start: int) -> list[str]:
    """Decode a ResStringPool chunk starting at ``start``."""
    header_size = _u16(buf, start + 2)
    chunk_size = _u32(buf, start + 4)
    end = start + chunk_size
    if header_size < 28 or chunk_size < header_size or end > len(buf):
        raise ValueError("bad string pool header")
    count = _u32(buf, start + 8)
    flags = _u32(buf, start + 16)
    strings_start = start + _u32(buf, start + 20)
    offsets_at = start + header_size
    if offsets_at + 4 * count > end or strings_start > end:
        raise ValueError("bad string pool counts")
    utf8 = bool(flags & UTF8_FLAG)
    result: list[str] = []
    for i in range(count):
        pos = strings_start + _u32(buf, offsets_at + 4 * i)
        if pos >= end:
            result.append("")
            continue
        try:
            result.append(_read_pool_string(buf, pos, end, utf8))
        except (struct.error, IndexError, ValueError):
            result.append("")
    return result


def _read_pool_string(buf: bytes, pos: int, end: int, utf8: bool) -> str:
    if utf8:
        # Two lengths: UTF-16 units (skipped), then UTF-8 bytes; each 1 or 2 bytes long.
        pos += 2 if buf[pos] & 0x80 else 1
        length = buf[pos]
        if length & 0x80:
            length = ((length & 0x7F) << 8) | buf[pos + 1]
            pos += 2
        else:
            pos += 1
        if pos + length > end:
            raise ValueError("string overruns pool")
        return buf[pos : pos + length].decode("utf-8", errors="replace")
    length = _u16(buf, pos)
    if length & 0x8000:
        length = ((length & 0x7FFF) << 16) | _u16(buf, pos + 2)
        pos += 4
    else:
        pos += 2
    if pos + 2 * length > end:
        raise ValueError("string overruns pool")
    return buf[pos : pos + 2 * length].decode("utf-16-le", errors="replace")


@dataclass
class _Manifest:
    package: str | None = None
    permissions: set[str] = field(default_factory=set)
    actions: set[str] = field(default_factory=set)
    strings: list[str] = field(default_factory=list)
    method: str = "axml"


def parse_axml(buf: bytes) -> _Manifest:
    """Parse a binary manifest; raises ValueError if the structure is unusable."""
    if len(buf) < 8 or _u16(buf, 0) != RES_XML_TYPE:
        raise ValueError("not a binary XML document")
    header_size = _u16(buf, 2)
    total = min(_u32(buf, 4), len(buf))
    pos = header_size
    strings: list[str] | None = None
    resource_ids: list[int] = []
    manifest = _Manifest()
    stack: list[str] = []

    def text(index: int) -> str | None:
        if strings is None or index == NO_INDEX or index >= len(strings):
            return None
        return strings[index]

    while pos + 8 <= total:
        chunk_type = _u16(buf, pos)
        chunk_header = _u16(buf, pos + 2)
        chunk_size = _u32(buf, pos + 4)
        if chunk_size < 8 or pos + chunk_size > total:
            break
        if chunk_type == RES_STRING_POOL_TYPE and strings is None:
            strings = _decode_string_pool(buf, pos)
        elif chunk_type == RES_XML_RESOURCE_MAP_TYPE:
            count = (chunk_size - chunk_header) // 4
            resource_ids = [_u32(buf, pos + chunk_header + 4 * i) for i in range(count)]
        elif chunk_type == RES_XML_START_ELEMENT_TYPE and strings is not None:
            ext = pos + chunk_header
            if ext + 20 > pos + chunk_size:
                break
            name = text(_u32(buf, ext + 4)) or ""
            attr_start = _u16(buf, ext + 8)
            attr_size = _u16(buf, ext + 10)
            attr_count = _u16(buf, ext + 12)
            attrs: dict[str, str] = {}
            for i in range(attr_count):
                at = ext + attr_start + i * attr_size
                if attr_size < 20 or at + 20 > pos + chunk_size:
                    break
                name_index = _u32(buf, at + 4)
                raw_index = _u32(buf, at + 8)
                data_type = buf[at + 15]
                data = _u32(buf, at + 16)
                attr_name = text(name_index) or ""
                # Obfuscators blank attribute names; the resource id still says android:name.
                if name_index < len(resource_ids) and resource_ids[name_index] == ANDROID_ATTR_NAME:
                    attr_name = "name"
                value = text(raw_index)
                if value is None and data_type == TYPE_STRING:
                    value = text(data)
                if value is not None:
                    attrs[attr_name] = value
            if name == "manifest" and "package" in attrs:
                manifest.package = attrs["package"]
            elif name in ("uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"):
                if attrs.get("name"):
                    manifest.permissions.add(attrs["name"])
            elif name == "action" and stack and stack[-1] == "intent-filter":
                if attrs.get("name"):
                    manifest.actions.add(attrs["name"])
            stack.append(name)
        elif chunk_type == RES_XML_START_ELEMENT_TYPE + 1 and stack:  # end element
            stack.pop()
        pos += chunk_size

    if strings is None:
        raise ValueError("binary XML without a string pool")
    manifest.strings = strings
    return manifest


_PERMISSION_RE = re.compile(r"^[A-Za-z0-9_.]*\.permission\.[A-Z0-9_]+$")
_ACTION_RE = re.compile(r"^[A-Za-z0-9_.]+\.action\.[A-Z0-9_]+$")
_PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")


def _manifest_from_strings(strings: Iterable[str], method: str) -> _Manifest:
    """Fallback: classify loose strings as permissions and actions."""
    manifest = _Manifest(method=method)
    collected = list(strings)
    for s in collected:
        if _PERMISSION_RE.match(s):
            manifest.permissions.add(s)
        elif _ACTION_RE.match(s):
            manifest.actions.add(s)
    manifest.strings = collected
    return manifest


def _printable_runs(buf: bytes) -> list[str]:
    """ASCII and UTF-16LE printable runs of length >= 4, like `strings`."""
    found = [m.decode("ascii") for m in re.findall(rb"[\x20-\x7e]{4,}", buf)]
    found += [
        m.decode("utf-16-le") for m in re.findall(rb"(?:[\x20-\x7e]\x00){4,}", buf)
    ]
    return found


_TEXT_ATTR_RE = re.compile(r"""([\w:.-]+)\s*=\s*["']([^"']*)["']""")


def _parse_text_manifest(text: str) -> _Manifest:
    """Very small regex reader for a plain-text manifest; no entity expansion."""
    manifest = _Manifest(method="text")
    for match in re.finditer(r"<\s*([\w:-]+)([^>]*)>", text):
        tag, body = match.group(1), match.group(2)
        attrs = {k.split(":")[-1]: v for k, v in _TEXT_ATTR_RE.findall(body)}
        if tag == "manifest" and "package" in attrs:
            manifest.package = attrs["package"]
        elif tag.startswith("uses-permission") and attrs.get("name"):
            manifest.permissions.add(attrs["name"])
        elif tag == "action" and attrs.get("name"):
            manifest.actions.add(attrs["name"])
    manifest.strings = list(manifest.permissions | manifest.actions)
    return manifest


def read_manifest(buf: bytes) -> _Manifest:
    """Best-effort manifest reader: AXML, then string pool, then raw strings."""
    if buf.lstrip()[:1] == b"<" or buf[:3] == b"\xef\xbb\xbf":
        return _parse_text_manifest(buf.decode("utf-8", errors="replace"))
    try:
        return parse_axml(buf)
    except (ValueError, struct.error, IndexError):
        pass
    if len(buf) >= 36 and _u16(buf, 8) == RES_STRING_POOL_TYPE:
        try:
            return _manifest_from_strings(_decode_string_pool(buf, 8), "string-pool")
        except (ValueError, struct.error, IndexError):
            pass
    return _manifest_from_strings(_printable_runs(buf), "raw-strings")


# --------------------------------------------------------------------------- DEX


@dataclass
class DexInfo:
    name: str
    strings: list[str]
    types: set[str]
    methods: set[tuple[str, str]]  # (class descriptor, method name)
    methods_parsed: bool


def _uleb128(buf: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    for _ in range(5):
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
    raise ValueError("bad uleb128")


def _table(buf: bytes, offset_field: int, item_size: int) -> tuple[int, int]:
    size = _u32(buf, offset_field)
    offset = _u32(buf, offset_field + 4)
    if size and (offset < DEX_HEADER_SIZE or offset + size * item_size > len(buf)):
        raise ValueError("dex table out of bounds")
    return size, offset


def parse_dex(name: str, buf: bytes) -> DexInfo:
    """Read the string, type and method-reference tables of a dex file."""
    if len(buf) < DEX_HEADER_SIZE or buf[:4] != DEX_MAGIC:
        raise ValueError("not a dex file")
    string_count, string_off = _table(buf, 0x38, 4)
    strings: list[str] = []
    for i in range(string_count):
        data_off = _u32(buf, string_off + 4 * i)
        if data_off >= len(buf):
            strings.append("")
            continue
        try:
            _, start = _uleb128(buf, data_off)
        except (ValueError, IndexError):
            strings.append("")
            continue
        stop = buf.find(b"\x00", start)
        stop = len(buf) if stop < 0 else stop
        # Modified UTF-8 differs from UTF-8 only for NUL and astral characters.
        strings.append(buf[start:stop].decode("utf-8", errors="replace"))

    def string_at(index: int) -> str:
        return strings[index] if index < len(strings) else ""

    types: list[str] = []
    methods: set[tuple[str, str]] = set()
    parsed = True
    try:
        type_count, type_off = _table(buf, 0x40, 4)
        types = [string_at(_u32(buf, type_off + 4 * i)) for i in range(type_count)]
        method_count, method_off = _table(buf, 0x58, 8)
        for i in range(method_count):
            class_idx, _proto, name_idx = struct.unpack_from("<HHI", buf, method_off + 8 * i)
            class_name = types[class_idx] if class_idx < len(types) else ""
            methods.add((class_name, string_at(name_idx)))
    except (ValueError, struct.error, IndexError):
        parsed = False
    return DexInfo(name=name, strings=strings, types=set(types), methods=methods,
                   methods_parsed=parsed)


# --------------------------------------------------------------------------- matching

METHOD_FEATURES: dict[str, tuple[str, str]] = {
    "telephony_get_device_id": ("Landroid/telephony/TelephonyManager;", "getDeviceId"),
    "telephony_get_subscriber_id": ("Landroid/telephony/TelephonyManager;", "getSubscriberId"),
    "load_library": ("Ljava/lang/System;", "loadLibrary"),
    "file_delete": ("Ljava/io/File;", "delete"),
}
COMMAND_FEATURES = ("chown", "chmod", "mount")
EXTENSION_FEATURES: dict[str, str] = {
    "ref_apk": ".apk",
    "ref_zip": ".zip",
    "ref_dex": ".dex",
    "ref_so": ".so",
    "ref_exe": ".exe",
}
SOCKET_DESCRIPTOR = "Ljava/net/InetSocketAddress;"
_DEX_ENTRY_RE = re.compile(r"^classes\d*\.dex$")
_COMMAND_RES = {c: re.compile(rf"(?<![A-Za-z0-9_]){c}(?![A-Za-z0-9_])") for c in COMMAND_FEATURES}
_EXT_RES = {
    slug: re.compile(rf"{re.escape(ext)}(?![A-Za-z0-9_])", re.IGNORECASE)
    for slug, ext in EXTENSION_FEATURES.items()
}


def _clip(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= MAX_EVIDENCE_CHARS else text[: MAX_EVIDENCE_CHARS - 3] + "..."


def _permission_matches(key: str, permission: str) -> bool:
    short = permission.rsplit(".", 1)[-1]
    if key == "PHONE_STATE":
        return short in ("READ_PHONE_STATE", "MODIFY_PHONE_STATE")
    return short == key


def match_features(
    manifest: _Manifest,
    dex_files: list[DexInfo],
    entry_names: list[str],
    text_entries: list[tuple[str, str]],
) -> tuple[dict[str, int], dict[str, str]]:
    """Map everything collected onto the 35 features, with evidence for each hit."""
    evidence: dict[str, str] = {}

    def hit(slug: str, why: str) -> None:
        evidence.setdefault(slug, _clip(why))

    dex_strings = [(d.name, s) for d in dex_files for s in d.strings if s]

    for feature in FEATURES:
        slug, key = feature.slug, feature.key
        if feature.category == "permission":
            for permission in sorted(manifest.permissions):
                if _permission_matches(key, permission):
                    hit(slug, f"uses-permission {permission}")
                    break
        elif feature.category == "intent":
            if key in manifest.actions:
                hit(slug, f"manifest intent-filter action {key}")
            else:
                for dex_name, s in dex_strings:
                    if s == key:
                        hit(slug, f"string \"{key}\" in {dex_name}")
                        break

    for slug, (cls, method) in METHOD_FEATURES.items():
        for dex in dex_files:
            if (cls, method) in dex.methods:
                hit(slug, f"calls {cls[1:-1].replace('/', '.')}.{method}() in {dex.name}")
                break
            if not dex.methods_parsed and method in dex.strings and cls in dex.strings:
                hit(slug, f"strings {cls} and {method} in {dex.name}")
                break

    for dex in dex_files:
        if any(name == "abortBroadcast" for _, name in dex.methods) or (
            not dex.methods_parsed and "abortBroadcast" in dex.strings
        ):
            hit("abort_broadcast", f"calls abortBroadcast() in {dex.name}")
            break

    for dex in dex_files:
        if SOCKET_DESCRIPTOR in dex.types or SOCKET_DESCRIPTOR in dex.strings:
            hit("inet_socket_address", f"references java.net.InetSocketAddress in {dex.name}")
            break

    sources = dex_strings + text_entries
    for command in COMMAND_FEATURES:
        pattern = _COMMAND_RES[command]
        for where, s in sources:
            if pattern.search(s):
                hit(command, f"string \"{s.strip()}\" in {where}")
                break

    for slug, pattern in _EXT_RES.items():
        for where, s in dex_strings:
            # Class descriptors such as "Lcom/foo/so;" are names, not file references.
            if not s.startswith("L") or not s.endswith(";"):
                if pattern.search(s):
                    hit(slug, f"string \"{s.strip()}\" in {where}")
                    break
        if slug in evidence:
            continue
        for name in entry_names:
            if _DEX_ENTRY_RE.match(name):
                continue
            if name.lower().endswith(EXTENSION_FEATURES[slug]):
                hit(slug, f"archive entry {name}")
                break

    features = {f.slug: int(f.slug in evidence) for f in FEATURES}
    return features, evidence


# --------------------------------------------------------------------------- entry point


def _load_source(source: Path | bytes | bytearray | memoryview) -> bytes:
    if isinstance(source, (bytes, bytearray, memoryview)):
        return bytes(source)
    path = Path(source)
    if not path.is_file():
        raise ApkParseError(f"File not found: {path}")
    return path.read_bytes()


def analyze_apk(source: Path | bytes) -> ApkReport:
    """Statically analyse an APK given as a path or raw bytes."""
    data = _load_source(source)
    if len(data) < 22 or not data.startswith(b"PK"):
        raise ApkParseError("Not an APK: the file is not a ZIP archive")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        infos = archive.infolist()
    except (zipfile.BadZipFile, zipfile.LargeZipFile, ValueError, OSError, EOFError) as exc:
        raise ApkParseError(f"Not an APK: {exc}") from exc
    if len(infos) > MAX_ENTRIES:
        raise ApkParseError(f"Archive has too many entries ({len(infos)})")

    budget = _Budget(MAX_TOTAL_BYTES)
    by_name = {info.filename: info for info in infos}
    manifest_info = by_name.get(MANIFEST_NAME)
    if manifest_info is None or manifest_info.is_dir():
        raise ApkParseError("Not an APK: AndroidManifest.xml is missing")
    try:
        manifest_bytes = budget.read(archive, manifest_info, MAX_MANIFEST_BYTES)
    except _TooLarge as exc:
        raise ApkParseError("AndroidManifest.xml is implausibly large") from exc
    except _Unreadable as exc:
        raise ApkParseError(f"AndroidManifest.xml cannot be read ({exc})") from exc
    manifest = read_manifest(manifest_bytes)

    dex_infos = sorted(
        (i for i in infos if _DEX_ENTRY_RE.match(i.filename)),
        key=lambda i: (len(i.filename), i.filename),
    )[:MAX_DEX_FILES]
    dex_files: list[DexInfo] = []
    for info in dex_infos:
        try:
            dex_files.append(parse_dex(info.filename, budget.read(archive, info, MAX_DEX_BYTES)))
        except (_TooLarge, _Unreadable, ValueError, struct.error, IndexError):
            continue  # a broken or oversized dex is skipped; the rest still counts

    text_entries: list[tuple[str, str]] = []
    for info in infos:
        if len(text_entries) >= MAX_TEXT_ENTRIES:
            break
        lowered = info.filename.lower()
        if info.is_dir() or info.filename == MANIFEST_NAME or not lowered.endswith(TEXT_SUFFIXES):
            continue
        if info.file_size > MAX_TEXT_ENTRY_BYTES:
            continue
        try:
            payload = budget.read(archive, info, MAX_TEXT_ENTRY_BYTES)
        except (_TooLarge, _Unreadable):
            continue
        if b"\x00" in payload[:1024]:
            continue  # binary XML resources and other non-text content
        for line in payload.decode("utf-8", errors="replace").splitlines():
            if line.strip():
                text_entries.append((info.filename, line))

    features, evidence = match_features(
        manifest, dex_files, [i.filename for i in infos if not i.is_dir()], text_entries
    )
    package = manifest.package
    if package is not None and not _PACKAGE_RE.match(package):
        package = None
    return ApkReport(
        package=package,
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        dex_count=len(dex_files),
        permissions=sorted(manifest.permissions),
        features=features,
        evidence=evidence,
    )
