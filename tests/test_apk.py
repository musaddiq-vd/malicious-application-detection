"""Tests for the static APK analyser, using APKs built in memory.

The builders below write real binary AndroidManifest (AXML) and dex structures,
so the parsers are exercised on the same layouts the Android toolchain emits.
"""

from __future__ import annotations

import io
import struct
import zipfile
from pathlib import Path

import pytest

from maldetect.features import slugs
from maldetect.ml import apk
from maldetect.ml.apk import ApkParseError, analyze_apk

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# --------------------------------------------------------------------------- builders


def _pad4(data: bytes) -> bytes:
    return data + b"\x00" * (-len(data) % 4)


def build_string_pool(strings: list[str], utf8: bool) -> bytes:
    offsets, blob = [], b""
    for s in strings:
        offsets.append(len(blob))
        if utf8:
            encoded = s.encode("utf-8")
            assert len(s) < 0x80 and len(encoded) < 0x80
            blob += bytes([len(s), len(encoded)]) + encoded + b"\x00"
        else:
            blob += struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\x00\x00"
    blob = _pad4(blob)
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    size = strings_start + len(blob)
    header = struct.pack(
        "<HHIIIIII",
        0x0001,
        header_size,
        size,
        len(strings),
        0,
        0x100 if utf8 else 0,
        strings_start,
        0,
    )
    return header + b"".join(struct.pack("<I", o) for o in offsets) + blob


def build_axml(
    elements: list[tuple[str, str, dict[str, str]]],
    utf8: bool = False,
    blank_attr_names: bool = False,
) -> bytes:
    """Build a binary manifest.

    ``elements`` is a list of ``("start" | "end", tag, attrs)`` events. Attribute
    names prefixed ``android:`` go in the android namespace. With
    ``blank_attr_names`` the ``android:name`` attribute name string is emptied
    (as obfuscators do) and only the resource map identifies it.
    """
    strings: list[str] = ["name"]  # index 0 maps to android:name via the resource map
    index: dict[str, int] = {"name": 0}

    def sid(s: str) -> int:
        if s not in index:
            index[s] = len(strings)
            strings.append(s)
        return index[s]

    sid(ANDROID_NS)
    body = b""
    for kind, tag, attrs in elements:
        if kind == "end":
            body += struct.pack("<HHIIIII", 0x0103, 16, 24, 1, 0xFFFFFFFF, 0xFFFFFFFF, sid(tag))
            continue
        attr_bytes = b""
        for key, value in attrs.items():
            if key.startswith("android:"):
                ns, local = sid(ANDROID_NS), key.split(":", 1)[1]
            else:
                ns, local = 0xFFFFFFFF, key
            name_index = 0 if local == "name" else sid(local)
            value_index = sid(value)
            attr_bytes += struct.pack(
                "<IIIHBBI", ns, name_index, value_index, 8, 0, 0x03, value_index
            )
        ext = struct.pack(
            "<IIHHHHHH", 0xFFFFFFFF, sid(tag), 20, 20, len(attrs), 0, 0, 0
        )
        size = 16 + len(ext) + len(attr_bytes)
        body += struct.pack("<HHIII", 0x0102, 16, size, 1, 0xFFFFFFFF) + ext + attr_bytes

    if blank_attr_names:
        strings[0] = ""
    pool = build_string_pool(strings, utf8)
    resource_map = struct.pack("<HHII", 0x0180, 8, 12, 0x01010003)
    payload = pool + resource_map + body
    return struct.pack("<HHI", 0x0003, 8, 8 + len(payload)) + payload


def manifest_events(
    package: str, permissions: list[str], actions: list[str]
) -> list[tuple[str, str, dict[str, str]]]:
    events: list[tuple[str, str, dict[str, str]]] = [("start", "manifest", {"package": package})]
    for permission in permissions:
        events += [
            ("start", "uses-permission", {"android:name": permission}),
            ("end", "uses-permission", {}),
        ]
    events += [("start", "application", {}), ("start", "receiver", {"android:name": ".R"})]
    events += [("start", "intent-filter", {})]
    for action in actions:
        events += [("start", "action", {"android:name": action}), ("end", "action", {})]
    events += [
        ("end", "intent-filter", {}),
        ("end", "receiver", {}),
        ("end", "application", {}),
        ("end", "manifest", {}),
    ]
    return events


def build_dex(strings: list[str], methods: tuple[tuple[str, str], ...] = ()) -> bytes:
    """Minimal dex: header, string_ids, type_ids, method_ids and string data."""
    referenced = [name for pair in methods for name in pair]
    all_strings = list(dict.fromkeys([*strings, *referenced]))
    type_names = [s for s in all_strings if s.startswith("L") and s.endswith(";")]
    n_str, n_type, n_method = len(all_strings), len(type_names), len(methods)
    string_ids_off = 0x70
    type_ids_off = string_ids_off + 4 * n_str
    method_ids_off = type_ids_off + 4 * n_type
    data_off = method_ids_off + 8 * n_method

    data, string_offsets = b"", []
    for s in all_strings:
        string_offsets.append(data_off + len(data))
        encoded = s.encode("utf-8")
        assert len(s) < 0x80
        data += bytes([len(s)]) + encoded + b"\x00"

    header = bytearray(0x70)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<II", header, 0x38, n_str, string_ids_off)
    struct.pack_into("<II", header, 0x40, n_type, type_ids_off)
    struct.pack_into("<II", header, 0x58, n_method, method_ids_off)
    string_ids = b"".join(struct.pack("<I", o) for o in string_offsets)
    type_ids = b"".join(struct.pack("<I", all_strings.index(t)) for t in type_names)
    method_ids = b"".join(
        struct.pack("<HHI", type_names.index(c), 0, all_strings.index(m)) for c, m in methods
    )
    return bytes(header) + string_ids + type_ids + method_ids + data


def build_apk(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


MALICIOUS_MANIFEST = manifest_events(
    "com.example.flashlight",
    [
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_PHONE_STATE",
        "android.permission.INTERNET",
    ],
    ["android.intent.action.BOOT_COMPLETED"],
)
MALICIOUS_DEX = build_dex(
    [
        "chmod 777 /data/local/tmp/x",
        "payload.apk",
        "Ljava/net/InetSocketAddress;",
        "amount",
        "Lcom/sneaky/so;",
    ],
    (
        ("Landroid/telephony/TelephonyManager;", "getDeviceId"),
        ("Landroid/content/BroadcastReceiver;", "abortBroadcast"),
        ("Ljava/lang/System;", "loadLibrary"),
    ),
)


# --------------------------------------------------------------------------- happy paths


@pytest.mark.parametrize("utf8", [False, True])
def test_parses_binary_manifest(utf8: bool) -> None:
    manifest = apk.parse_axml(build_axml(MALICIOUS_MANIFEST, utf8=utf8))
    assert manifest.package == "com.example.flashlight"
    assert "android.permission.SEND_SMS" in manifest.permissions
    assert manifest.actions == {"android.intent.action.BOOT_COMPLETED"}


def test_resource_map_identifies_obfuscated_name_attribute() -> None:
    manifest = apk.parse_axml(build_axml(MALICIOUS_MANIFEST, blank_attr_names=True))
    assert "android.permission.INTERNET" in manifest.permissions


def test_parses_dex_method_references() -> None:
    info = apk.parse_dex("classes.dex", MALICIOUS_DEX)
    assert info.methods_parsed
    assert ("Landroid/telephony/TelephonyManager;", "getDeviceId") in info.methods
    assert "Ljava/net/InetSocketAddress;" in info.types


def test_analyze_full_apk() -> None:
    data = build_apk(
        {
            "AndroidManifest.xml": build_axml(MALICIOUS_MANIFEST),
            "classes.dex": MALICIOUS_DEX,
            "classes2.dex": build_dex([], (("Ljava/io/File;", "delete"),)),
            "lib/armeabi-v7a/libnative.so": b"\x7fELF",
            "assets/run.sh": b"#!/system/bin/sh\nmount -o remount,rw /system\n",
            "res/layout/main.xml": b"\x03\x00\x08\x00binary",
        }
    )
    report = analyze_apk(data)

    assert report.package == "com.example.flashlight"
    assert report.dex_count == 2
    assert report.size_bytes == len(data)
    assert len(report.sha256) == 64
    assert report.permissions == sorted(report.permissions)
    assert set(report.features) == set(slugs())
    assert set(report.evidence) == {s for s, v in report.features.items() if v}

    expected_on = {
        "send_sms", "receive_sms", "read_phone_state", "internet", "boot_completed",
        "telephony_get_device_id", "abort_broadcast", "load_library", "file_delete",
        "inet_socket_address", "chmod", "mount", "ref_apk", "ref_so",
    }  # fmt: skip
    on = {slug for slug, value in report.features.items() if value}
    assert on == expected_on
    assert "classes2.dex" in report.evidence["file_delete"]
    assert "libnative.so" in report.evidence["ref_so"]
    assert "assets/run.sh" in report.evidence["mount"]
    # Word-boundary and descriptor rules: "amount" is not "mount", "Lcom/sneaky/so;" is not ".so".
    assert "amount" not in report.evidence["mount"]

    as_dict = report.to_dict()
    assert as_dict["package"] == "com.example.flashlight"
    assert as_dict["features"]["chmod"] == 1


def test_analyze_from_path(tmp_path: Path) -> None:
    path = tmp_path / "app.apk"
    path.write_bytes(build_apk({"AndroidManifest.xml": build_axml(MALICIOUS_MANIFEST)}))
    report = analyze_apk(path)
    assert report.features["send_sms"] == 1
    assert report.dex_count == 0


def test_benign_apk_has_few_features() -> None:
    events = manifest_events("com.example.notes", ["android.permission.INTERNET"], [])
    data = build_apk(
        {"AndroidManifest.xml": build_axml(events), "classes.dex": build_dex(["Hello"])}
    )
    report = analyze_apk(data)
    assert {s for s, v in report.features.items() if v} == {"internet"}


def test_plain_text_manifest_is_accepted() -> None:
    xml = (
        b'<?xml version="1.0"?><manifest package="com.example.src" '
        b'xmlns:android="http://schemas.android.com/apk/res/android">'
        b'<uses-permission android:name="android.permission.CAMERA"/></manifest>'
    )
    report = analyze_apk(build_apk({"AndroidManifest.xml": xml}))
    assert report.package == "com.example.src"
    assert report.features["camera"] == 1


def test_damaged_manifest_falls_back_to_string_scan() -> None:
    good = build_axml(MALICIOUS_MANIFEST)
    # Corrupt the document chunk type so the structured parse fails.
    broken = b"\x00\x00" + good[2:]
    report = analyze_apk(build_apk({"AndroidManifest.xml": broken}))
    assert report.features["send_sms"] == 1
    assert report.features["boot_completed"] == 1


# --------------------------------------------------------------------------- hostile input


def test_rejects_non_zip() -> None:
    with pytest.raises(ApkParseError):
        analyze_apk(b"this is not an apk at all, just some text padding it out")


def test_rejects_empty_and_truncated() -> None:
    with pytest.raises(ApkParseError):
        analyze_apk(b"")
    data = build_apk({"AndroidManifest.xml": build_axml(MALICIOUS_MANIFEST)})
    with pytest.raises(ApkParseError):
        analyze_apk(data[: len(data) // 2])


def test_rejects_zip_without_manifest() -> None:
    with pytest.raises(ApkParseError, match="AndroidManifest"):
        analyze_apk(build_apk({"classes.dex": MALICIOUS_DEX}))


def test_missing_file_raises_parse_error(tmp_path: Path) -> None:
    with pytest.raises(ApkParseError):
        analyze_apk(tmp_path / "nope.apk")


def test_zip_bomb_manifest_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(apk, "MAX_MANIFEST_BYTES", 64 * 1024)
    bomb = build_apk({"AndroidManifest.xml": b"\x00" * (4 * 1024 * 1024)})
    assert len(bomb) < 64 * 1024  # compresses extremely well
    with pytest.raises(ApkParseError, match="large"):
        analyze_apk(bomb)


def test_lying_size_header_cannot_bypass_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(apk, "MAX_DEX_BYTES", 1024)
    data = bytearray(
        build_apk(
            {
                "AndroidManifest.xml": build_axml(MALICIOUS_MANIFEST),
                "classes.dex": MALICIOUS_DEX + b"\x00" * 200_000,
            }
        )
    )
    # Rewrite the dex entry's declared uncompressed size (central directory) to a tiny value.
    name = b"classes.dex"
    cd = data.find(b"PK\x01\x02")
    while cd != -1:
        name_len = struct.unpack_from("<H", data, cd + 28)[0]
        if bytes(data[cd + 46 : cd + 46 + name_len]) == name:
            struct.pack_into("<I", data, cd + 24, 10)
        cd = data.find(b"PK\x01\x02", cd + 4)
    report = analyze_apk(bytes(data))
    assert report.dex_count == 0  # skipped, not read past the cap
    assert report.features["send_sms"] == 1


def test_total_budget_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(apk, "MAX_TOTAL_BYTES", 4096)
    data = build_apk(
        {
            "AndroidManifest.xml": build_axml(MALICIOUS_MANIFEST),
            "classes.dex": MALICIOUS_DEX + b"\x00" * 100_000,
        }
    )
    report = analyze_apk(data)
    assert report.dex_count == 0


def test_garbage_dex_and_manifest_do_not_crash() -> None:
    data = build_apk(
        {
            "AndroidManifest.xml": b"\x03\x00\x08\x00\xff\xff\xff\x7f" + b"\xff" * 64,
            "classes.dex": b"dex\n035\x00" + b"\xff" * 200,
            "classes2.dex": b"not a dex",
        }
    )
    report = analyze_apk(data)
    assert report.dex_count == 0
    assert set(report.features) == set(slugs())


def test_encrypted_entry_is_rejected() -> None:
    data = bytearray(build_apk({"AndroidManifest.xml": build_axml(MALICIOUS_MANIFEST)}))
    # Set the "encrypted" general-purpose flag bit in both headers.
    for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        pos = data.find(signature)
        flags = struct.unpack_from("<H", data, pos + flag_offset)[0]
        struct.pack_into("<H", data, pos + flag_offset, flags | 0x1)
    with pytest.raises(ApkParseError):
        analyze_apk(bytes(data))


def test_never_writes_to_disk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    analyze_apk(build_apk({"AndroidManifest.xml": build_axml(MALICIOUS_MANIFEST)}))
    assert list(tmp_path.iterdir()) == []
